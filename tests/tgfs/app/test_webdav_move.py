"""WebDAV MOVE -- the verb behind every rename -- against a fake channel.

The handler used to hand anything but the happy path to the ops layer and
let it blow up, so a MOVE onto an existing name, into a missing folder or
with "Overwrite: F" all ended in a 500. Clients that save by writing a
temporary file and renaming it over the original (davfs2, rclone, most
desktop file managers) never got the rename through.

The tests drive the real WebDAV app down to ``Ops`` / ``FileApi`` with
message deletion switched on.
"""

from typing import Dict, cast

import pytest
from fastapi.testclient import TestClient

from tgfs.app.webdav import create_webdav_app
from tgfs.core.client import Client
from tgfs.core.ops import Ops
from tests.tgfs.core.test_copy_and_move import FakeClient


@pytest.fixture
def client() -> FakeClient:
    fake = FakeClient()
    root = fake.dir_api.root
    root.create_dir("src")
    root.create_dir("dest")
    return fake


@pytest.fixture
def ops(client) -> Ops:
    return Ops(cast(Client, client))


@pytest.fixture
def http(client) -> TestClient:
    app = create_webdav_app(cast(Dict[str, Client], {"test": client}), "/webdav")
    return TestClient(app)


def move(http: TestClient, source: str, destination: str, **headers: str):
    return http.request(
        "MOVE",
        f"/test{source}",
        headers={"Destination": f"http://tgfs/webdav/test{destination}", **headers},
    )


async def size_of(ops: Ops, path: str) -> int:
    fd = await ops.desc(path)
    return fd.get_latest_version().size


class TestRename:
    @pytest.mark.asyncio
    async def test_renaming_a_file_keeps_its_content(self, http, ops):
        await ops.upload_from_bytes(b"x" * 42, "/src/old.txt")

        resp = move(http, "/src/old.txt", "/src/new.txt")

        assert resp.status_code == 201
        assert await size_of(ops, "/src/new.txt") == 42
        assert [f.name for f in ops.cd("/src").find_files()] == ["new.txt"]

    @pytest.mark.asyncio
    async def test_renaming_a_folder_keeps_the_files_below_it(self, http, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 7, "/src/sub/file.txt")

        resp = move(http, "/src/sub/", "/src/renamed/")

        assert resp.status_code == 201
        assert await size_of(ops, "/src/renamed/file.txt") == 7
        assert [d.name for d in ops.cd("/src").find_dirs()] == ["renamed"]

    @pytest.mark.asyncio
    async def test_names_are_url_decoded(self, http, ops):
        await ops.upload_from_bytes(b"x", "/src/a.txt")

        resp = move(http, "/src/a.txt", "/src/with%20space%20%C3%A4.txt")

        assert resp.status_code == 201
        ops.stat_file("/src/with space ä.txt")


class TestExistingDestination:
    @pytest.mark.asyncio
    async def test_overwrites_an_existing_file_by_default(self, http, ops, client):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")
        replaced = ops.stat_file("/dest/a.txt").message_id

        resp = move(http, "/src/a.txt", "/dest/a.txt")

        assert resp.status_code == 204
        assert await size_of(ops, "/dest/a.txt") == 10
        assert ops.cd("/src").find_files() == []
        assert len(ops.cd("/dest").find_files()) == 1
        # The replaced file's descriptor is gone from the channel ...
        assert replaced not in client.channel.messages
        # ... the moved one is untouched.
        assert ops.stat_file("/dest/a.txt").message_id in client.channel.messages

    @pytest.mark.asyncio
    async def test_overwrite_false_keeps_both_files(self, http, ops):
        await ops.upload_from_bytes(b"n" * 10, "/src/a.txt")
        await ops.upload_from_bytes(b"o" * 20, "/dest/a.txt")

        resp = move(http, "/src/a.txt", "/dest/a.txt", Overwrite="F")

        assert resp.status_code == 412
        assert await size_of(ops, "/src/a.txt") == 10
        assert await size_of(ops, "/dest/a.txt") == 20

    @pytest.mark.asyncio
    async def test_overwrites_an_existing_folder(self, http, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 3, "/src/sub/new.txt")
        await ops.mkdir("/dest/sub", False)
        await ops.upload_from_bytes(b"x" * 5, "/dest/sub/old.txt")

        resp = move(http, "/src/sub", "/dest/sub")

        assert resp.status_code == 204
        assert [f.name for f in ops.cd("/dest/sub").find_files()] == ["new.txt"]
        assert ops.cd("/src").find_dirs() == []


class TestRejectedMoves:
    @pytest.mark.asyncio
    async def test_missing_parent_is_a_conflict(self, http, ops):
        await ops.upload_from_bytes(b"x", "/src/a.txt")

        resp = move(http, "/src/a.txt", "/nope/a.txt")

        assert resp.status_code == 409
        ops.stat_file("/src/a.txt")

    @pytest.mark.asyncio
    async def test_moving_onto_itself_is_forbidden(self, http, ops):
        await ops.upload_from_bytes(b"x", "/src/a.txt")

        resp = move(http, "/src/a.txt", "/src/a.txt")

        assert resp.status_code == 403
        ops.stat_file("/src/a.txt")

    @pytest.mark.asyncio
    async def test_moving_a_folder_into_itself_is_a_conflict(self, http, ops):
        await ops.mkdir("/src/sub", False)

        resp = move(http, "/src", "/src/sub/src")

        assert resp.status_code == 409
        ops.cd("/src/sub")

    @pytest.mark.asyncio
    async def test_replacing_a_parent_does_not_delete_the_source(self, http, ops):
        await ops.mkdir("/src/sub", False)
        await ops.upload_from_bytes(b"x" * 9, "/src/sub/a.txt")

        resp = move(http, "/src/sub/a.txt", "/src")

        assert resp.status_code == 409
        assert await size_of(ops, "/src/sub/a.txt") == 9

    def test_missing_source_is_not_found(self, http):
        assert move(http, "/src/none.txt", "/dest/none.txt").status_code == 404

    def test_missing_destination_header_is_a_bad_request(self, http):
        assert http.request("MOVE", "/test/src").status_code == 400
