"""WebDAV MKCOL and PUT above the client level.

The top of the tree is the list of configured clients, not a writable
directory. Asking to create something there used to reach an unguarded
dict lookup and come back as a 500, so a client that starts by making its
target folder (tgsaver, most upload tools) saw a server error instead of
being told it may not write there.

The tests drive the real WebDAV app down to ``Ops`` / ``FileApi``.
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
    fake.dir_api.root.create_dir("src")
    return fake


@pytest.fixture
def ops(client) -> Ops:
    return Ops(cast(Client, client))


@pytest.fixture
def http(client) -> TestClient:
    app = create_webdav_app(cast(Dict[str, Client], {"test": client}), "/webdav")
    return TestClient(app)


def mkcol(http: TestClient, path: str):
    return http.request("MKCOL", path)


class TestMkcol:
    def test_creates_a_folder(self, http, ops):
        assert mkcol(http, "/test/src/sub").status_code == 201
        ops.cd("/src/sub")

    def test_an_existing_folder_is_reported_as_created(self, http):
        assert mkcol(http, "/test/src").status_code == 201
        assert mkcol(http, "/test/src").status_code == 201

    @pytest.mark.asyncio
    async def test_an_existing_file_is_a_conflict(self, http, ops):
        await ops.upload_from_bytes(b"x", "/src/a.txt")

        assert mkcol(http, "/test/src/a.txt").status_code == 409

    def test_missing_parent_is_a_conflict(self, http):
        assert mkcol(http, "/test/nope/sub").status_code == 409

    def test_a_folder_beside_the_clients_is_forbidden(self, http):
        """The top level holds the configured clients and nothing else."""
        assert mkcol(http, "/incoming").status_code == 403

    def test_an_unconfigured_client_is_a_conflict(self, http):
        assert mkcol(http, "/other/src/sub").status_code == 409


class TestPut:
    def test_writes_a_file(self, http, ops):
        assert http.put("/test/src/a.txt", content=b"x" * 5).status_code == 201
        ops.stat_file("/src/a.txt")

    def test_a_missing_parent_is_a_conflict(self, http):
        """RFC 4918 9.7.1 -- PUT does not create the folders on the way."""
        assert http.put("/test/nope/a.txt", content=b"x").status_code == 409

    def test_a_file_beside_the_clients_is_forbidden(self, http):
        assert http.put("/a.txt", content=b"x").status_code == 403

    def test_an_unconfigured_client_is_a_conflict(self, http):
        assert http.put("/other/a.txt", content=b"x").status_code == 409

    def test_putting_to_a_folder_is_a_conflict(self, http):
        assert http.put("/test/src", content=b"x").status_code == 409
