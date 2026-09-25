"""WebDAV PROPPATCH -- the modification time a client sets after an upload.

CarotDAV (and other clients) follow every PUT with a PROPPATCH that carries
the source file's modification time. The server used to answer 405, which
those clients report as a failed upload although the bytes are stored. The
verb now exists; ``getlastmodified`` and ``Win32LastModifiedTime`` re-date
the latest version, everything else is answered per property.

The tests drive the real WebDAV app down to ``Ops`` / ``FileApi``.
"""

import datetime
from typing import Dict, cast

import pytest
from fastapi.testclient import TestClient
from lxml import etree as et

from tgfs.app.webdav import create_webdav_app
from tgfs.core.client import Client
from tgfs.core.ops import Ops
from tests.tgfs.core.test_copy_and_move import FakeClient

DAV = "{DAV:}"
MS = "{urn:schemas-microsoft-com:}"
Y2K = "Sat, 01 Jan 2000 00:00:00 GMT"
Y2K_MS = 946684800000


@pytest.fixture
def client() -> FakeClient:
    fake = FakeClient()
    fake.dir_api.root.create_dir("dir")
    return fake


@pytest.fixture
def ops(client) -> Ops:
    return Ops(cast(Client, client))


@pytest.fixture
def http(client) -> TestClient:
    app = create_webdav_app(cast(Dict[str, Client], {"test": client}), "/webdav")
    return TestClient(app)


def proppatch(http: TestClient, path: str, *props: str, remove: bool = False):
    action = "remove" if remove else "set"
    body = (
        '<?xml version="1.0"?>'
        '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:">'
        f"<D:{action}><D:prop>{''.join(props)}</D:prop></D:{action}>"
        "</D:propertyupdate>"
    )
    return http.request(
        "PROPPATCH",
        f"/test{path}",
        content=body,
        headers={"Content-Type": "text/xml; charset=utf-8"},
    )


def statuses(resp) -> dict[str, str]:
    root = et.fromstring(resp.content)
    result: dict[str, str] = {}
    for propstat in root.iter(f"{DAV}propstat"):
        status = propstat.findtext(f"{DAV}status") or ""
        props = propstat.find(f"{DAV}prop")
        assert props is not None
        for prop in props:
            result[str(prop.tag)] = status
    return result


def last_modified_of(http: TestClient, path: str) -> str:
    resp = http.request("PROPFIND", f"/test{path}", headers={"Depth": "0"})
    assert resp.status_code == 207
    return et.fromstring(resp.content).findtext(f".//{DAV}getlastmodified") or ""


async def latest_timestamp(ops: Ops, path: str) -> int:
    return (await ops.desc(path)).get_latest_version().updated_at_timestamp


class TestSetLastModified:
    @pytest.mark.asyncio
    async def test_getlastmodified_re_dates_the_file(self, http, ops):
        await ops.upload_from_bytes(b"x" * 10, "/dir/a.txt")

        resp = proppatch(
            http, "/dir/a.txt", f"<D:getlastmodified>{Y2K}</D:getlastmodified>"
        )

        assert resp.status_code == 207
        assert statuses(resp) == {f"{DAV}getlastmodified": "HTTP/1.1 200 OK"}
        assert await latest_timestamp(ops, "/dir/a.txt") == Y2K_MS
        assert last_modified_of(http, "/dir/a.txt") == Y2K

    @pytest.mark.asyncio
    async def test_windows_spelling_works_as_well(self, http, ops):
        await ops.upload_from_bytes(b"x" * 10, "/dir/a.txt")

        resp = proppatch(
            http,
            "/dir/a.txt",
            f"<Z:Win32LastModifiedTime>{Y2K}</Z:Win32LastModifiedTime>",
        )

        assert statuses(resp) == {f"{MS}Win32LastModifiedTime": "HTTP/1.1 200 OK"}
        assert await latest_timestamp(ops, "/dir/a.txt") == Y2K_MS

    @pytest.mark.asyncio
    async def test_what_carotdav_sends_after_an_upload(self, http, ops):
        """Every property is 200: the time is kept, the attributes accepted.

        CarotDAV treats anything but 200 on any of the four as a failed
        upload, so accepting the attributes it sends is what keeps the
        transfer green.
        """
        await ops.upload_from_bytes(b"x" * 10, "/dir/a.txt")

        resp = proppatch(
            http,
            "/dir/a.txt",
            f"<Z:Win32CreationTime>{Y2K}</Z:Win32CreationTime>",
            f"<Z:Win32LastAccessTime>{Y2K}</Z:Win32LastAccessTime>",
            f"<Z:Win32LastModifiedTime>{Y2K}</Z:Win32LastModifiedTime>",
            "<Z:Win32FileAttributes>00000020</Z:Win32FileAttributes>",
        )

        assert resp.status_code == 207
        assert statuses(resp) == {
            f"{MS}Win32CreationTime": "HTTP/1.1 200 OK",
            f"{MS}Win32LastAccessTime": "HTTP/1.1 200 OK",
            f"{MS}Win32LastModifiedTime": "HTTP/1.1 200 OK",
            f"{MS}Win32FileAttributes": "HTTP/1.1 200 OK",
        }
        assert await latest_timestamp(ops, "/dir/a.txt") == Y2K_MS

    @pytest.mark.asyncio
    async def test_the_descriptor_is_rewritten_not_replaced(self, http, ops, client):
        await ops.upload_from_bytes(b"x" * 10, "/dir/a.txt")
        descriptor = ops.stat_file("/dir/a.txt").message_id
        messages = len(client.channel.messages)

        proppatch(http, "/dir/a.txt", f"<D:getlastmodified>{Y2K}</D:getlastmodified>")

        assert ops.stat_file("/dir/a.txt").message_id == descriptor
        assert len(client.channel.messages) == messages
        assert f'"updatedAt": {Y2K_MS}' in client.channel.messages[descriptor].text


class TestRefused:
    @pytest.mark.asyncio
    async def test_dating_before_an_older_version_is_a_conflict(self, http, ops):
        await ops.upload_from_bytes(b"one", "/dir/a.txt")
        first = await latest_timestamp(ops, "/dir/a.txt")
        await ops.upload_from_bytes(b"two", "/dir/a.txt")
        second = await latest_timestamp(ops, "/dir/a.txt")
        assert len((await ops.desc("/dir/a.txt")).get_versions()) == 2

        resp = proppatch(
            http, "/dir/a.txt", f"<D:getlastmodified>{Y2K}</D:getlastmodified>"
        )

        assert statuses(resp) == {f"{DAV}getlastmodified": "HTTP/1.1 409 Conflict"}
        assert await latest_timestamp(ops, "/dir/a.txt") == second
        assert (await ops.desc("/dir/a.txt")).get_latest_version().size == 3
        assert first <= second

    @pytest.mark.asyncio
    async def test_unparseable_date_is_a_conflict(self, http, ops):
        await ops.upload_from_bytes(b"x", "/dir/a.txt")
        before = await latest_timestamp(ops, "/dir/a.txt")

        resp = proppatch(
            http, "/dir/a.txt", "<D:getlastmodified>soon</D:getlastmodified>"
        )

        assert statuses(resp) == {f"{DAV}getlastmodified": "HTTP/1.1 409 Conflict"}
        assert await latest_timestamp(ops, "/dir/a.txt") == before

    @pytest.mark.asyncio
    async def test_folders_keep_their_own_timestamps(self, http):
        resp = proppatch(http, "/dir/", f"<D:getlastmodified>{Y2K}</D:getlastmodified>")

        assert resp.status_code == 207
        assert statuses(resp) == {f"{DAV}getlastmodified": "HTTP/1.1 403 Forbidden"}

    @pytest.mark.asyncio
    async def test_computed_properties_are_forbidden(self, http, ops):
        await ops.upload_from_bytes(b"x", "/dir/a.txt")

        resp = proppatch(
            http,
            "/dir/a.txt",
            "<D:displayname>b.txt</D:displayname>",
            "<D:getcontentlength>1</D:getcontentlength>",
        )

        assert statuses(resp) == {
            f"{DAV}displayname": "HTTP/1.1 403 Forbidden",
            f"{DAV}getcontentlength": "HTTP/1.1 403 Forbidden",
        }

    def test_missing_file_is_not_found(self, http):
        resp = proppatch(
            http, "/dir/none.txt", f"<D:getlastmodified>{Y2K}</D:getlastmodified>"
        )
        assert resp.status_code == 404

    def test_malformed_body_is_a_bad_request(self, http):
        resp = http.request("PROPPATCH", "/test/dir/", content="<broken")
        assert resp.status_code == 400

    def test_options_advertises_the_verb(self, http):
        resp = http.options("/test/dir/")
        assert "PROPPATCH" in resp.headers["Allow"].split(", ")
