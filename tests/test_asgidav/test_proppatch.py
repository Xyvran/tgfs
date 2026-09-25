"""PROPPATCH: parsing the body and answering per property."""

import pytest
from fastapi import Request
from lxml import etree as et

from asgidav.reqres import (
    PropertyUpdate,
    ProppatchRequest,
    parse_http_date,
    proppatch,
)
from .common import MockFolder, MockResource

DAV = "{DAV:}"
MS = "{urn:schemas-microsoft-com:}"


def request_with(body: bytes, mocker) -> Request:
    request = mocker.Mock(spec=Request)
    request.body = mocker.AsyncMock(return_value=body)
    return request


def statuses(xml: str) -> dict[str, str]:
    """Property tag -> status line, from a multistatus body."""
    root = et.fromstring(xml.encode())
    result: dict[str, str] = {}
    for propstat in root.iter(f"{DAV}propstat"):
        status = propstat.findtext(f"{DAV}status") or ""
        props = propstat.find(f"{DAV}prop")
        assert props is not None
        for prop in props:
            result[str(prop.tag)] = status
    return result


class TestProppatchRequest:
    @pytest.mark.asyncio
    async def test_set_and_remove_are_collected(self, mocker):
        body = b"""<?xml version="1.0"?>
        <D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:">
          <D:set><D:prop>
            <D:getlastmodified>Sat, 01 Jan 2000 00:00:00 GMT</D:getlastmodified>
            <Z:Win32FileAttributes>00000020</Z:Win32FileAttributes>
          </D:prop></D:set>
          <D:remove><D:prop><Z:Win32CreationTime/></D:prop></D:remove>
        </D:propertyupdate>"""

        r = await ProppatchRequest.from_request(request_with(body, mocker))

        assert r.updates == [
            PropertyUpdate(f"{DAV}getlastmodified", "Sat, 01 Jan 2000 00:00:00 GMT"),
            PropertyUpdate(f"{MS}Win32FileAttributes", "00000020"),
            PropertyUpdate(f"{MS}Win32CreationTime", None, remove=True),
        ]

    @pytest.mark.asyncio
    async def test_malformed_xml_is_rejected(self, mocker):
        with pytest.raises(ValueError, match="well-formed"):
            await ProppatchRequest.from_request(request_with(b"<D:set>", mocker))

    @pytest.mark.asyncio
    async def test_other_root_element_is_rejected(self, mocker):
        body = b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        with pytest.raises(ValueError, match="propertyupdate"):
            await ProppatchRequest.from_request(request_with(body, mocker))


class TestParseHttpDate:
    def test_rfc1123(self):
        assert parse_http_date("Sat, 01 Jan 2000 00:00:00 GMT") == 946684800000

    def test_iso8601(self):
        assert parse_http_date("2000-01-01T00:00:00Z") == 946684800000
        assert parse_http_date("2000-01-01T01:00:00+01:00") == 946684800000

    def test_garbage(self):
        with pytest.raises(ValueError):
            parse_http_date("yesterday")


class TestProppatch:
    @pytest.mark.asyncio
    async def test_last_modified_is_stored(self):
        resource = MockResource("/test.txt")
        update = PropertyUpdate(
            f"{DAV}getlastmodified", "Sat, 01 Jan 2000 00:00:00 GMT"
        )

        xml = await proppatch(resource, [update], "/webdav")

        assert statuses(xml) == {f"{DAV}getlastmodified": "HTTP/1.1 200 OK"}
        assert await resource.last_modified() == 946684800000
        assert (
            et.fromstring(xml.encode()).findtext(f".//{DAV}href") == "/webdav/test.txt"
        )

    @pytest.mark.asyncio
    async def test_windows_spelling_is_stored_too(self):
        resource = MockResource("/test.txt")
        update = PropertyUpdate(
            f"{MS}Win32LastModifiedTime", "Sat, 01 Jan 2000 00:00:00 GMT"
        )

        xml = await proppatch(resource, [update], "")

        assert statuses(xml) == {f"{MS}Win32LastModifiedTime": "HTTP/1.1 200 OK"}
        assert await resource.last_modified() == 946684800000

    @pytest.mark.asyncio
    async def test_each_property_is_answered_on_its_own(self):
        resource = MockResource("/test.txt")
        updates = [
            PropertyUpdate(f"{DAV}getlastmodified", "Sat, 01 Jan 2000 00:00:00 GMT"),
            PropertyUpdate(f"{MS}Win32CreationTime", "Sat, 01 Jan 2000 00:00:00 GMT"),
            PropertyUpdate(f"{MS}Win32FileAttributes", "00000020"),
            PropertyUpdate("{http://example.com/}color", "blue"),
            PropertyUpdate("{http://example.com/}gone", None, remove=True),
        ]

        xml = await proppatch(resource, updates, "")

        assert statuses(xml) == {
            f"{DAV}getlastmodified": "HTTP/1.1 200 OK",
            f"{MS}Win32CreationTime": "HTTP/1.1 200 OK",
            f"{MS}Win32FileAttributes": "HTTP/1.1 200 OK",
            "{http://example.com/}color": "HTTP/1.1 403 Forbidden",
            "{http://example.com/}gone": "HTTP/1.1 200 OK",
        }
        assert await resource.last_modified() == 946684800000

    @pytest.mark.asyncio
    async def test_windows_attributes_are_accepted_and_not_stored(self):
        resource = MockResource("/test.txt")
        updates = [
            PropertyUpdate(f"{MS}Win32CreationTime", "Sat, 01 Jan 2000 00:00:00 GMT"),
            PropertyUpdate(f"{MS}Win32LastAccessTime", "Sat, 01 Jan 2000 00:00:00 GMT"),
            PropertyUpdate(f"{MS}Win32FileAttributes", "00000020"),
        ]

        xml = await proppatch(resource, updates, "")

        assert set(statuses(xml).values()) == {"HTTP/1.1 200 OK"}
        assert await resource.creation_date() == 1609459200000
        assert await resource.last_modified() == 1609545600000

    @pytest.mark.asyncio
    async def test_unparseable_date_is_a_conflict(self):
        resource = MockResource("/test.txt")
        update = PropertyUpdate(f"{DAV}getlastmodified", "yesterday")

        xml = await proppatch(resource, [update], "")

        assert statuses(xml) == {f"{DAV}getlastmodified": "HTTP/1.1 409 Conflict"}
        assert await resource.last_modified() == 1609545600000

    @pytest.mark.asyncio
    async def test_rejected_value_is_a_conflict(self):
        resource = MockResource("/test.txt")
        update = PropertyUpdate(
            f"{DAV}getlastmodified", "Thu, 01 Jan 1960 00:00:00 GMT"
        )

        xml = await proppatch(resource, [update], "")

        assert statuses(xml) == {f"{DAV}getlastmodified": "HTTP/1.1 409 Conflict"}

    @pytest.mark.asyncio
    async def test_removing_the_modification_time_is_forbidden(self):
        resource = MockResource("/test.txt")
        update = PropertyUpdate(f"{DAV}getlastmodified", None, remove=True)

        xml = await proppatch(resource, [update], "")

        assert statuses(xml) == {f"{DAV}getlastmodified": "HTTP/1.1 403 Forbidden"}

    @pytest.mark.asyncio
    async def test_member_without_a_timestamp_forbids_it(self):
        folder = MockFolder("/dir")
        update = PropertyUpdate(
            f"{DAV}getlastmodified", "Sat, 01 Jan 2000 00:00:00 GMT"
        )

        xml = await proppatch(folder, [update], "")

        assert statuses(xml) == {f"{DAV}getlastmodified": "HTTP/1.1 403 Forbidden"}
