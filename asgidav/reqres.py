import datetime
import email.utils
from dataclasses import dataclass
from http import HTTPStatus
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import lxml.etree as et
from fastapi import Request
from lxml.etree import _Element as Element

from asgidav.async_map import async_map
from asgidav.folder import Folder
from asgidav.member import Member, Properties, PropertyName, ResourceType

DAV_NS = "DAV:"
NS_MAP = {"D": DAV_NS}


@dataclass
class PropfindRequest:
    depth: int
    props: Tuple[str, ...] = (
        "displayname",
        "getcontentlength",
        "getcontenttype",
        "getetag",
        "getlastmodified",
        "creationdate",
        "resourcetype",
    )

    @classmethod
    async def from_request(cls, request: Request):
        depth = int(request.headers["Depth"])

        try:
            body = await request.body()
            root = et.fromstring(body)

            if root.find(".//D:propname", NS_MAP) is not None:
                return cls(depth=depth)

            if root.find(".//D:allprop", NS_MAP) is not None:
                return cls(depth=depth)

            if (elem := root.find(".//D:prop", NS_MAP)) is not None:
                requested_props = frozenset(
                    et.QName(prop_elem).localname for prop_elem in elem
                )
                return cls(
                    depth=depth, props=tuple(requested_props.intersection(cls.props))
                )
        except (et.XMLSyntaxError,):
            return cls(depth=depth)


def _tag(name: str) -> str:
    return "{%s}%s" % (DAV_NS, name)


async def _propstat(member: Member, prop_names: Tuple[PropertyName, ...]) -> Element:
    root = et.Element(_tag("propstat"), nsmap=NS_MAP)
    properties: Properties = await member.get_properties()
    props = et.SubElement(root, _tag("prop"))
    for name in set(prop_names) & set(properties.keys()):
        prop = et.SubElement(props, _tag(name))
        if name == "resourcetype" and member.resource_type == ResourceType.COLLECTION:
            et.SubElement(prop, _tag(properties[name]))
        else:
            prop.text = properties[name]

    status = et.SubElement(root, _tag("status"))
    status.text = "HTTP/1.1 200 OK"

    return root


async def _propfind_response(
    member: Member, depth: int, prop_names: Tuple[PropertyName, ...], base_path: str
) -> List[Element]:
    root = et.Element(_tag("response"))

    href = et.SubElement(root, _tag("href"))
    href.text = quote(f"{base_path}{member.path}", safe="/")

    propstat_elem = await _propstat(
        member=member,
        prop_names=prop_names,
    )
    root.append(propstat_elem)

    res = [root]

    if not isinstance(member, Folder) or depth == 0:
        return res

    folder: Folder = member

    names = await member.member_names()
    sub_members = await async_map(lambda name: folder.member(name), names)
    propfind_responses = await async_map(
        lambda m: _propfind_response(m, depth - 1, prop_names, base_path),
        (m for m in sub_members if m is not None),
    )
    for sub_response in propfind_responses:
        res.extend(sub_response)

    return res


async def propfind(
    members: Tuple[Member, ...],
    depth: int,
    prop_names: Tuple[PropertyName, ...],
    base_path: str,
) -> str:
    root = et.Element(_tag("multistatus"), nsmap=NS_MAP)

    for propfind_responses in await async_map(
        lambda member: _propfind_response(member, depth, prop_names, base_path), members
    ):
        for response in propfind_responses:
            root.append(response)

    et.register_namespace("D", DAV_NS)
    return et.tostring(root, encoding="unicode")


# -- PROPPATCH ---------------------------------------------------------------

MS_NS = "urn:schemas-microsoft-com:"


def _ms_tag(name: str) -> str:
    return "{%s}%s" % (MS_NS, name)


# The properties a PROPPATCH may set: both spellings of the modification
# time, the DAV one and the one Windows clients (and CarotDAV) send.
LAST_MODIFIED_TAGS = frozenset(
    {_tag("getlastmodified"), _ms_tag("Win32LastModifiedTime")}
)

# Live properties this server computes and never lets a client change.
PROTECTED_TAGS = frozenset(
    {
        _tag("creationdate"),
        _tag("displayname"),
        _tag("getcontentlength"),
        _tag("getcontenttype"),
        _tag("getetag"),
        _tag("resourcetype"),
        _tag("lockdiscovery"),
        _tag("supportedlock"),
        _ms_tag("Win32CreationTime"),
        _ms_tag("Win32LastAccessTime"),
        _ms_tag("Win32FileAttributes"),
    }
)


@dataclass
class PropertyUpdate:
    """One ``set`` or ``remove`` of a PROPPATCH body."""

    tag: str  # Clark notation: {namespace}localname
    value: Optional[str]  # None for a removal
    remove: bool = False


@dataclass
class ProppatchRequest:
    updates: List[PropertyUpdate]

    @classmethod
    async def from_request(cls, request: Request) -> "ProppatchRequest":
        """Parse a ``propertyupdate`` body; ``ValueError`` when it is not one."""
        try:
            root = et.fromstring(await request.body())
        except et.XMLSyntaxError as ex:
            raise ValueError(f"not well-formed XML: {ex}") from ex
        if root.tag != _tag("propertyupdate"):
            raise ValueError("the body is not a DAV:propertyupdate")

        updates: List[PropertyUpdate] = []
        for action in root:
            if action.tag not in (_tag("set"), _tag("remove")):
                continue
            remove = action.tag == _tag("remove")
            for prop in action.findall("D:prop", NS_MAP):
                for elem in prop:
                    if not isinstance(elem.tag, str):
                        continue  # a comment or processing instruction
                    updates.append(
                        PropertyUpdate(
                            tag=elem.tag,
                            value=None if remove else (elem.text or "").strip(),
                            remove=remove,
                        )
                    )
        return cls(updates=updates)


def parse_http_date(value: str) -> int:
    """An RFC 1123 (or ISO 8601) date as Unix milliseconds.

    ``getlastmodified`` and ``Win32LastModifiedTime`` are RFC 1123 dates;
    ISO 8601 is accepted as well because some clients send the
    ``creationdate`` format for both. A date without a zone is UTC.
    """
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as ex:
            raise ValueError(f"not a date: {value!r}") from ex
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp() * 1000)


async def _apply_property(member: Member, update: PropertyUpdate) -> HTTPStatus:
    """Apply one property update and say how it went, RFC 4918 9.2 style.

    200 when stored, 403 for a property this server computes itself or
    cannot store, 409 for a value the member does not accept.
    """
    if update.tag in LAST_MODIFIED_TAGS:
        if update.remove:
            return HTTPStatus.FORBIDDEN
        try:
            timestamp = parse_http_date(update.value or "")
            await member.set_last_modified(timestamp)
        except NotImplementedError:
            return HTTPStatus.FORBIDDEN
        except ValueError:
            return HTTPStatus.CONFLICT
        return HTTPStatus.OK
    if update.tag in PROTECTED_TAGS:
        return HTTPStatus.FORBIDDEN
    # A dead property: there is nowhere to keep it, so setting one is
    # refused. Removing one is a success, it does not exist either way.
    return HTTPStatus.OK if update.remove else HTTPStatus.FORBIDDEN


async def proppatch(
    member: Member, updates: Sequence[PropertyUpdate], base_path: str
) -> str:
    """Answer a PROPPATCH with a ``multistatus`` body.

    Every property is applied and reported on its own. RFC 4918 asks for
    all-or-nothing, but clients set the modification time in one request
    with properties this server cannot store (Windows attributes, creation
    time); under all-or-nothing the time would never get through. The
    per-property status tells the client exactly what was kept.
    """
    by_status: Dict[HTTPStatus, List[str]] = {}
    for update in updates:
        status = await _apply_property(member, update)
        by_status.setdefault(status, []).append(update.tag)

    root = et.Element(_tag("multistatus"), nsmap=NS_MAP)
    response = et.SubElement(root, _tag("response"))
    href = et.SubElement(response, _tag("href"))
    href.text = quote(f"{base_path}{member.path}", safe="/")
    for status in sorted(by_status):
        propstat = et.SubElement(response, _tag("propstat"))
        prop = et.SubElement(propstat, _tag("prop"))
        for tag in by_status[status]:
            et.SubElement(prop, tag)
        status_elem = et.SubElement(propstat, _tag("status"))
        status_elem.text = f"HTTP/1.1 {status.value} {status.phrase}"

    et.register_namespace("D", DAV_NS)
    return et.tostring(root, encoding="unicode")
