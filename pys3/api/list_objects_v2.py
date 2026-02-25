import asyncio
import base64
from dataclasses import dataclass
from http import HTTPStatus
from typing import List, Optional, Set, Tuple

from fastapi import Response

from pys3.folder import Folder
from pys3.member import Member
from pys3.resource import Resource
from pys3.xml_builder.list_objects_v2 import (
    CommonPrefix,
    ListObjectsV2Result,
    S3Object,
)


@dataclass
class ObjectEntry:
    key: str
    last_modified: str
    size: int
    etag: Optional[str] = None


async def collect_objects(
    folder: Folder, prefix: str = "", relative_path: str = ""
) -> List[ObjectEntry]:
    member_names = await folder.member_names()

    members = await asyncio.gather(*(folder.member(name) for name in member_names))

    async def process_member(name: str, member: Optional[Member]) -> List[ObjectEntry]:
        if member is None:
            return []
        key = f"{relative_path}{name}" if relative_path else name
        if isinstance(member, Resource):
            last_modified, size = await asyncio.gather(
                member.last_modified(), member.content_length()
            )
            return [ObjectEntry(key=key, last_modified=last_modified, size=size)]
        if isinstance(member, Folder):
            return await collect_objects(member, prefix, relative_path=f"{key}/")
        return []

    results = await asyncio.gather(
        *(process_member(name, m) for name, m in zip(member_names, members))
    )

    return [entry for entries in results for entry in entries]


def _filter_by_prefix(entries: List[ObjectEntry], prefix: str) -> List[ObjectEntry]:
    if not prefix:
        return entries
    return [e for e in entries if e.key.startswith(prefix)]


def _apply_delimiter(
    entries: List[ObjectEntry], prefix: str, delimiter: str
) -> Tuple[List[ObjectEntry], Set[str]]:
    if not delimiter:
        return entries, set()

    result_entries: List[ObjectEntry] = []
    common_prefixes: Set[str] = set()
    prefix_len = len(prefix)

    for entry in entries:
        suffix = entry.key[prefix_len:]
        delimiter_pos = suffix.find(delimiter)

        if delimiter_pos >= 0:
            common_prefix = entry.key[: prefix_len + delimiter_pos + len(delimiter)]
            common_prefixes.add(common_prefix)
        else:
            result_entries.append(entry)

    return result_entries, common_prefixes


def _paginate(
    entries: List[ObjectEntry],
    common_prefixes: Set[str],
    max_keys: int,
    start_after: Optional[str] = None,
    continuation_token: Optional[str] = None,
) -> Tuple[List[ObjectEntry], List[str], bool, Optional[str]]:
    cursor = None
    if continuation_token:
        cursor = base64.urlsafe_b64decode(continuation_token.encode()).decode()
    elif start_after:
        cursor = start_after

    entries_sorted = sorted(entries, key=lambda e: e.key)
    prefixes_sorted = sorted(common_prefixes)

    all_keys: List[Tuple[str, bool, int]] = []
    for i, e in enumerate(entries_sorted):
        all_keys.append((e.key, False, i))
    for i, p in enumerate(prefixes_sorted):
        all_keys.append((p, True, i))

    all_keys.sort(key=lambda x: x[0])

    if cursor:
        all_keys = [(k, is_prefix, idx) for k, is_prefix, idx in all_keys if k > cursor]

    truncated_keys = all_keys[:max_keys]
    is_truncated = len(all_keys) > max_keys

    result_entries: List[ObjectEntry] = []
    result_prefixes: List[str] = []

    for key, is_prefix, idx in truncated_keys:
        if is_prefix:
            result_prefixes.append(key)
        else:
            result_entries.append(entries_sorted[idx])

    next_token = None
    if is_truncated and truncated_keys:
        last_key = truncated_keys[-1][0]
        next_token = base64.urlsafe_b64encode(last_key.encode()).decode()

    return result_entries, result_prefixes, is_truncated, next_token


async def handle_list_objects_v2(
    folder: Folder,
    bucket_name: str,
    prefix: str = "",
    delimiter: Optional[str] = None,
    max_keys: int = 1000,
    start_after: Optional[str] = None,
    continuation_token: Optional[str] = None,
    encoding_type: Optional[str] = None,
) -> Response:
    all_entries = await collect_objects(folder)

    filtered_entries = _filter_by_prefix(all_entries, prefix)

    delimited_entries, common_prefix_set = _apply_delimiter(
        filtered_entries, prefix, delimiter or ""
    )

    paginated_entries, paginated_prefixes, is_truncated, next_token = _paginate(
        delimited_entries,
        common_prefix_set,
        max_keys,
        start_after,
        continuation_token,
    )

    contents = [
        S3Object(
            key=e.key,
            last_modified=e.last_modified,
            size=e.size,
            etag=e.etag,
        )
        for e in paginated_entries
    ]

    common_prefixes = [CommonPrefix(prefix=p) for p in paginated_prefixes]

    result = ListObjectsV2Result(
        name=bucket_name,
        prefix=prefix,
        contents=contents,
        common_prefixes=common_prefixes,
        max_keys=max_keys,
        key_count=len(contents) + len(common_prefixes),
        is_truncated=is_truncated,
        delimiter=delimiter,
        encoding_type=encoding_type,
        continuation_token=continuation_token,
        next_continuation_token=next_token,
        start_after=start_after,
    )
    return Response(
        content=result.to_xml(),
        status_code=HTTPStatus.OK,
        media_type="application/xml; charset=utf-8",
    )
