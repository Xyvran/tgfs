import asyncio
from http import HTTPStatus
from typing import Optional, Tuple

from fastapi.responses import StreamingResponse

from pys3.resource import Resource


def _parse_range_header(range_header: Optional[str]) -> Tuple[int, int]:
    if range_header:
        begin_str, end_str = range_header.replace("bytes=", "").split("-", 1)
        begin = int(begin_str) if begin_str else 0
        end = int(end_str) if end_str else -1
        return begin, end
    return 0, -1


async def handle_get_object(
    resource: Resource, range_header: Optional[str] = None
) -> StreamingResponse:
    begin, end = _parse_range_header(range_header)

    content, media_type, last_modified, content_length = await asyncio.gather(
        resource.get_content(begin, end),
        resource.content_type(),
        resource.last_modified(),
        resource.content_length(),
    )

    headers = {
        "Last-Modified": str(last_modified),
        "Accept-Ranges": "bytes",
    }

    if range_header is not None:
        status_code = HTTPStatus.PARTIAL_CONTENT
    else:
        status_code = HTTPStatus.OK

    return StreamingResponse(
        content=content,
        status_code=status_code,
        media_type=media_type,
        headers=headers,
    )
