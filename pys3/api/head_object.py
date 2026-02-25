import asyncio
from http import HTTPStatus

from fastapi import Response

from pys3.resource import Resource


async def handle_head_object(resource: Resource) -> Response:
    last_modified, content_length, content_type = await asyncio.gather(
        resource.last_modified(),
        resource.content_length(),
        resource.content_type(),
    )

    return Response(
        status_code=HTTPStatus.OK,
        headers={
            "Last-Modified": str(last_modified),
            "Content-Length": str(content_length),
            "Content-Type": content_type,
            "Accept-Ranges": "bytes",
        },
    )
