import asyncio
from http import HTTPStatus

from fastapi import Response

from pys3.resource import Resource


async def handle_head_object(resource: Resource) -> Response:
    last_modified, content_length = await asyncio.gather(
        resource.last_modified(),
        resource.content_length(),
    )

    return Response(
        status_code=HTTPStatus.OK,
        headers={
            "Last-Modified": str(last_modified),
        },
    )
