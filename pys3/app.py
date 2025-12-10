import asyncio
from http import HTTPStatus
from typing import Annotated, Awaitable, Callable, Optional

from fastapi import FastAPI, Header, Query, Response
from fastapi.responses import StreamingResponse
from starlette.requests import Request

from .member import Member
from .resource import Resource


def q(alias: str):
    return Query(None, alias=alias)


def create_app(
    get_member: Callable[[str], Awaitable[Optional[Member]]],
    base_path: str = "",
):
    app = FastAPI()

    NOT_FOUND = Response(
        status_code=HTTPStatus.NOT_FOUND,
        headers={
            "Content-Type": "text/plain",
        },
    )

    @app.head("/{key:path}")
    async def head_object(
        key: str,
        host: Annotated[str, Header()],
        part_number: Optional[int] = q("partNumber"),
        response_cache_control: Optional[str] = q("response-cache-control"),
        response_content_disposition: Optional[str] = q("response-content-disposition"),
        response_content_encoding: Optional[str] = q("response-content-encoding"),
        response_content_language: Optional[str] = q("response-content-language"),
        response_content_type: Optional[str] = q("response-content-type"),
        response_expires: Optional[str] = q("response-expires"),
        version_id: Optional[str] = q("versionId"),
        auth_header: Annotated[Optional[str], Header(alias="Authorization")] = None,
        range_header: Annotated[Optional[str], Header(alias="range")] = None,
    ):
        if member := await get_member(f"/{key}"):
            begin, end = 0, -1
            if isinstance(member, Resource):
                last_modified = await member.last_modified()

                headers = {
                    "Last-Modified": str(last_modified),
                }

                status_code = HTTPStatus.OK
                return Response(status_code=status_code, headers=headers)

            raise ValueError("Expected a Resource, got a Folder")
        return NOT_FOUND

    @app.get("/{key:path}")
    async def get_object(
        key: str,
        request: Request,
        host: Annotated[str, Header()],
        list_type: Optional[str] = q("list-type"),
        prefix: Optional[str] = q("prefix"),
        encoding_type: Optional[str] = q("encoding-type"),
        part_number: Optional[int] = q("partNumber"),
        response_cache_control: Optional[str] = q("response-cache-control"),
        response_content_disposition: Optional[str] = q("response-content-disposition"),
        response_content_encoding: Optional[str] = q("response-content-encoding"),
        response_content_language: Optional[str] = q("response-content-language"),
        response_content_type: Optional[str] = q("response-content-type"),
        response_expires: Optional[str] = q("response-expires"),
        version_id: Optional[str] = q("versionId"),
        auth_header: Annotated[Optional[str], Header(alias="Authorization")] = None,
        range_header: Annotated[Optional[str], Header(alias="range")] = None,
    ):
        print(request.headers)
        print(f"GET Object: key={key}")
        print(f"  list_type={list_type}")
        print(f"  part_number={part_number}")
        print(f"  response_cache_control={response_cache_control}")
        print(f"  response_content_disposition={response_content_disposition}")
        print(f"  response_content_encoding={response_content_encoding}")
        print(f"  response_content_language={response_content_language}")
        print(f"  response_content_type={response_content_type}")
        print(f"  response_expires={response_expires}")
        print(f"  version_id={version_id}")
        print(f"  auth_header={auth_header}")
        print(f"  range_header={range_header}")
        if member := await get_member(f"/{key}"):
            begin, end = 0, -1
            if isinstance(member, Resource):
                content, media_type, last_modified, content_length = (
                    await asyncio.gather(
                        member.get_content(begin, end),
                        member.content_type(),
                        member.last_modified(),
                        member.content_length(),
                    )
                )

                headers = {
                    "Last-Modified": str(last_modified),
                    "Accept-Ranges": "bytes",
                }

                status_code = HTTPStatus.OK

                return StreamingResponse(
                    content=content,
                    status_code=status_code,
                    media_type=media_type,
                    headers=headers,
                )

            raise ValueError("Expected a Resource, got a Folder")
        return NOT_FOUND

    return app
