import posixpath
from http import HTTPStatus
from typing import Annotated, Awaitable, Callable, Optional, Tuple

from fastapi import FastAPI, Header, Query, Response
from starlette.requests import Request

from tgfs.config import get_config

from .api.get_object import handle_get_object
from .api.head_object import handle_head_object
from .api.list_buckets import handle_list_buckets
from .api.list_objects_v2 import handle_list_objects_v2
from .auth import authenticate_request
from .folder import Folder
from .member import Member
from .resource import Resource


def q(alias: str):
    return Query(None, alias=alias)


def parse_bucket_key(key: str, prefix: Optional[str] = None) -> Tuple[str, str]:
    """Parse an S3 path into bucket name and effective prefix.

    Splits "bucket/path/to/dir" into ("bucket", "path/to/dir"),
    then merges with the query-string prefix if provided.
    """
    bucket, _, base_prefix = key.partition("/")
    effective_prefix = posixpath.join(base_prefix, prefix) if prefix else base_prefix
    return bucket, effective_prefix


def create_app(
    get_member: Callable[[str], Awaitable[Optional[Member]]],
    base_path: str = "",
):
    app = FastAPI()

    NOT_FOUND = Response(
        status_code=HTTPStatus.NOT_FOUND,
        headers={"Content-Type": "text/plain"},
    )

    @app.head("/{key:path}")
    async def route_head(
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
        member = await get_member(f"/{key}")
        if not member or not isinstance(member, Resource):
            return NOT_FOUND

        return await handle_head_object(member)

    @app.get("/{key:path}")
    async def route_get(
        key: str,
        request: Request,
        host: Annotated[str, Header()],
        list_type: Optional[str] = q("list-type"),
        prefix: Optional[str] = q("prefix"),
        delimiter: Optional[str] = q("delimiter"),
        max_keys: Optional[int] = q("max-keys"),
        continuation_token: Optional[str] = q("continuation-token"),
        start_after: Optional[str] = q("start-after"),
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
        config = get_config()
        if not await authenticate_request(
            request,
            config.tgfs.server.s3.access_key_id,
            config.tgfs.server.s3.secret_access_key,
        ):
            return Response(status_code=HTTPStatus.UNAUTHORIZED)

        # ListBuckets: GET /
        if key == "" or key == "/":
            root_folder = await get_member("/")
            if root_folder and isinstance(root_folder, Folder):
                return await handle_list_buckets(root_folder)
            return NOT_FOUND

        # ListObjectsV2: GET /{bucket}[/{prefix}]?list-type=2
        if list_type == "2":
            bucket_name, effective_prefix = parse_bucket_key(key, prefix)

            bucket_folder = await get_member(f"/{bucket_name}")
            if not bucket_folder or not isinstance(bucket_folder, Folder):
                return NOT_FOUND

            return await handle_list_objects_v2(
                folder=bucket_folder,
                bucket_name=bucket_name,
                prefix=effective_prefix,
                delimiter=delimiter,
                max_keys=max_keys or 1000,
                start_after=start_after,
                continuation_token=continuation_token,
                encoding_type=encoding_type,
            )

        # GetObject: GET /{bucket}/{key}
        member = await get_member(f"/{key}")
        if not member or not isinstance(member, Resource):
            return NOT_FOUND

        return await handle_get_object(member, range_header)

    return app
