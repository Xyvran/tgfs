from http import HTTPStatus

from fastapi import Response

from pys3.folder import Folder
from pys3.xml.list_buckets import ListBucketsResult, S3Bucket


async def handle_list_buckets(root_folder: Folder) -> Response:
    bucket_names = await root_folder.member_names()
    creation_date = await root_folder.creation_date()

    buckets = [
        S3Bucket(name=name, creation_date=creation_date)
        for name in sorted(bucket_names)
    ]

    result = ListBucketsResult(buckets=buckets)
    return Response(
        content=result.to_xml(),
        status_code=HTTPStatus.OK,
        media_type="application/xml; charset=utf-8",
    )
