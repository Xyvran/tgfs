from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote

import lxml.etree as et

from .common import root_element


@dataclass
class S3Object:
    key: str
    last_modified: str
    size: int
    etag: Optional[str] = None
    storage_class: str = "STANDARD"


@dataclass
class CommonPrefix:
    prefix: str


@dataclass
class ListObjectsV2Result:
    name: str
    prefix: str
    contents: List[S3Object]
    common_prefixes: List[CommonPrefix]
    max_keys: int = 1000
    key_count: int = 0
    is_truncated: bool = False
    delimiter: Optional[str] = None
    encoding_type: Optional[str] = None
    continuation_token: Optional[str] = None
    next_continuation_token: Optional[str] = None
    start_after: Optional[str] = None

    def to_xml(self) -> bytes:
        root = root_element("ListBucketResult")

        encode = self._url_encode if self.encoding_type == "url" else lambda x: x

        et.SubElement(root, "Name").text = self.name
        et.SubElement(root, "Prefix").text = encode(self.prefix)

        if self.delimiter:
            et.SubElement(root, "Delimiter").text = self.delimiter

        if self.encoding_type:
            et.SubElement(root, "EncodingType").text = self.encoding_type

        et.SubElement(root, "KeyCount").text = str(self.key_count)
        et.SubElement(root, "MaxKeys").text = str(self.max_keys)
        et.SubElement(root, "IsTruncated").text = (
            "true" if self.is_truncated else "false"
        )

        if self.continuation_token:
            et.SubElement(root, "ContinuationToken").text = self.continuation_token

        if self.next_continuation_token:
            et.SubElement(
                root, "NextContinuationToken"
            ).text = self.next_continuation_token

        if self.start_after:
            et.SubElement(root, "StartAfter").text = encode(self.start_after)

        for obj in self.contents:
            contents_elem = et.SubElement(root, "Contents")
            et.SubElement(contents_elem, "Key").text = encode(obj.key)
            et.SubElement(contents_elem, "LastModified").text = obj.last_modified
            if obj.etag:
                et.SubElement(contents_elem, "ETag").text = f'"{obj.etag}"'
            et.SubElement(contents_elem, "Size").text = str(obj.size)
            et.SubElement(contents_elem, "StorageClass").text = obj.storage_class

        for cp in self.common_prefixes:
            cp_elem = et.SubElement(root, "CommonPrefixes")
            et.SubElement(cp_elem, "Prefix").text = encode(cp.prefix)

        return et.tostring(root, xml_declaration=True, encoding="UTF-8")

    @staticmethod
    def _url_encode(value: str) -> str:
        return quote(value, safe="")
