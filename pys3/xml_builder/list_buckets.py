from dataclasses import dataclass, field
from typing import List

import lxml.etree as et

from .common import root_element


@dataclass
class S3Bucket:
    name: str
    creation_date: str


@dataclass
class S3Owner:
    id: str = "owner-id"
    display_name: str = "owner"


@dataclass
class ListBucketsResult:
    buckets: List[S3Bucket]
    owner: S3Owner = field(default_factory=S3Owner)

    def to_xml(self) -> bytes:
        root = root_element("ListAllMyBucketsResult")

        owner_elem = et.SubElement(root, "Owner")
        et.SubElement(owner_elem, "ID").text = self.owner.id
        et.SubElement(owner_elem, "DisplayName").text = self.owner.display_name

        buckets_elem = et.SubElement(root, "Buckets")
        for bucket in self.buckets:
            bucket_elem = et.SubElement(buckets_elem, "Bucket")
            et.SubElement(bucket_elem, "Name").text = bucket.name
            et.SubElement(bucket_elem, "CreationDate").text = bucket.creation_date

        return et.tostring(root, xml_declaration=True, encoding="UTF-8")
