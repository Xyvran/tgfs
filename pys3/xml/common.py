import lxml.etree as et
from lxml.etree import _Element as Element

S3_NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"


def root_element(tag: str) -> Element:
    return et.Element(tag, nsmap={None: S3_NAMESPACE})  # type: ignore[dict-item]
