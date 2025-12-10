from pydantic import BaseModel


class GetObjectRespHeaders(BaseModel):
    last_modified: str
    content_length: str
    cache_control: str
    content_disposition: str
    content_encoding: str
    content_language: str
    content_range: str
    content_type: str
    expires: str
