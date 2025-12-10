from urllib.parse import quote

from fastapi import Request


class AWSAuth:
    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
    ):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    @classmethod
    def _create_canonical_request(cls, request: Request) -> str:
        headers = {
            k.lower(): request.headers[k].strip() for k in request.headers.keys()
        }
        canonical_querystring = "&".join(
            f"{quote(k)}={quote(request.query_params[k])}"
            for k in sorted(request.query_params.keys())
        )
        canonical_headers = "".join(
            f"{k}:{headers[k]}\n" for k in sorted(headers.keys())
        )
        signed_headers = ";".join(sorted(headers.keys()))
        payload_hash = ""
        canonical_request = (
            f"{request.method}\n"
            f"{request.url}\n"
            f"{canonical_querystring}\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{payload_hash}"
        )
        return canonical_request

    @classmethod
    def _create_string_to_sign(cls, request: Request) -> str:
        canonical_request = cls._create_canonical_request(request)
        ts = request.headers.get("x-amz-date")
        payload_hash = request.headers.get("x-amz-content-sha256")

        return "AWS-HMAC-SHA256\n" f"{canonical_request}"
