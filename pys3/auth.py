import hashlib
import hmac
from typing import Dict
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
    def _parse_authorization_header(cls, request: Request) -> Dict[str, str]:
        auth_header = request.headers.get("authorization", "")
        if " " not in auth_header:
            return {}
        try:
            rest = auth_header.split(" ", 1)[1]
            return {
                k.strip(): v.strip()
                for k, v in (pair.split("=") for pair in rest.split(",") if "=" in pair)
            }
        except Exception:
            return {}

    @classmethod
    async def _create_canonical_request(cls, request: Request) -> str:
        canonical_querystring = "&".join(
            f"{quote(k)}={quote(request.query_params[k])}"
            for k in sorted(request.query_params.keys())
        )

        auth_params = cls._parse_authorization_header(request)
        signed_headers = auth_params.get("SignedHeaders", "")

        canonical_headers = "".join(
            f"{key.lower().strip()}:{request.headers.get(key, '').strip()}\n"
            for key in signed_headers.split(";")
            if key.strip()
        )

        body = await request.body()
        payload_hash = hashlib.sha256(body).hexdigest()

        return (
            f"{request.method}\n"
            f"{request.url.path}\n"
            f"{canonical_querystring}\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{payload_hash}"
        )

    @classmethod
    async def _create_string_to_sign(cls, request: Request) -> str:
        auth_header = request.headers.get("authorization", "")
        algorithm = auth_header.split(" ")[0] if auth_header else "AWS4-HMAC-SHA256"
        request_date_time = request.headers.get("x-amz-date", "")

        credential_scope = f"{request_date_time[:8]}/us-east-1/s3/aws4_request"

        canonical_request = await cls._create_canonical_request(request)
        hashed_canonical_request = hashlib.sha256(
            canonical_request.encode()
        ).hexdigest()

        return (
            f"{algorithm}\n"
            f"{request_date_time}\n"
            f"{credential_scope}\n"
            f"{hashed_canonical_request}"
        )

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def derive_signing_key_sigv4(self, request: Request) -> bytes:
        date = request.headers.get("x-amz-date", "")[:8]
        k_date = self._sign(f"AWS4{self.secret_access_key}".encode("utf-8"), date)
        k_region = self._sign(k_date, "us-east-1")
        k_service = self._sign(k_region, "s3")
        return self._sign(k_service, "aws4_request")

    async def authenticate(self, request: Request) -> bool:
        string_to_sign = await self._create_string_to_sign(request)
        signing_key = self.derive_signing_key_sigv4(request)

        calculated_signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        provided_signature = self._parse_authorization_header(request).get(
            "Signature", ""
        )

        return hmac.compare_digest(calculated_signature, provided_signature)
