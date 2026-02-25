import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Dict, Tuple
from urllib.parse import quote

from fastapi import Request


def is_presigned_request(request: Request) -> bool:
    return (
        "X-Amz-Signature" in request.query_params
        and "Authorization" not in request.headers
    )


class AWSAuthBase(ABC):
    def __init__(self, access_key_id: str, secret_access_key: str):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    @abstractmethod
    def _get_algorithm(self, request: Request) -> str:
        """Get the signing algorithm from the request."""
        pass

    @abstractmethod
    def _get_signed_headers(self, request: Request) -> str:
        """Get the semicolon-separated list of signed headers."""
        pass

    @abstractmethod
    def _get_credential_scope_and_date(self, request: Request) -> Tuple[str, str]:
        """Get (credential_scope, request_datetime) from the request."""
        pass

    @abstractmethod
    def _get_provided_signature(self, request: Request) -> str:
        """Get the signature provided in the request."""
        pass

    @abstractmethod
    def _get_provided_access_key(self, request: Request) -> str:
        """Get the access key ID from the request."""
        pass

    @abstractmethod
    def _get_request_date(self, request: Request) -> str:
        """Get the request date (YYYYMMDD) for signing key derivation."""
        pass

    @abstractmethod
    def _is_presigned(self) -> bool:
        pass

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _derive_signing_key(self, date: str, region: str, service: str) -> bytes:
        k_date = self._sign(f"AWS4{self.secret_access_key}".encode("utf-8"), date)
        k_region = self._sign(k_date, region)
        k_service = self._sign(k_region, service)
        return self._sign(k_service, "aws4_request")

    def _get_payload_hash(self, request: Request, body: bytes) -> str:
        content_sha256 = request.headers.get("x-amz-content-sha256")
        if content_sha256:
            return content_sha256

        if self._is_presigned():
            return "UNSIGNED-PAYLOAD"

        return hashlib.sha256(body).hexdigest()

    def _build_canonical_query_string(self, request: Request) -> str:
        params = dict(request.query_params)
        if self._is_presigned():
            params.pop("X-Amz-Signature", None)

        return "&".join(
            f"{quote(k, safe='~')}={quote(params[k], safe='~')}"
            for k in sorted(params.keys())
        )

    @staticmethod
    def _canonical_uri(request: Request) -> str:
        return quote(request.url.path, safe="/")

    async def _create_canonical_request(self, request: Request) -> str:
        canonical_querystring = self._build_canonical_query_string(request)
        signed_headers = self._get_signed_headers(request)

        canonical_headers = "".join(
            f"{key.lower().strip()}:{request.headers.get(key, '').strip()}\n"
            for key in signed_headers.split(";")
            if key.strip()
        )

        body = await request.body()
        payload_hash = self._get_payload_hash(request, body)

        return (
            f"{request.method}\n"
            f"{self._canonical_uri(request)}\n"
            f"{canonical_querystring}\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{payload_hash}"
        )

    async def _create_string_to_sign(self, request: Request) -> str:
        algorithm = self._get_algorithm(request)
        credential_scope, request_date_time = self._get_credential_scope_and_date(
            request
        )

        canonical_request = await self._create_canonical_request(request)
        hashed_canonical_request = hashlib.sha256(
            canonical_request.encode()
        ).hexdigest()

        return (
            f"{algorithm}\n"
            f"{request_date_time}\n"
            f"{credential_scope}\n"
            f"{hashed_canonical_request}"
        )

    def _verify_access_key(self, request: Request) -> bool:
        return self._get_provided_access_key(request) == self.access_key_id

    async def authenticate(self, request: Request) -> bool:
        if not self._verify_access_key(request):
            return False

        string_to_sign = await self._create_string_to_sign(request)
        credential_scope, _ = self._get_credential_scope_and_date(request)
        # scope format: date/region/service/aws4_request
        scope_parts = credential_scope.split("/")
        signing_key = self._derive_signing_key(scope_parts[0], scope_parts[1], scope_parts[2])

        calculated_signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        provided_signature = self._get_provided_signature(request)

        return hmac.compare_digest(calculated_signature, provided_signature)


class AWSHeaderAuth(AWSAuthBase):
    @staticmethod
    def _parse_authorization_header(request: Request) -> Dict[str, str]:
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

    def _is_presigned(self) -> bool:
        return False

    def _get_algorithm(self, request: Request) -> str:
        auth_header = request.headers.get("authorization", "")
        return auth_header.split(" ")[0] if auth_header else "AWS4-HMAC-SHA256"

    def _get_signed_headers(self, request: Request) -> str:
        auth_params = self._parse_authorization_header(request)
        return auth_params.get("SignedHeaders", "")

    def _get_credential_scope_and_date(self, request: Request) -> Tuple[str, str]:
        auth_params = self._parse_authorization_header(request)
        credential = auth_params.get("Credential", "")
        parts = credential.split("/", 1)
        scope = parts[1] if len(parts) > 1 else ""
        request_date_time = request.headers.get("x-amz-date", "")
        return scope, request_date_time

    def _get_provided_signature(self, request: Request) -> str:
        return self._parse_authorization_header(request).get("Signature", "")

    def _get_provided_access_key(self, request: Request) -> str:
        auth_params = self._parse_authorization_header(request)
        credential = auth_params.get("Credential", "")
        return credential.split("/")[0] if "/" in credential else credential

    def _get_request_date(self, request: Request) -> str:
        return request.headers.get("x-amz-date", "")[:8]


class AWSPresignedAuth(AWSAuthBase):
    def _is_presigned(self) -> bool:
        return True

    def _get_algorithm(self, request: Request) -> str:
        return request.query_params.get("X-Amz-Algorithm", "AWS4-HMAC-SHA256")

    def _get_signed_headers(self, request: Request) -> str:
        return request.query_params.get("X-Amz-SignedHeaders", "")

    def _get_credential_scope_and_date(self, request: Request) -> Tuple[str, str]:
        credential = request.query_params.get("X-Amz-Credential", "")
        parts = credential.split("/", 1)
        scope = parts[1] if len(parts) > 1 else ""
        request_date_time = request.query_params.get("X-Amz-Date", "")
        return scope, request_date_time

    def _get_provided_signature(self, request: Request) -> str:
        return request.query_params.get("X-Amz-Signature", "")

    def _get_provided_access_key(self, request: Request) -> str:
        credential = request.query_params.get("X-Amz-Credential", "")
        return credential.split("/")[0] if "/" in credential else credential

    def _get_request_date(self, request: Request) -> str:
        return request.query_params.get("X-Amz-Date", "")[:8]


async def authenticate_request(
    request: Request, access_key_id: str, secret_access_key: str
) -> bool:
    auth = (
        AWSPresignedAuth(access_key_id, secret_access_key)
        if is_presigned_request(request)
        else AWSHeaderAuth(access_key_id, secret_access_key)
    )

    return await auth.authenticate(request)
