"""
Loystar API client used by MCP tools.

The Postman documentation exposes many Loystar endpoints, including internal
localhost examples. This client intentionally wraps a small read-only allowlist
first, so the AI can query merchant-owned data without gaining arbitrary API
write access.
"""
from __future__ import annotations

import json
import re
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from src.config import settings


class LoystarAPIError(RuntimeError):
    """Raised when a Loystar API request fails."""


@dataclass(frozen=True)
class LoystarCredentials:
    """Per-request Loystar merchant session headers."""

    access_token: str
    client: str
    uid: str
    expiry: str
    token_type: str = "Bearer"


current_loystar_credentials: ContextVar[Optional[LoystarCredentials]] = ContextVar(
    "current_loystar_credentials",
    default=None,
)


class LoystarClient:
    """Typed wrapper around merchant-safe Loystar API endpoints."""

    _BRANCH_RESPONSE_FIELDS = {
        "active",
        "address",
        "address_line_1",
        "address_line_2",
        "attributes",
        "branch_address",
        "branch_code",
        "branch_name",
        "business_branches",
        "city",
        "country",
        "created_at",
        "data",
        "id",
        "latitude",
        "longitude",
        "name",
        "postal_code",
        "postcode",
        "state",
        "status",
        "type",
        "updated_at",
    }

    def __init__(
        self,
        api_base_url: str = settings.loystar_api_base_url,
        api_v1_base_url: str = settings.loystar_api_v1_base_url,
        timeout_seconds: float = settings.loystar_timeout_seconds,
        redact_pii: bool = settings.loystar_redact_pii,
    ):
        self.api_base_url = api_base_url.rstrip("/")
        self.api_v1_base_url = api_v1_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.redact_pii = redact_pii

    def is_configured(self) -> bool:
        """Return True when the merchant Loystar session headers are configured."""
        credentials = current_loystar_credentials.get()
        if credentials:
            return True

        if not settings.allow_environment_credentials:
            return False

        return all(
            [
                settings.loystar_access_token,
                settings.loystar_client,
                settings.loystar_uid,
                settings.loystar_expiry,
            ]
        )

    def auth_status(self) -> Dict[str, Any]:
        """Expose non-sensitive configuration status for local debugging."""
        request_credentials = current_loystar_credentials.get()
        has_request_credentials = request_credentials is not None
        credentials = request_credentials
        if credentials is None and settings.allow_environment_credentials:
            credentials = LoystarCredentials(
                access_token=settings.loystar_access_token or "",
                client=settings.loystar_client or "",
                uid=settings.loystar_uid or "",
                expiry=settings.loystar_expiry or "",
                token_type=settings.loystar_token_type,
            )
        return {
            "configured": self.is_configured(),
            "credential_source": (
                "request_headers"
                if has_request_credentials
                else "environment"
                if settings.allow_environment_credentials
                else "not_configured"
            ),
            "api_base_url": self.api_base_url,
            "api_v1_base_url": self.api_v1_base_url,
            # Report the credentials active for this request. OAuth-backed MCP
            # calls intentionally do not populate the process environment.
            "has_access_token": bool(credentials and credentials.access_token),
            "has_client": bool(credentials and credentials.client),
            "has_uid": bool(credentials and credentials.uid),
            "has_expiry": bool(credentials and credentials.expiry),
            "credentials_expired": self._credentials_expired(credentials),
            "redact_pii": self.redact_pii,
        }

    @staticmethod
    def _credentials_expired(
        credentials: Optional[LoystarCredentials],
    ) -> Optional[bool]:
        """Return expiry state without exposing the upstream expiry value."""
        if not credentials or not credentials.expiry:
            return None
        value = credentials.expiry.strip()
        try:
            expires_at = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            try:
                expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return expires_at <= datetime.now(timezone.utc)

    def _headers(self) -> Dict[str, str]:
        credentials = current_loystar_credentials.get()
        if credentials:
            return {
                "access-token": credentials.access_token,
                "token-type": credentials.token_type,
                "client": credentials.client,
                "uid": credentials.uid,
                "expiry": credentials.expiry,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

        if not settings.allow_environment_credentials or not self.is_configured():
            raise LoystarAPIError(
                "A merchant-scoped Loystar connection is required."
            )

        return {
            "access-token": settings.loystar_access_token or "",
            "token-type": settings.loystar_token_type,
            "client": settings.loystar_client or "",
            "uid": settings.loystar_uid or "",
            "expiry": settings.loystar_expiry or "",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def sign_in(self, email: str, password: str) -> Dict[str, Any]:
        """
        Sign in a Loystar merchant and extract session headers.

        This is intended for local/live demos and connector token exchange. The
        password is never stored by this server.
        """
        if not email or not password:
            raise LoystarAPIError("email and password are required")

        url = f"{self.api_base_url}/api/v2/auth/sign_in"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                url,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={"email": email, "password": password},
            )

        try:
            payload = response.json()
        except ValueError:
            payload = {"raw": response.text}

        if response.status_code >= 400:
            raise LoystarAPIError(
                f"Loystar sign-in failed: {response.status_code} {response.reason_phrase}"
            )

        credentials = {
            "access_token": response.headers.get("access-token"),
            "client": response.headers.get("client"),
            "uid": response.headers.get("uid"),
            "expiry": response.headers.get("expiry"),
            "token_type": response.headers.get("token-type", "Bearer"),
        }
        missing = [key for key, value in credentials.items() if key != "token_type" and not value]
        if missing:
            raise LoystarAPIError(
                "Loystar sign-in succeeded, but required session headers were missing: "
                + ", ".join(missing)
            )

        return {
            "source": "loystar_api",
            "url": url,
            "credentials": credentials,
            "merchant": self._redact(payload),
        }

    async def _request(
        self,
        method: str,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        url = f"{base_url}{path}"
        urls = [url]
        primary_url = f"{self.api_base_url}{path}"
        if method.upper() == "GET" and base_url.rstrip("/") == self.api_v1_base_url:
            if primary_url != url:
                urls.append(primary_url)

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for index, candidate_url in enumerate(urls):
                try:
                    response = await client.request(
                        method,
                        candidate_url,
                        headers=self._headers(),
                        params=self._clean(params),
                        json=json_body,
                    )
                except httpx.RequestError as exc:
                    if index + 1 < len(urls):
                        continue
                    raise LoystarAPIError(
                        "Loystar API request failed: upstream connection error "
                        f"({type(exc).__name__})"
                    ) from exc
                url = candidate_url
                if response.status_code < 500:
                    break

        try:
            payload = response.json()
        except ValueError:
            payload = {"raw": response.text}

        if response.status_code >= 400:
            detail = self._safe_error_detail(payload)
            request_id = next(
                (
                    response.headers.get(name)
                    for name in ("x-request-id", "request-id", "x-correlation-id")
                    if response.headers.get(name)
                ),
                None,
            )
            parts = [
                f"Loystar API request failed: {response.status_code} {response.reason_phrase}"
            ]
            if request_id:
                parts.append(f"request_id={request_id[:128]}")
            if detail:
                parts.append(f"detail={detail}")
            raise LoystarAPIError("; ".join(parts))

        return {
            "source": "loystar_api",
            "method": method,
            "url": url,
            "params": self._clean(params),
            "data": (
                payload
                if (
                    not self.redact_pii
                    or (include_pii and settings.allow_request_pii_override)
                )
                else self._redact(payload)
            ),
        }

    @staticmethod
    def _clean(values: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in (values or {}).items()
            if value is not None and value != ""
        }

    def _safe_error_detail(self, payload: Any) -> Optional[str]:
        """Extract a short, redacted upstream error without leaking response data."""
        if not isinstance(payload, dict):
            return None
        selected = {
            key: payload[key]
            for key in ("error", "errors", "message", "detail")
            if key in payload
        }
        if not selected:
            return None
        return json.dumps(self._redact(selected), ensure_ascii=False)[:500]

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._redact_field(key, item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    def _redact_field(self, key: str, value: Any) -> Any:
        lowered = key.lower().replace("-", "_")
        if any(
            secret_name in lowered
            for secret_name in ("access_token", "refresh_token", "password", "secret")
        ):
            return "[redacted]"
        if ("email" in lowered or lowered == "uid") and isinstance(value, str):
            return self._mask_email(value)
        if any(name in lowered for name in ("phone", "mobile")) and isinstance(value, str):
            return self._mask_phone(value)
        if lowered in {
            "customer_name",
            "first_name",
            "last_name",
            "full_name",
            "firstname",
            "lastname",
            "fullname",
        } and isinstance(value, str):
            return f"{value[:1]}***" if value else "***"
        if any(
            name in lowered
            for name in (
                "street_address",
                "home_address",
                "customer_address",
                "date_of_birth",
                "birth_date",
                "birthday",
                "postal_code",
                "national_id",
            )
        ):
            return "[redacted]"
        return self._redact(value)

    def _minimize_business_branches(self, value: Any) -> Any:
        """Keep branch facts while dropping nested staff and account metadata."""
        if isinstance(value, list):
            return [self._minimize_business_branches(item) for item in value]
        if not isinstance(value, dict):
            return value
        return {
            key: self._minimize_business_branches(item)
            for key, item in value.items()
            if key.lower().replace("-", "_") in self._BRANCH_RESPONSE_FIELDS
        }

    @staticmethod
    def _mask_email(email: str) -> str:
        if "@" not in email:
            return "***"
        name, domain = email.split("@", 1)
        prefix = name[:2] if len(name) > 2 else name[:1]
        return f"{prefix}***@{domain}"

    @staticmethod
    def _mask_phone(phone: str) -> str:
        digits = re.sub(r"\D", "", phone)
        if len(digits) <= 4:
            return "***"
        return f"***{digits[-4:]}"

    async def get_customers(
        self,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/customers_list",
            params={"page[number]": page_number, "page[size]": page_size},
            include_pii=include_pii,
        )

    async def search_customers(
        self,
        query: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/merchant/search_customers",
            params={"query": query, "from": from_date, "to": to_date},
            include_pii=include_pii,
        )

    async def get_sales(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/sales_list",
            params={
                "from": from_date,
                "to": to_date,
                "page[number]": page_number,
                "page[size]": page_size,
            },
            include_pii=include_pii,
        )

    async def get_orders(
        self,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/orders_list",
            params={"page[number]": page_number, "page[size]": page_size},
            include_pii=include_pii,
        )

    async def get_products(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/get_latest_merchant_products",
            params={"time_stamp": time_stamp},
            include_pii=include_pii,
        )

    async def get_product_categories(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/get_latest_merchant_product_categories_get_version",
            params={"time_stamp": time_stamp},
            include_pii=include_pii,
        )

    async def get_loyalty_programs(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/get_merchant_loyalty_programs_get_version",
            params={"time_stamp": time_stamp},
            include_pii=include_pii,
        )

    async def get_business_branches(self, include_pii: bool = False) -> Dict[str, Any]:
        result = await self._request(
            "GET",
            self.api_base_url,
            "/api/v2/business_branches",
            include_pii=include_pii,
        )
        result["data"] = self._minimize_business_branches(result["data"])
        return result

    async def get_invoices(
        self,
        status: Optional[str] = None,
        query: Optional[str] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_base_url,
            "/api/v2/invoices",
            params={"status": status, "query": query},
            include_pii=include_pii,
        )

    async def get_sms_balance(self) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_v1_base_url,
            "/api/v2/get_merchant_sms_balance",
        )

    async def get_current_subscription(self) -> Dict[str, Any]:
        return await self._request(
            "GET",
            self.api_base_url,
            "/api/v2/get_merchant_current_subscription",
        )
