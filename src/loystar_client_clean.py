"""Resilient Loystar API client for the clean MCP production entrypoint.

This consolidates the useful fixes from ``fix/production-mcp-oauth`` without
changing the legacy client used by the old entrypoint.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from src.config import settings
from src.loystar_client import (
    LoystarAPIError,
    LoystarClient,
    LoystarCredentials,
    current_loystar_credentials,
)


class ResilientLoystarClient(LoystarClient):
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

    def auth_status(self) -> Dict[str, Any]:
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
            "has_access_token": bool(credentials and credentials.access_token),
            "has_client": bool(credentials and credentials.client),
            "has_uid": bool(credentials and credentials.uid),
            "has_expiry": bool(credentials and credentials.expiry),
            "credentials_expired": self._credentials_expired(credentials),
            "redact_pii": self.redact_pii,
        }

    @staticmethod
    def _credentials_expired(credentials: Optional[LoystarCredentials]) -> Optional[bool]:
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

    async def _request(
        self,
        method: str,
        base_url: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        primary = f"{base_url}{path}"
        urls = [primary]
        fallback = f"{self.api_base_url}{path}"
        if method.upper() == "GET" and base_url.rstrip("/") == self.api_v1_base_url:
            if fallback != primary:
                urls.append(fallback)

        response: Optional[httpx.Response] = None
        resolved_url = primary
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for index, candidate in enumerate(urls):
                try:
                    response = await client.request(
                        method,
                        candidate,
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
                resolved_url = candidate
                if response.status_code < 500:
                    break

        if response is None:
            raise LoystarAPIError("Loystar API request failed: no upstream response")

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
            "url": resolved_url,
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

    def _safe_error_detail(self, payload: Any) -> Optional[str]:
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

    def _minimize_business_branches(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._minimize_business_branches(item) for item in value]
        if not isinstance(value, dict):
            return value
        return {
            key: self._minimize_business_branches(item)
            for key, item in value.items()
            if key.lower().replace("-", "_") in self._BRANCH_RESPONSE_FIELDS
        }

    async def get_business_branches(self, include_pii: bool = False) -> Dict[str, Any]:
        result = await self._request(
            "GET",
            self.api_base_url,
            "/api/v2/business_branches",
            include_pii=include_pii,
        )
        result["data"] = self._minimize_business_branches(result["data"])
        return result
