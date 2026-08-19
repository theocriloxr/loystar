"""Security controls shared by the OAuth and MCP HTTP surfaces."""
from __future__ import annotations

import hashlib
import secrets
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Optional
from uuid import uuid4

from fastapi import HTTPException, Request, status

from src.config import settings


def mask_identity(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if "@" in value:
        name, domain = value.split("@", 1)
        prefix = name[:2] if len(name) > 2 else name[:1]
        return f"{prefix}***@{domain}"
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-3:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    client_ip: str
    path: str
    method: str
    tool_name: Optional[str]
    merchant_uid: Optional[str]
    credential_source: str
    status: str
    error_code: Optional[str] = None


class AuditLog:
    """In-memory in development; PostgreSQL-backed in production."""

    def __init__(self, max_events: int, use_database: bool = False):
        self._events: Deque[AuditEvent] = deque(maxlen=max_events)
        self.max_events = max_events
        self.use_database = use_database

    async def record(
        self,
        request: Request,
        tool_name: Optional[str],
        status_value: str,
        error_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        merchant_uid = request.headers.get("x-loystar-uid")
        credential_source = "not_configured"
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            oauth_store = getattr(request.app.state, "oauth_store", None)
            if oauth_store:
                token = auth_header.split(" ", 1)[1].strip()
                session = await oauth_store.resolve_token(
                    token, expected_resource=settings.canonical_mcp_resource
                )
                if session:
                    merchant_uid = session.merchant_uid
                    credential_source = "oauth_bearer"

        if credential_source == "not_configured":
            if request.headers.get("x-loystar-access-token"):
                credential_source = "request_headers"
            elif settings.allow_environment_credentials and settings.loystar_access_token:
                merchant_uid = merchant_uid or settings.loystar_uid
                credential_source = "environment"

        event = AuditEvent(
            event_id=f"audit_{uuid4().hex}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=request.client.host if request.client else "unknown",
            path=request.url.path[:512],
            method=request.method[:16],
            tool_name=tool_name[:255] if tool_name else None,
            merchant_uid=mask_identity(merchant_uid),
            credential_source=credential_source,
            status=status_value[:50],
            error_code=error_code[:100] if error_code else None,
        )

        if self.use_database:
            from src.database import get_db_context
            from src.models import ConnectorAuditEvent

            async with get_db_context() as db:
                db.add(
                    ConnectorAuditEvent(
                        event_id=event.event_id,
                        timestamp=datetime.fromisoformat(event.timestamp),
                        client_ip=event.client_ip,
                        path=event.path,
                        method=event.method,
                        tool_name=event.tool_name,
                        merchant_uid=event.merchant_uid,
                        credential_source=event.credential_source,
                        status=event.status,
                        error_code=event.error_code,
                    )
                )
        else:
            self._events.appendleft(event)
        return asdict(event)

    async def list_events(self, limit: int = 50) -> Dict[str, Any]:
        safe_limit = max(1, min(limit, self.max_events))
        if self.use_database:
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import ConnectorAuditEvent

            async with get_db_context() as db:
                result = await db.execute(
                    select(ConnectorAuditEvent)
                    .order_by(ConnectorAuditEvent.timestamp.desc())
                    .limit(safe_limit)
                )
                records = result.scalars().all()
                events = [
                    {
                        "event_id": record.event_id,
                        "timestamp": record.timestamp.isoformat(),
                        "client_ip": record.client_ip,
                        "path": record.path,
                        "method": record.method,
                        "tool_name": record.tool_name,
                        "merchant_uid": record.merchant_uid,
                        "credential_source": record.credential_source,
                        "status": record.status,
                        "error_code": record.error_code,
                    }
                    for record in records
                ]
        else:
            events = [asdict(event) for event in list(self._events)[:safe_limit]]
        return {"events": events, "count": len(events), "max_events": self.max_events}


class RateLimiter:
    """Atomic Redis limiter in production; fixed-window memory limiter locally."""

    _REDIS_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        redis_url: Optional[str] = None,
        namespace: str = "mcp",
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.window = timedelta(seconds=window_seconds)
        self.redis_url = redis_url
        self.namespace = namespace
        self._buckets: Dict[str, Deque[datetime]] = {}
        self._redis: Any = None

    async def initialize(self) -> None:
        if not self.redis_url:
            return
        import redis.asyncio as redis

        self._redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        await self._redis.ping()

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()

    async def healthcheck(self) -> None:
        if self.redis_url:
            if self._redis is None:
                raise RuntimeError("Redis rate limiter has not been initialized")
            await self._redis.ping()

    async def check(self, key: str) -> None:
        safe_key = f"loystar:{self.namespace}:{_fingerprint(key)}"
        if self.redis_url:
            if self._redis is None:
                raise RuntimeError("Redis rate limiter has not been initialized")
            current = await self._redis.eval(
                self._REDIS_SCRIPT, 1, safe_key, self.window_seconds
            )
            if int(current) > self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded.",
                    headers={"Retry-After": str(self.window_seconds)},
                )
            return

        now = datetime.now(timezone.utc)
        bucket = self._buckets.setdefault(safe_key, deque())
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded.",
                headers={"Retry-After": str(self.window_seconds)},
            )
        bucket.append(now)


def verify_connector_auth(request: Request) -> None:
    if not settings.require_connector_auth:
        return
    expected = settings.connector_api_key
    provided = request.headers.get("x-connector-api-key")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Connector authentication is not configured.",
        )
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing connector API key.",
        )


def verify_admin_auth(request: Request) -> None:
    expected = settings.admin_api_key
    provided = request.headers.get("x-admin-api-key")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found.",
        )
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin credentials.",
        )


def rate_limit_key(request: Request) -> str:
    client_ip = request.client.host if request.client else "unknown"
    authorization = request.headers.get("authorization", "")
    merchant_uid = request.headers.get("x-loystar-uid")
    identity = merchant_uid or authorization or request.headers.get("user-agent", "anonymous")
    return f"{client_ip}:{identity}"
