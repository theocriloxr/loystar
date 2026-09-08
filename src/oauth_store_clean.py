"""Clean OAuth 2.1 state and persistence for the production MCP entrypoint.

Unlike the legacy path, this implementation has no import-time monkeypatching.
Authorization-client validation and token-endpoint client authentication are
separate operations, DCR writes are verified after commit, PKCE is enforced,
and tokens/codes remain merchant- and resource-bound.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.config import settings
from src.loystar_client import LoystarCredentials

SUPPORTED_SCOPES = {"loystar.read", "offline_access"}
SUPPORTED_GRANTS = {"authorization_code", "refresh_token"}
SUPPORTED_TOKEN_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}
_PKCE_VALUE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def validate_redirect_uri(uri: str) -> None:
    if not uri or len(uri) > 512 or "*" in uri:
        raise ValueError("redirect_uri is invalid")
    parsed = urlparse(uri)
    if parsed.fragment or parsed.username or parsed.password:
        raise ValueError("redirect_uri cannot contain fragments or user information")
    is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise ValueError("redirect_uri must use HTTPS or an HTTP loopback address")
    if not parsed.hostname:
        raise ValueError("redirect_uri must include a host")


def normalize_scope(scope: str) -> str:
    values = {value for value in scope.split() if value}
    if "loystar.read" not in values:
        raise ValueError("scope must include loystar.read")
    if not values.issubset(SUPPORTED_SCOPES):
        raise ValueError("unsupported OAuth scope")
    return " ".join(sorted(values))


def _validate_pkce_challenge(challenge: str, method: str) -> None:
    if method != "S256":
        raise ValueError("PKCE code_challenge_method must be S256")
    if not _PKCE_VALUE.fullmatch(challenge or ""):
        raise ValueError("PKCE code_challenge is invalid")


def _verify_pkce(challenge: str, verifier: Optional[str]) -> bool:
    if not verifier or not _PKCE_VALUE.fullmatch(verifier):
        return False
    try:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
    except UnicodeEncodeError:
        return False
    computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return secrets.compare_digest(computed, challenge)


@dataclass(frozen=True)
class RegisteredClient:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str = "none"
    client_secret_hash: Optional[str] = None
    source: str = "registered"


@dataclass
class PendingAuthorization:
    credentials: LoystarCredentials
    redirect_uri: str
    client_id: str
    code_challenge: str
    expires_at: datetime
    scope: str
    resource: str


@dataclass
class OAuthSession:
    access_token: str
    credentials: LoystarCredentials
    merchant_uid: str
    expires_at: datetime
    scope: str
    client_id: str
    resource: str
    refresh_token: Optional[str] = None
    refresh_expires_at: Optional[datetime] = None


class OAuthStore:
    def __init__(
        self,
        code_ttl_seconds: int = 300,
        token_ttl_seconds: int = 3600,
        refresh_token_ttl_seconds: int = 2_592_000,
        use_database: bool = False,
    ) -> None:
        self.code_ttl = timedelta(seconds=code_ttl_seconds)
        self.token_ttl = timedelta(seconds=token_ttl_seconds)
        self.refresh_token_ttl = timedelta(seconds=refresh_token_ttl_seconds)
        self.use_database = use_database
        self._clients: Dict[str, RegisteredClient] = {}
        self._codes: Dict[str, PendingAuthorization] = {}
        self._tokens: Dict[str, OAuthSession] = {}
        self._refresh_tokens: Dict[str, OAuthSession] = {}
        self._db_initialized = False

    async def initialize(self) -> None:
        if not self.use_database:
            return
        from src.database import init_db

        await init_db()
        self._db_initialized = True

    async def _ensure_db(self) -> None:
        if self.use_database and not self._db_initialized:
            await self.initialize()

    @staticmethod
    def _serialize_credentials(credentials: LoystarCredentials) -> str:
        return json.dumps(
            {
                "access_token": credentials.access_token,
                "client": credentials.client,
                "uid": credentials.uid,
                "expiry": credentials.expiry,
                "token_type": credentials.token_type,
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _deserialize_credentials(value: str) -> LoystarCredentials:
        payload = json.loads(value)
        required = {"access_token", "client", "uid", "expiry"}
        if not isinstance(payload, dict) or not required.issubset(payload):
            raise ValueError("stored Loystar credentials are incomplete")
        return LoystarCredentials(
            access_token=str(payload["access_token"]),
            client=str(payload["client"]),
            uid=str(payload["uid"]),
            expiry=str(payload["expiry"]),
            token_type=str(payload.get("token_type") or "Bearer"),
        )

    def _encrypt_credentials(self, credentials: LoystarCredentials) -> str:
        from src.encryption import encrypt_credentials

        return encrypt_credentials(self._serialize_credentials(credentials))

    def _decrypt_credentials(self, encrypted: str) -> LoystarCredentials:
        from src.encryption import decrypt_credentials

        return self._deserialize_credentials(decrypt_credentials(encrypted))

    async def register_client(
        self,
        *,
        client_name: str,
        redirect_uris: list[str],
        grant_types: Optional[list[str]] = None,
        response_types: Optional[list[str]] = None,
        token_endpoint_auth_method: str = "none",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> dict[str, Any]:
        if not client_name or len(client_name) > 255:
            raise ValueError("client_name is required and must be at most 255 characters")
        if not redirect_uris or len(redirect_uris) > 10:
            raise ValueError("one to ten redirect_uris are required")
        normalized_redirects = list(dict.fromkeys(str(uri) for uri in redirect_uris))
        for uri in normalized_redirects:
            validate_redirect_uri(uri)

        grants = list(dict.fromkeys(grant_types or ["authorization_code", "refresh_token"]))
        responses = list(dict.fromkeys(response_types or ["code"]))
        if not grants or not set(grants).issubset(SUPPORTED_GRANTS):
            raise ValueError("unsupported grant type")
        if set(responses) != {"code"}:
            raise ValueError("only response_type=code is supported")
        if token_endpoint_auth_method not in SUPPORTED_TOKEN_AUTH_METHODS:
            raise ValueError("unsupported token endpoint authentication method")

        generated_secret = False
        if token_endpoint_auth_method != "none" and not client_secret:
            client_secret = secrets.token_urlsafe(48)
            generated_secret = True

        final_client_id = client_id or f"loy_client_{secrets.token_urlsafe(24)}"
        if not final_client_id or len(final_client_id) > 512:
            raise ValueError("client_id is invalid")

        registered = RegisteredClient(
            client_id=final_client_id,
            client_name=client_name,
            redirect_uris=normalized_redirects,
            grant_types=grants,
            response_types=["code"],
            token_endpoint_auth_method=token_endpoint_auth_method,
            client_secret_hash=_hash_secret(client_secret) if client_secret else None,
        )

        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import OAuthClient

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthClient).where(OAuthClient.client_id == final_client_id)
                )
                row = result.scalar_one_or_none()
                if row is None:
                    row = OAuthClient(client_id=final_client_id)
                    db.add(row)
                row.client_name = registered.client_name
                row.redirect_uris = registered.redirect_uris
                row.grant_types = registered.grant_types
                row.response_types = registered.response_types
                row.token_endpoint_auth_method = registered.token_endpoint_auth_method
                row.client_secret_hash = registered.client_secret_hash
                await db.flush()

            # Do not return 201 until a fresh transaction can read the client.
            persisted = await self.get_client(final_client_id, allow_cimd=False)
            if persisted is None:
                raise RuntimeError("OAuth client registration did not persist")
        else:
            self._clients[final_client_id] = registered

        response: dict[str, Any] = {
            "client_id": final_client_id,
            "client_id_issued_at": int(_now().timestamp()),
            "client_name": client_name,
            "redirect_uris": normalized_redirects,
            "grant_types": grants,
            "response_types": ["code"],
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }
        if client_secret and (generated_secret or token_endpoint_auth_method != "none"):
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = 0
        return response

    async def register_static_clients(self, clients: list[dict[str, Any]]) -> None:
        for item in clients:
            await self.register_client(
                client_id=str(item["client_id"]),
                client_name=str(item.get("client_name") or item["client_id"]),
                redirect_uris=[str(uri) for uri in item["redirect_uris"]],
                grant_types=item.get("grant_types"),
                response_types=item.get("response_types"),
                token_endpoint_auth_method=str(item.get("token_endpoint_auth_method", "none")),
                client_secret=item.get("client_secret"),
            )

    @staticmethod
    def _row_to_client(row: Any) -> RegisteredClient:
        return RegisteredClient(
            client_id=row.client_id,
            client_name=row.client_name,
            redirect_uris=list(row.redirect_uris or []),
            grant_types=list(row.grant_types or []),
            response_types=list(row.response_types or []),
            token_endpoint_auth_method=row.token_endpoint_auth_method or "none",
            client_secret_hash=row.client_secret_hash,
            source="registered",
        )

    async def get_client(
        self,
        client_id: str,
        *,
        allow_cimd: bool = True,
    ) -> Optional[RegisteredClient]:
        registered: Optional[RegisteredClient] = None
        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import OAuthClient

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthClient).where(OAuthClient.client_id == client_id)
                )
                row = result.scalar_one_or_none()
                if row is not None:
                    registered = self._row_to_client(row)
        else:
            registered = self._clients.get(client_id)

        if registered is not None or not allow_cimd or not settings.oauth_enable_cimd:
            return registered

        from src.oauth_cimd_clean import resolve_cimd_client

        metadata = await resolve_cimd_client(client_id)
        if metadata is None:
            return None
        return RegisteredClient(source="cimd", **metadata)

    async def validate_client(
        self,
        client_id: str,
        redirect_uri: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> RegisteredClient:
        """Validate client identity/redirect for the authorization endpoint.

        ``client_secret`` is accepted for interface compatibility but is never
        required here. Confidential clients authenticate only at token-like
        endpoints.
        """
        client = await self.get_client(client_id)
        if client is None:
            raise ValueError("unknown OAuth client")
        if redirect_uri is not None and redirect_uri not in client.redirect_uris:
            raise ValueError("redirect_uri is not registered for this client")
        return client

    async def authenticate_token_client(
        self,
        client_id: str,
        client_secret: Optional[str],
        *,
        auth_method_used: Optional[str] = None,
        required_grant: Optional[str] = None,
    ) -> RegisteredClient:
        client = await self.get_client(client_id)
        if client is None:
            raise ValueError("client authentication failed")
        if required_grant and required_grant not in client.grant_types:
            raise ValueError("client is not registered for this grant")

        configured_method = client.token_endpoint_auth_method or "none"
        if configured_method == "none":
            if auth_method_used not in {None, "none"} or client_secret:
                raise ValueError("public client must not use a client secret")
            return client

        if configured_method not in {"client_secret_post", "client_secret_basic"}:
            raise ValueError("unsupported token endpoint authentication method")
        if auth_method_used and auth_method_used != configured_method:
            raise ValueError("client authentication method mismatch")
        if not client_secret or not client.client_secret_hash:
            raise ValueError("client authentication failed")
        if not secrets.compare_digest(_hash_secret(client_secret), client.client_secret_hash):
            raise ValueError("client authentication failed")
        return client

    async def create_code(
        self,
        *,
        credentials: LoystarCredentials,
        redirect_uri: str,
        client_id: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
        resource: str,
    ) -> str:
        await self._prune()
        await self.validate_client(client_id, redirect_uri)
        _validate_pkce_challenge(code_challenge, code_challenge_method)
        normalized_scope = normalize_scope(scope)

        code = f"loy_code_{secrets.token_urlsafe(32)}"
        pending = PendingAuthorization(
            credentials=credentials,
            redirect_uri=redirect_uri,
            client_id=client_id,
            code_challenge=code_challenge,
            expires_at=_now() + self.code_ttl,
            scope=normalized_scope,
            resource=resource,
        )
        code_hash = _hash_secret(code)

        if self.use_database:
            await self._ensure_db()
            from src.database import get_db_context
            from src.models import OAuthAuthorizationCode

            async with get_db_context() as db:
                db.add(
                    OAuthAuthorizationCode(
                        code_hash=code_hash,
                        encrypted_credentials=self._encrypt_credentials(credentials),
                        redirect_uri=redirect_uri,
                        client_id=client_id,
                        code_challenge=code_challenge,
                        code_challenge_method="S256",
                        scope=normalized_scope,
                        resource=resource,
                        expires_at=pending.expires_at,
                    )
                )
                await db.flush()
        else:
            self._codes[code_hash] = pending
        return code

    def _new_session(
        self,
        credentials: LoystarCredentials,
        client_id: str,
        resource: str,
        scope: str,
    ) -> OAuthSession:
        include_refresh = "offline_access" in scope.split()
        return OAuthSession(
            access_token=f"loy_at_{secrets.token_urlsafe(40)}",
            refresh_token=f"loy_rt_{secrets.token_urlsafe(48)}" if include_refresh else None,
            credentials=credentials,
            merchant_uid=credentials.uid,
            expires_at=_now() + self.token_ttl,
            refresh_expires_at=_now() + self.refresh_token_ttl if include_refresh else None,
            scope=scope,
            client_id=client_id,
            resource=resource,
        )

    @staticmethod
    def _add_db_session(db: Any, session: OAuthSession, encrypted_credentials: str) -> None:
        from src.models import OAuthAccessToken

        db.add(
            OAuthAccessToken(
                access_token_hash=_hash_secret(session.access_token),
                refresh_token_hash=_hash_secret(session.refresh_token) if session.refresh_token else None,
                encrypted_credentials=encrypted_credentials,
                merchant_uid=session.merchant_uid,
                client_id=session.client_id,
                resource=session.resource,
                scope=session.scope,
                expires_at=session.expires_at,
                refresh_expires_at=session.refresh_expires_at,
            )
        )

    def _store_memory_session(self, session: OAuthSession) -> None:
        self._tokens[_hash_secret(session.access_token)] = session
        if session.refresh_token:
            self._refresh_tokens[_hash_secret(session.refresh_token)] = session

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str,
        code_verifier: Optional[str],
        resource: str,
        client_secret: Optional[str] = None,
        auth_method_used: Optional[str] = None,
    ) -> OAuthSession:
        await self._prune()
        await self.authenticate_token_client(
            client_id,
            client_secret,
            auth_method_used=auth_method_used,
            required_grant="authorization_code",
        )
        code_hash = _hash_secret(code)

        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import delete, select
            from src.database import get_db_context
            from src.models import OAuthAuthorizationCode

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthAuthorizationCode)
                    .where(
                        OAuthAuthorizationCode.code_hash == code_hash,
                        OAuthAuthorizationCode.expires_at > _now(),
                    )
                    .with_for_update()
                )
                pending = result.scalar_one_or_none()
                if pending is None:
                    raise ValueError("invalid or expired authorization code")
                if pending.redirect_uri != redirect_uri or pending.client_id != client_id:
                    raise ValueError("authorization code binding failed")
                if pending.resource != resource:
                    raise ValueError("resource does not match authorization request")
                if not _verify_pkce(pending.code_challenge, code_verifier):
                    raise ValueError("PKCE verification failed")

                credentials = self._decrypt_credentials(pending.encrypted_credentials)
                session = self._new_session(credentials, client_id, resource, pending.scope)
                await db.execute(
                    delete(OAuthAuthorizationCode).where(OAuthAuthorizationCode.id == pending.id)
                )
                self._add_db_session(db, session, pending.encrypted_credentials)
                await db.flush()
                return session

        pending = self._codes.get(code_hash)
        if pending is None or pending.expires_at <= _now():
            raise ValueError("invalid or expired authorization code")
        if pending.redirect_uri != redirect_uri or pending.client_id != client_id:
            raise ValueError("authorization code binding failed")
        if pending.resource != resource:
            raise ValueError("resource does not match authorization request")
        if not _verify_pkce(pending.code_challenge, code_verifier):
            raise ValueError("PKCE verification failed")
        self._codes.pop(code_hash, None)
        session = self._new_session(pending.credentials, client_id, resource, pending.scope)
        self._store_memory_session(session)
        return session

    async def refresh(
        self,
        *,
        refresh_token: str,
        client_id: str,
        resource: str,
        client_secret: Optional[str] = None,
        auth_method_used: Optional[str] = None,
    ) -> OAuthSession:
        await self.authenticate_token_client(
            client_id,
            client_secret,
            auth_method_used=auth_method_used,
            required_grant="refresh_token",
        )
        refresh_hash = _hash_secret(refresh_token)

        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import OAuthAccessToken

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthAccessToken)
                    .where(
                        OAuthAccessToken.refresh_token_hash == refresh_hash,
                        OAuthAccessToken.refresh_expires_at > _now(),
                        OAuthAccessToken.revoked_at.is_(None),
                    )
                    .with_for_update()
                )
                row = result.scalar_one_or_none()
                if row is None:
                    raise ValueError("invalid or expired refresh token")
                if row.client_id != client_id or row.resource != resource:
                    raise ValueError("refresh token binding failed")

                credentials = self._decrypt_credentials(row.encrypted_credentials)
                row.revoked_at = _now()
                session = self._new_session(credentials, client_id, resource, row.scope)
                self._add_db_session(db, session, row.encrypted_credentials)
                await db.flush()
                return session

        old = self._refresh_tokens.get(refresh_hash)
        if old is None or not old.refresh_expires_at or old.refresh_expires_at <= _now():
            raise ValueError("invalid or expired refresh token")
        if old.client_id != client_id or old.resource != resource:
            raise ValueError("refresh token binding failed")
        self._refresh_tokens.pop(refresh_hash, None)
        self._tokens.pop(_hash_secret(old.access_token), None)
        session = self._new_session(old.credentials, client_id, resource, old.scope)
        self._store_memory_session(session)
        return session

    async def resolve_token(
        self,
        token: str,
        expected_resource: Optional[str] = None,
    ) -> Optional[OAuthSession]:
        await self._prune()
        token_hash = _hash_secret(token)

        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import OAuthAccessToken

            conditions = [
                OAuthAccessToken.access_token_hash == token_hash,
                OAuthAccessToken.expires_at > _now(),
                OAuthAccessToken.revoked_at.is_(None),
            ]
            if expected_resource:
                conditions.append(OAuthAccessToken.resource == expected_resource)
            async with get_db_context() as db:
                result = await db.execute(select(OAuthAccessToken).where(*conditions))
                row = result.scalar_one_or_none()
                if row is None:
                    return None
                return OAuthSession(
                    access_token=token,
                    refresh_token=None,
                    credentials=self._decrypt_credentials(row.encrypted_credentials),
                    merchant_uid=row.merchant_uid,
                    expires_at=row.expires_at,
                    refresh_expires_at=row.refresh_expires_at,
                    scope=row.scope,
                    client_id=row.client_id,
                    resource=row.resource,
                )

        session = self._tokens.get(token_hash)
        if session is None or session.expires_at <= _now():
            return None
        if expected_resource and session.resource != expected_resource:
            return None
        return session

    async def revoke_token(
        self,
        *,
        token: str,
        client_id: str,
        client_secret: Optional[str] = None,
        auth_method_used: Optional[str] = None,
    ) -> None:
        await self.authenticate_token_client(
            client_id,
            client_secret,
            auth_method_used=auth_method_used,
        )
        token_hash = _hash_secret(token)

        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import or_, select
            from src.database import get_db_context
            from src.models import OAuthAccessToken

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthAccessToken).where(
                        or_(
                            OAuthAccessToken.access_token_hash == token_hash,
                            OAuthAccessToken.refresh_token_hash == token_hash,
                        ),
                        OAuthAccessToken.client_id == client_id,
                    )
                )
                row = result.scalar_one_or_none()
                if row is not None:
                    row.revoked_at = _now()
            return

        session = self._tokens.get(token_hash) or self._refresh_tokens.get(token_hash)
        if session and session.client_id == client_id:
            self._tokens.pop(_hash_secret(session.access_token), None)
            if session.refresh_token:
                self._refresh_tokens.pop(_hash_secret(session.refresh_token), None)

    async def _prune(self) -> None:
        now = _now()
        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import and_, delete, or_
            from src.database import get_db_context
            from src.models import OAuthAccessToken, OAuthAuthorizationCode

            async with get_db_context() as db:
                await db.execute(
                    delete(OAuthAuthorizationCode).where(OAuthAuthorizationCode.expires_at <= now)
                )
                await db.execute(
                    delete(OAuthAccessToken).where(
                        or_(
                            OAuthAccessToken.refresh_expires_at <= now,
                            and_(
                                OAuthAccessToken.refresh_expires_at.is_(None),
                                OAuthAccessToken.expires_at <= now,
                            ),
                        )
                    )
                )
            return

        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._tokens = {k: v for k, v in self._tokens.items() if v.expires_at > now}
        self._refresh_tokens = {
            k: v
            for k, v in self._refresh_tokens.items()
            if v.refresh_expires_at and v.refresh_expires_at > now
        }
