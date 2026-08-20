"""OAuth 2.1 state for remote MCP clients.

Production mode uses PostgreSQL and fails closed. Development mode may use the
in-memory backend for tests and local demos.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.loystar_client import LoystarCredentials

SUPPORTED_SCOPES = {"loystar.read", "offline_access"}


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def validate_redirect_uri(uri: str) -> None:
    """Reject wildcard, fragment, credential, and insecure redirect URIs."""
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


@dataclass(frozen=True)
class RegisteredClient:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str = "none"
    client_secret_hash: Optional[str] = None


@dataclass
class PendingAuthorization:
    credentials: LoystarCredentials
    redirect_uri: str
    client_id: str
    code_challenge: str
    expires_at: datetime
    scope: str
    resource: str
    code_challenge_method: str = "S256"


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
    """Registered clients, authorization codes, and rotating token pairs."""

    def __init__(
        self,
        code_ttl_seconds: int = 300,
        token_ttl_seconds: int = 900,
        refresh_token_ttl_seconds: int = 2_592_000,
        use_database: bool = False,
    ):
        self.code_ttl = timedelta(seconds=code_ttl_seconds)
        self.token_ttl = timedelta(seconds=token_ttl_seconds)
        self.refresh_token_ttl = timedelta(seconds=refresh_token_ttl_seconds)
        self.use_database = use_database
        self._codes: Dict[str, PendingAuthorization] = {}
        self._tokens: Dict[str, OAuthSession] = {}
        self._refresh_tokens: Dict[str, OAuthSession] = {}
        self._clients: Dict[str, RegisteredClient] = {}
        self._db_initialized = False

    async def initialize(self) -> None:
        if not self.use_database:
            return
        from src.database import init_db

        await init_db()
        self._db_initialized = True

    async def _ensure_db(self) -> None:
        if not self.use_database:
            return
        if not self._db_initialized:
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
        data = json.loads(value)
        required = {"access_token", "client", "uid", "expiry"}
        if not required.issubset(data):
            raise ValueError("stored Loystar credentials are incomplete")
        return LoystarCredentials(
            access_token=data["access_token"],
            client=data["client"],
            uid=data["uid"],
            expiry=data["expiry"],
            token_type=data.get("token_type", "Bearer"),
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
        for uri in redirect_uris:
            validate_redirect_uri(uri)

        grants = grant_types or ["authorization_code", "refresh_token"]
        responses = response_types or ["code"]
        if not set(grants).issubset({"authorization_code", "refresh_token"}):
            raise ValueError("unsupported grant type")
        if responses != ["code"] and set(responses) != {"code"}:
            raise ValueError("only response_type=code is supported")
        if token_endpoint_auth_method not in {"none", "client_secret_post", "client_secret_basic"}:
            raise ValueError("unsupported token endpoint authentication method")
        if token_endpoint_auth_method in {"client_secret_post", "client_secret_basic"} and not client_secret:
            client_secret = secrets.token_urlsafe(48)

        final_client_id = client_id or f"loy_client_{secrets.token_urlsafe(24)}"
        secret_hash = _hash_secret(client_secret) if client_secret else None
        client = RegisteredClient(
            client_id=final_client_id,
            client_name=client_name,
            redirect_uris=list(dict.fromkeys(redirect_uris)),
            grant_types=grants,
            response_types=responses,
            token_endpoint_auth_method=token_endpoint_auth_method,
            client_secret_hash=secret_hash,
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
                record = result.scalar_one_or_none()
                if record:
                    record.client_name = client.client_name
                    record.redirect_uris = client.redirect_uris
                    record.grant_types = client.grant_types
                    record.response_types = client.response_types
                    record.token_endpoint_auth_method = client.token_endpoint_auth_method
                    record.client_secret_hash = client.client_secret_hash
                else:
                    db.add(
                        OAuthClient(
                            client_id=client.client_id,
                            client_secret_hash=client.client_secret_hash,
                            client_name=client.client_name,
                            redirect_uris=client.redirect_uris,
                            grant_types=client.grant_types,
                            response_types=client.response_types,
                            token_endpoint_auth_method=client.token_endpoint_auth_method,
                        )
                    )
        else:
            self._clients[final_client_id] = client

        response: dict[str, Any] = {
            "client_id": final_client_id,
            "client_id_issued_at": int(_now().timestamp()),
            "client_name": client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": grants,
            "response_types": responses,
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }
        if client_secret:
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = 0
        return response

    async def register_static_clients(self, clients: list[dict[str, Any]]) -> None:
        for client in clients:
            await self.register_client(
                client_id=str(client["client_id"]),
                client_name=str(client.get("client_name") or client["client_id"]),
                redirect_uris=[str(uri) for uri in client["redirect_uris"]],
                grant_types=client.get("grant_types"),
                response_types=client.get("response_types"),
                token_endpoint_auth_method=str(
                    client.get("token_endpoint_auth_method", "none")
                ),
                client_secret=client.get("client_secret"),
            )

    async def get_client(self, client_id: str) -> Optional[RegisteredClient]:
        if self.use_database:
            await self._ensure_db()
            from sqlalchemy import select
            from src.database import get_db_context
            from src.models import OAuthClient

            async with get_db_context() as db:
                result = await db.execute(
                    select(OAuthClient).where(OAuthClient.client_id == client_id)
                )
                record = result.scalar_one_or_none()
                if not record:
                    return None
                return RegisteredClient(
                    client_id=record.client_id,
                    client_name=record.client_name,
                    redirect_uris=list(record.redirect_uris or []),
                    grant_types=list(record.grant_types or []),
                    response_types=list(record.response_types or []),
                    token_endpoint_auth_method=record.token_endpoint_auth_method,
                    client_secret_hash=record.client_secret_hash,
                )
        return self._clients.get(client_id)

    async def validate_client(
        self,
        client_id: str,
        redirect_uri: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> RegisteredClient:
        client = await self.get_client(client_id)
        if not client:
            raise ValueError("unknown OAuth client")
        if redirect_uri is not None and redirect_uri not in client.redirect_uris:
            raise ValueError("redirect_uri is not registered for this client")
        if client.token_endpoint_auth_method in ("client_secret_post", "client_secret_basic"):
            if not client_secret or not client.client_secret_hash:
                raise ValueError("client authentication failed")
            if not secrets.compare_digest(
                _hash_secret(client_secret), client.client_secret_hash
            ):
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
        if code_challenge_method != "S256":
            raise ValueError("PKCE code_challenge_method must be S256")
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            raise ValueError("PKCE code_challenge is invalid")

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

        if self.use_database:
            await self._ensure_db()
            from src.database import get_db_context
            from src.models import OAuthAuthorizationCode

            encrypted = self._encrypt_credentials(credentials)
            async with get_db_context() as db:
                db.add(
                    OAuthAuthorizationCode(
                        code_hash=_hash_secret(code),
                        encrypted_credentials=encrypted,
                        redirect_uri=redirect_uri,
                        client_id=client_id,
                        code_challenge=code_challenge,
                        code_challenge_method="S256",
                        scope=normalized_scope,
                        resource=resource,
                        expires_at=pending.expires_at,
                    )
                )
        else:
            self._codes[_hash_secret(code)] = pending
        return code

    @staticmethod
    def _verify_pkce(challenge: str, verifier: Optional[str]) -> bool:
        if not verifier or len(verifier) < 43 or len(verifier) > 128:
            return False
        try:
            digest = hashlib.sha256(verifier.encode("ascii")).digest()
        except UnicodeEncodeError:
            return False
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return secrets.compare_digest(computed, challenge)

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
            refresh_token=(
                f"loy_rt_{secrets.token_urlsafe(48)}" if include_refresh else None
            ),
            credentials=credentials,
            merchant_uid=credentials.uid,
            expires_at=_now() + self.token_ttl,
            refresh_expires_at=(
                _now() + self.refresh_token_ttl if include_refresh else None
            ),
            scope=scope,
            client_id=client_id,
            resource=resource,
        )

    def _store_memory_session(self, session: OAuthSession) -> None:
        self._tokens[_hash_secret(session.access_token)] = session
        if session.refresh_token:
            self._refresh_tokens[_hash_secret(session.refresh_token)] = session

    def _add_db_session(self, db: Any, session: OAuthSession) -> None:
        from src.models import OAuthAccessToken

        db.add(
            OAuthAccessToken(
                access_token_hash=_hash_secret(session.access_token),
                refresh_token_hash=(
                    _hash_secret(session.refresh_token) if session.refresh_token else None
                ),
                encrypted_credentials=self._encrypt_credentials(session.credentials),
                merchant_uid=session.merchant_uid,
                client_id=session.client_id,
                resource=session.resource,
                scope=session.scope,
                expires_at=session.expires_at,
                refresh_expires_at=session.refresh_expires_at,
            )
        )

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str,
        code_verifier: Optional[str],
        resource: str,
        client_secret: Optional[str] = None,
    ) -> OAuthSession:
        await self._prune()
        await self.validate_client(client_id, redirect_uri, client_secret)
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
                if not pending:
                    raise ValueError("invalid or expired authorization code")
                if pending.redirect_uri != redirect_uri or pending.client_id != client_id:
                    raise ValueError("authorization code binding failed")
                if pending.resource != resource:
                    raise ValueError("resource does not match authorization request")
                if not self._verify_pkce(pending.code_challenge, code_verifier):
                    raise ValueError("PKCE verification failed")
                credentials = self._decrypt_credentials(pending.encrypted_credentials)
                await db.execute(
                    delete(OAuthAuthorizationCode).where(
                        OAuthAuthorizationCode.id == pending.id
                    )
                )
                session = self._new_session(
                    credentials, client_id, resource, pending.scope
                )
                self._add_db_session(db, session)
                return session

        pending = self._codes.pop(code_hash, None)
        if not pending or pending.expires_at <= _now():
            raise ValueError("invalid or expired authorization code")
        if pending.redirect_uri != redirect_uri or pending.client_id != client_id:
            raise ValueError("authorization code binding failed")
        if pending.resource != resource:
            raise ValueError("resource does not match authorization request")
        if not self._verify_pkce(pending.code_challenge, code_verifier):
            raise ValueError("PKCE verification failed")
        session = self._new_session(
            pending.credentials, client_id, resource, pending.scope
        )
        self._store_memory_session(session)
        return session

    async def refresh(
        self,
        *,
        refresh_token: str,
        client_id: str,
        resource: str,
        client_secret: Optional[str] = None,
    ) -> OAuthSession:
        await self.validate_client(client_id, client_secret=client_secret)
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
                record = result.scalar_one_or_none()
                if not record:
                    raise ValueError("invalid or expired refresh token")
                if record.client_id != client_id or record.resource != resource:
                    raise ValueError("refresh token binding failed")
                credentials = self._decrypt_credentials(record.encrypted_credentials)
                record.revoked_at = _now()
                session = self._new_session(
                    credentials, client_id, resource, record.scope
                )
                self._add_db_session(db, session)
                return session

        old_session = self._refresh_tokens.pop(refresh_hash, None)
        if (
            not old_session
            or not old_session.refresh_expires_at
            or old_session.refresh_expires_at <= _now()
        ):
            raise ValueError("invalid or expired refresh token")
        if old_session.client_id != client_id or old_session.resource != resource:
            raise ValueError("refresh token binding failed")
        self._tokens.pop(_hash_secret(old_session.access_token), None)
        session = self._new_session(
            old_session.credentials, client_id, resource, old_session.scope
        )
        self._store_memory_session(session)
        return session

    async def resolve_token(
        self, token: str, expected_resource: Optional[str] = None
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
                result = await db.execute(
                    select(OAuthAccessToken).where(*conditions)
                )
                record = result.scalar_one_or_none()
                if not record:
                    return None
                credentials = self._decrypt_credentials(record.encrypted_credentials)
                return OAuthSession(
                    access_token=token,
                    refresh_token=None,
                    credentials=credentials,
                    merchant_uid=record.merchant_uid,
                    expires_at=record.expires_at,
                    refresh_expires_at=record.refresh_expires_at,
                    scope=record.scope,
                    client_id=record.client_id,
                    resource=record.resource,
                )

        session = self._tokens.get(token_hash)
        if not session or session.expires_at <= _now():
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
    ) -> None:
        await self.validate_client(client_id, client_secret=client_secret)
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
                record = result.scalar_one_or_none()
                if record:
                    record.revoked_at = _now()
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
            from sqlalchemy import delete
            from src.database import get_db_context
            from src.models import OAuthAccessToken, OAuthAuthorizationCode

            async with get_db_context() as db:
                await db.execute(
                    delete(OAuthAuthorizationCode).where(
                        OAuthAuthorizationCode.expires_at <= now
                    )
                )
                await db.execute(
                    delete(OAuthAccessToken).where(
                        OAuthAccessToken.refresh_expires_at.is_not(None),
                        OAuthAccessToken.refresh_expires_at <= now,
                    )
                )
            return

        self._codes = {
            key: value for key, value in self._codes.items() if value.expires_at > now
        }
        self._tokens = {
            key: value for key, value in self._tokens.items() if value.expires_at > now
        }
        self._refresh_tokens = {
            key: value
            for key, value in self._refresh_tokens.items()
            if value.refresh_expires_at and value.refresh_expires_at > now
        }
