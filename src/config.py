"""Configuration management for the Loystar MCP server."""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Runtime
    environment: str = Field(default="development", alias="ENVIRONMENT")
    server_host: str = Field(default="127.0.0.1", alias="MCP_SERVER_HOST")
    server_port: int = Field(default=8000, alias="MCP_SERVER_PORT")
    server_base_url: str = Field(default="http://localhost:8000", alias="MCP_SERVER_BASE_URL")
    allowed_hosts_csv: str = Field(
        default="localhost,127.0.0.1,testserver", alias="ALLOWED_HOSTS"
    )
    allowed_origins_csv: str = Field(
        default="http://localhost:8000,http://127.0.0.1:8000",
        alias="ALLOWED_ORIGINS",
    )
    max_request_body_bytes: int = Field(default=1_048_576, alias="MAX_REQUEST_BODY_BYTES")
    trust_proxy_headers: bool = Field(default=True, alias="TRUST_PROXY_HEADERS")
    enable_demo_routes: bool = Field(default=True, alias="ENABLE_DEMO_ROUTES")
    enable_legacy_routes: bool = Field(default=True, alias="ENABLE_LEGACY_ROUTES")
    enable_prototype_routes: bool = Field(default=True, alias="ENABLE_PROTOTYPE_ROUTES")
    enable_prototype_tools: bool = Field(default=True, alias="ENABLE_PROTOTYPE_TOOLS")
    enable_billing_routes: bool = Field(default=True, alias="ENABLE_BILLING_ROUTES")

    # Durable infrastructure
    database_url: Optional[str] = Field(default=None, alias="DATABASE_URL")
    redis_url: Optional[str] = Field(default=None, alias="REDIS_URL")
    oauth_encryption_key: Optional[str] = Field(default=None, alias="OAUTH_ENCRYPTION_KEY")

    # Loystar API
    loystar_api_base_url: str = Field(
        default="https://api.loystar.co", alias="LOYSTAR_API_BASE_URL"
    )
    loystar_api_v1_base_url: str = Field(
        default="https://api1.loystar.co", alias="LOYSTAR_API_V1_BASE_URL"
    )
    loystar_access_token: Optional[str] = Field(default=None, alias="LOYSTAR_ACCESS_TOKEN")
    loystar_token_type: str = Field(default="Bearer", alias="LOYSTAR_TOKEN_TYPE")
    loystar_client: Optional[str] = Field(default=None, alias="LOYSTAR_CLIENT")
    loystar_uid: Optional[str] = Field(default=None, alias="LOYSTAR_UID")
    loystar_expiry: Optional[str] = Field(default=None, alias="LOYSTAR_EXPIRY")
    loystar_timeout_seconds: float = Field(default=20.0, alias="LOYSTAR_TIMEOUT_SECONDS")
    loystar_redact_pii: bool = Field(default=True, alias="LOYSTAR_REDACT_PII")
    allow_request_pii_override: bool = Field(default=False, alias="ALLOW_REQUEST_PII_OVERRIDE")
    allow_environment_credentials: bool = Field(
        default=True, alias="ALLOW_ENVIRONMENT_CREDENTIALS"
    )

    # OAuth 2.1 / MCP authorization
    oauth_issuer: Optional[str] = Field(default=None, alias="OAUTH_ISSUER")
    oauth_code_ttl_seconds: int = Field(default=300, alias="OAUTH_CODE_TTL_SECONDS")
    oauth_token_ttl_seconds: int = Field(default=900, alias="OAUTH_TOKEN_TTL_SECONDS")
    oauth_refresh_token_ttl_seconds: int = Field(
        default=2_592_000, alias="OAUTH_REFRESH_TOKEN_TTL_SECONDS"
    )
    oauth_static_clients_json: str = Field(default="[]", alias="OAUTH_STATIC_CLIENTS_JSON")
    oauth_allow_dynamic_registration: bool = Field(
        default=True, alias="OAUTH_ALLOW_DYNAMIC_REGISTRATION"
    )
    oauth_dcr_initial_access_token: Optional[str] = Field(
        default=None, alias="OAUTH_DCR_INITIAL_ACCESS_TOKEN"
    )

    # Connector/admin controls
    connector_api_key: Optional[str] = Field(default=None, alias="CONNECTOR_API_KEY")
    require_connector_auth: bool = Field(default=False, alias="REQUIRE_CONNECTOR_AUTH")
    admin_api_key: Optional[str] = Field(default=None, alias="ADMIN_API_KEY")
    rate_limit_requests: int = Field(default=60, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")
    oauth_rate_limit_requests: int = Field(default=20, alias="OAUTH_RATE_LIMIT_REQUESTS")
    audit_log_max_events: int = Field(default=500, alias="AUDIT_LOG_MAX_EVENTS")

    # Billing / integrations
    stripe_secret_key: Optional[str] = Field(default=None, alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: Optional[str] = Field(default=None, alias="STRIPE_WEBHOOK_SECRET")
    stripe_price_id_free: Optional[str] = Field(default=None, alias="STRIPE_PRICE_ID_FREE")
    stripe_price_id_pro: Optional[str] = Field(default=None, alias="STRIPE_PRICE_ID_PRO")
    stripe_price_id_enterprise: Optional[str] = Field(
        default=None, alias="STRIPE_PRICE_ID_ENTERPRISE"
    )
    paystack_secret_key: Optional[str] = Field(default=None, alias="PAYSTACK_SECRET_KEY")
    twilio_account_sid: Optional[str] = Field(default=None, alias="TWILIO_ACCOUNT_SID")
    twilio_auth_token: Optional[str] = Field(default=None, alias="TWILIO_AUTH_TOKEN")
    twilio_phone_number: Optional[str] = Field(default=None, alias="TWILIO_PHONE_NUMBER")
    sendgrid_api_key: Optional[str] = Field(default=None, alias="SENDGRID_API_KEY")

    # HITL prototype
    hitl_approval_webhook_url: str = Field(
        default="http://localhost:8000/api/v1/hitl/approve",
        alias="HITL_APPROVAL_WEBHOOK_URL",
    )
    hitl_auto_approve_threshold: float = Field(
        default=100.0, alias="HITL_AUTO_APPROVE_THRESHOLD"
    )
    hitl_campaign_size_threshold: int = Field(
        default=50, alias="HITL_CAMPAIGN_SIZE_THRESHOLD"
    )

    # Reserved AI/vector configuration
    pinecone_api_key: Optional[str] = Field(default=None, alias="PINECONE_API_KEY")
    pinecone_environment: str = Field(default="us-west1", alias="PINECONE_ENVIRONMENT")
    pinecone_index_name: str = Field(
        default="loystar_memories", alias="PINECONE_INDEX_NAME"
    )
    ai_provider: str = Field(default="", alias="AI_PROVIDER")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_embedding_model: str = Field(
        default="text-embedding-3-small", alias="OPENAI_EMBEDDING_MODEL"
    )
    openai_chat_model: str = Field(default="gpt-4o-mini", alias="OPENAI_CHAT_MODEL")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_chat_model: str = Field(
        default="claude-sonnet-4-20250514", alias="ANTHROPIC_CHAT_MODEL"
    )

    # Legacy JWT settings retained for compatibility; OAuth uses opaque tokens.
    jwt_secret_key: str = Field(default="change_this_secret_key", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=60, alias="JWT_EXPIRATION_MINUTES")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    @property
    def allowed_hosts(self) -> list[str]:
        return [value.strip() for value in self.allowed_hosts_csv.split(",") if value.strip()]

    @property
    def allowed_origins(self) -> list[str]:
        return [
            value.strip().rstrip("/")
            for value in self.allowed_origins_csv.split(",")
            if value.strip()
        ]

    @property
    def oauth_static_clients(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.oauth_static_clients_json)
        except json.JSONDecodeError as exc:
            raise ValueError("OAUTH_STATIC_CLIENTS_JSON must be valid JSON") from exc
        if not isinstance(value, list):
            raise ValueError("OAUTH_STATIC_CLIENTS_JSON must contain a JSON array")
        return value

    @property
    def canonical_mcp_resource(self) -> str:
        return f"{self.server_base_url.rstrip('/')}/mcp"

    def validate_for_startup(self) -> None:
        """Fail closed when a production deployment is missing required controls."""
        errors: list[str] = []

        if self.rate_limit_requests < 1 or self.rate_limit_window_seconds < 1:
            errors.append("rate-limit values must be positive")
        if self.oauth_code_ttl_seconds < 60:
            errors.append("OAUTH_CODE_TTL_SECONDS must be at least 60")
        if self.oauth_token_ttl_seconds < 60:
            errors.append("OAUTH_TOKEN_TTL_SECONDS must be at least 60")
        if self.oauth_refresh_token_ttl_seconds <= self.oauth_token_ttl_seconds:
            errors.append("refresh-token TTL must be longer than access-token TTL")
        if self.max_request_body_bytes < 1024:
            errors.append("MAX_REQUEST_BODY_BYTES must be at least 1024")

        for name, url in (
            ("LOYSTAR_API_BASE_URL", self.loystar_api_base_url),
            ("LOYSTAR_API_V1_BASE_URL", self.loystar_api_v1_base_url),
        ):
            if urlparse(url).scheme != "https" and self.is_production:
                errors.append(f"{name} must use HTTPS in production")

        if self.is_production:
            parsed_base_url = urlparse(self.server_base_url)
            if parsed_base_url.scheme != "https":
                errors.append("MCP_SERVER_BASE_URL must use HTTPS in production")
            if not parsed_base_url.hostname or parsed_base_url.path not in {"", "/"}:
                errors.append("MCP_SERVER_BASE_URL must be an HTTPS origin without a path")
            if self.oauth_issuer and urlparse(self.oauth_issuer).scheme != "https":
                errors.append("OAUTH_ISSUER must use HTTPS in production")
            if not self.database_url:
                errors.append("DATABASE_URL is required in production")
            elif not self.database_url.startswith(
                ("postgresql+asyncpg://", "postgresql://", "postgres://")
            ):
                errors.append("DATABASE_URL must be a PostgreSQL connection URL")
            if not self.redis_url:
                errors.append("REDIS_URL is required in production")
            elif not self.redis_url.startswith(("redis://", "rediss://")):
                errors.append("REDIS_URL must use redis:// or rediss://")
            if not self.oauth_encryption_key or len(self.oauth_encryption_key) < 32:
                errors.append("OAUTH_ENCRYPTION_KEY must contain at least 32 characters")
            if not self.admin_api_key or len(self.admin_api_key) < 32:
                errors.append("ADMIN_API_KEY must contain at least 32 characters")
            if "*" in self.allowed_hosts or not self.allowed_hosts:
                errors.append("ALLOWED_HOSTS must be an explicit non-empty allowlist")
            if "*" in self.allowed_origins:
                errors.append("ALLOWED_ORIGINS cannot contain '*' in production")
            if self.enable_demo_routes:
                errors.append("ENABLE_DEMO_ROUTES must be false in production")
            if self.enable_legacy_routes:
                errors.append("ENABLE_LEGACY_ROUTES must be false in production")
            if self.enable_prototype_routes:
                errors.append("ENABLE_PROTOTYPE_ROUTES must be false in production")
            if self.enable_prototype_tools:
                errors.append("ENABLE_PROTOTYPE_TOOLS must be false in production")
            if self.enable_billing_routes:
                errors.append("ENABLE_BILLING_ROUTES must be false in production")
            if self.allow_environment_credentials:
                errors.append("ALLOW_ENVIRONMENT_CREDENTIALS must be false in production")
            if any(
                [
                    self.loystar_access_token,
                    self.loystar_client,
                    self.loystar_uid,
                    self.loystar_expiry,
                ]
            ):
                errors.append("single-merchant LOYSTAR_* session credentials are forbidden")
            if self.require_connector_auth and (
                not self.connector_api_key or len(self.connector_api_key) < 32
            ):
                errors.append("CONNECTOR_API_KEY must contain at least 32 characters")
            if (
                not self.oauth_allow_dynamic_registration
                and not self.oauth_static_clients
            ):
                errors.append(
                    "configure OAUTH_STATIC_CLIENTS_JSON or enable dynamic registration"
                )

        # Parse and validate static-client configuration even in development.
        for client in self.oauth_static_clients:
            if not isinstance(client, dict):
                errors.append("each static OAuth client must be an object")
                continue
            if not client.get("client_id") or not client.get("redirect_uris"):
                errors.append("each static OAuth client needs client_id and redirect_uris")

        if errors:
            raise RuntimeError("Invalid server configuration: " + "; ".join(errors))


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
