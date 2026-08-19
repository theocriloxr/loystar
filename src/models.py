"""
Database models for Loystar MCP Server
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text, ForeignKey, JSON, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import declarative_base, relationship
import uuid

Base = declarative_base()


class LoyaltyTier(str, Enum):
    """Customer loyalty tier enumeration"""
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"
    VIP = "vip"


class RiskLevel(str, Enum):
    """Risk level for HITL classification"""
    AUTONOMOUS = "autonomous"
    ESCALATED = "escalated"


class ApprovalStatus(str, Enum):
    """HITL approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Channel(str, Enum):
    """Communication channel enumeration"""
    SMS = "sms"
    WHATSAPP = "whatsapp"
    EMAIL = "email"


class Workspace(Base):
    """Multi-tenant workspace (merchant) model"""
    __tablename__ = "workspaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    api_key = Column(String(255), unique=True, nullable=False)
    jwt_secret = Column(String(255), nullable=False)
    
    # Financial constraints
    margin_threshold = Column(Float, default=0.1)  # 10% minimum margin
    max_discount_percent = Column(Integer, default=50)
    max_campaign_budget = Column(Float, default=10000.0)
    
    # HITL settings
    auto_approve_threshold = Column(Float, default=100.0)
    campaign_size_threshold = Column(Integer, default=50)
    
    # Integration settings
    stripe_customer_prefix = Column(String(50), default="loystar")
    paystack_merchant_code = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    customers = relationship("Customer", back_populates="workspace")
    campaigns = relationship("Campaign", back_populates="workspace")
    coupons = relationship("Coupon", back_populates="workspace")
    
    __table_args__ = (
        Index("idx_workspace_slug", "slug"),
        Index("idx_workspace_api_key", "api_key"),
    )


class Customer(Base):
    """Customer entity model"""
    __tablename__ = "customers"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Primary identity
    email = Column(String(255))
    phone = Column(String(50))
    name = Column(String(255))
    
    # External IDs
    loystar_customer_id = Column(String(100), unique=True, nullable=False)
    stripe_customer_id = Column(String(100))
    paystack_customer_id = Column(String(100))
    
    # Loyalty metrics
    loyalty_tier = Column(String(50), default=LoyaltyTier.BRONZE.value)
    points_balance = Column(Integer, default=0)
    lifetime_value_usd = Column(Float, default=0.0)
    
    # RFM metrics
    recency_days = Column(Integer, default=0)
    frequency_score = Column(Integer, default=0)
    monetary_score = Column(Float, default=0.0)
    
    # Risk assessment
    churn_risk_score = Column(Float, default=0.0)
    last_churn_check = Column(DateTime)
    
    # Tags and preferences
    lifestyle_tags = Column(ARRAY(String), default=[])
    communication_preferences = Column(JSON, default={})
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_transaction_at = Column(DateTime)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="customers")
    transactions = relationship("Transaction", back_populates="customer")
    messages = relationship("Message", back_populates="customer")
    coupons = relationship("CustomerCoupon", back_populates="customer")
    
    __table_args__ = (
        Index("idx_customer_workspace", "workspace_id"),
        Index("idx_customer_loystar_id", "loystar_customer_id"),
        Index("idx_customer_email", "email"),
        Index("idx_customer_phone", "phone"),
        Index("idx_customer_stripe_id", "stripe_customer_id"),
        Index("idx_customer_paystack_id", "paystack_customer_id"),
        Index("idx_customer_churn_risk", "churn_risk_score"),
    )


class Transaction(Base):
    """Transaction event model"""
    __tablename__ = "transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id = Column(UUID(as_uuid=True), ForeignKey("customers.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # External transaction data
    external_transaction_id = Column(String(255), unique=True)
    stripe_charge_id = Column(String(100))
    paystack_charge_id = Column(String(100))
    
    # Transaction details
    amount_usd = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    status = Column(String(50), nullable=False)
    
    # Metadata
    extra_data = Column(JSON, default={})
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    customer = relationship("Customer", back_populates="transactions")
    workspace = relationship("Workspace")
    
    __table_args__ = (
        Index("idx_transaction_customer", "customer_id"),
        Index("idx_transaction_workspace", "workspace_id"),
        Index("idx_transaction_external_id", "external_transaction_id"),
        Index("idx_transaction_created", "created_at"),
    )


class Campaign(Base):
    """Marketing campaign model"""
    __tablename__ = "campaigns"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Campaign details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    channel = Column(String(50), nullable=False)  # SMS, WHATSAPP, EMAIL, MULTI
    
    # Targeting
    target_tier = Column(String(50))
    target_size = Column(Integer, default=0)
    customer_selectionCriteria = Column(JSON)
    
    # Offer details
    discount_percent = Column(Integer)
    points_award = Column(Integer)
    coupon_code = Column(String(50))
    
    # Scheduling
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Status
    status = Column(String(50), default="draft")  # draft, scheduled, active, completed, cancelled
    is_automated = Column(Boolean, default=False)
    
    # HITL
    risk_level = Column(String(50), default=RiskLevel.AUTONOMOUS.value)
    approval_status = Column(String(50), default=ApprovalStatus.PENDING.value)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="campaigns")
    
    __table_args__ = (
        Index("idx_campaign_workspace", "workspace_id"),
        Index("idx_campaign_status", "status"),
        Index("idx_campaign_scheduled", "scheduled_at"),
    )


class Coupon(Base):
    """Coupon code model"""
    __tablename__ = "coupons"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Coupon details
    code = Column(String(50), unique=True, nullable=False)
    discount_percent = Column(Integer, nullable=False)
    max_uses = Column(Integer, default=1)
    current_uses = Column(Integer, default=0)
    
    # Expiration
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_by = Column(String(100))
    purpose = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="coupons")
    customer_coupons = relationship("CustomerCoupon", back_populates="coupon")
    
    __table_args__ = (
        Index("idx_coupon_workspace", "workspace_id"),
        Index("idx_coupon_code", "code"),
    )


class CustomerCoupon(Base):
    """Customer-coupon assignment model"""
    __tablename__ = "customer_coupons"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id = Column(UUID(as_uuid=True), ForeignKey("customers.id"), nullable=False)
    coupon_id = Column(UUID(as_uuid=True), ForeignKey("coupons.id"), nullable=False)
    
    # Status
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime)
    
    # Timestamps
    assigned_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    customer = relationship("Customer", back_populates="coupons")
    coupon = relationship("Coupon", back_populates="customer_coupons")
    
    __table_args__ = (
        Index("idx_customer_coupon_customer", "customer_id"),
        Index("idx_customer_coupon_coupon", "coupon_id"),
    )


class Message(Base):
    """Outbound message model"""
    __tablename__ = "messages"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id = Column(UUID(as_uuid=True), ForeignKey("customers.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Message details
    channel = Column(String(50), nullable=False)  # SMS, WHATSAPP, EMAIL
    message_type = Column(String(50), default="transactional")  # transactional, promotional, retention
    content = Column(Text, nullable=False)
    
    # Delivery status
    status = Column(String(50), default="pending")  # pending, sent, delivered, failed
    external_message_id = Column(String(255))
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime)
    delivered_at = Column(DateTime)
    
    # Relationships
    customer = relationship("Customer", back_populates="messages")
    workspace = relationship("Workspace")
    
    __table_args__ = (
        Index("idx_message_customer", "customer_id"),
        Index("idx_message_workspace", "workspace_id"),
        Index("idx_message_status", "status"),
    )


class HitlRequest(Base):
    """HITL approval request model"""
    __tablename__ = "hitl_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Request details
    action_type = Column(String(100), nullable=False)  # coupon_create, campaign_send, etc.
    action_data = Column(JSON, nullable=False)
    financial_exposure = Column(Float, default=0.0)
    target_count = Column(Integer, default=1)
    
    # Risk classification
    risk_level = Column(String(50), default=RiskLevel.ESCALATED.value)
    
    # Approval status
    status = Column(String(50), default=ApprovalStatus.PENDING.value)
    approved_by = Column(String(100))
    rejected_by = Column(String(100))
    approval_notes = Column(Text)
    
    # Webhook for interactive approval
    webhook_payload = Column(JSON)
    webhook_response = Column(JSON)
    
    # Expiration
    expires_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approved_at = Column(DateTime)
    rejected_at = Column(DateTime)
    
    # Relationships
    workspace = relationship("Workspace")
    
    __table_args__ = (
        Index("idx_hitl_workspace", "workspace_id"),
        Index("idx_hitl_status", "status"),
        Index("idx_hitl_created", "created_at"),
    )


class OAuthClient(Base):
    """Registered public or confidential OAuth client."""
    __tablename__ = "oauth_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(512), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(64), nullable=True)
    client_name = Column(String(255), nullable=False)
    redirect_uris = Column(JSON, nullable=False)
    grant_types = Column(
        JSON,
        nullable=False,
        default=lambda: ["authorization_code", "refresh_token"],
    )
    response_types = Column(JSON, nullable=False, default=lambda: ["code"])
    token_endpoint_auth_method = Column(String(50), nullable=False, default="none")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class OAuthAuthorizationCode(Base):
    """Persistent OAuth authorization code, replacing in-memory storage.

    Credentials are encrypted at rest using AES-256-GCM (see src/encryption.py)
    and stored as a single ``encrypted_credentials`` TEXT column.
    """
    __tablename__ = "oauth_authorization_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_hash = Column(String(64), unique=True, nullable=False, index=True)

    # Single encrypted blob: AES-256-GCM ciphertext of LoystarCredentials JSON
    encrypted_credentials = Column(Text, nullable=False)

    redirect_uri = Column(String(512), nullable=False)
    client_id = Column(String(512), nullable=False)
    code_challenge = Column(String(128), nullable=False)
    code_challenge_method = Column(String(16), nullable=False, default="S256")
    scope = Column(String(255), nullable=False, default="loystar.read")
    resource = Column(String(1024), nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_oauth_code_expires", "expires_at"),
    )


class OAuthAccessToken(Base):
    """Persistent OAuth access token, replacing in-memory storage.

    Credentials are encrypted at rest using AES-256-GCM.
    ``merchant_uid`` is stored in plaintext for indexing/auditing only.
    """
    __tablename__ = "oauth_access_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    access_token_hash = Column(String(64), unique=True, nullable=False, index=True)
    refresh_token_hash = Column(String(64), unique=True, nullable=True, index=True)

    # Single encrypted blob: AES-256-GCM ciphertext of LoystarCredentials JSON
    encrypted_credentials = Column(Text, nullable=False)

    # Clear-text merchant identifier for indexing and audit — NOT the full credentials
    merchant_uid = Column(String(255), nullable=False, index=True)

    client_id = Column(String(512), nullable=False, index=True)
    resource = Column(String(1024), nullable=False)
    scope = Column(String(255), nullable=False, default="loystar.read")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    refresh_expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_oauth_token_merchant", "merchant_uid"),
        Index("idx_oauth_token_expires", "expires_at"),
    )


class ConnectorAuditEvent(Base):
    """Durable audit event that never stores raw tokens or tool results."""
    __tablename__ = "connector_audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(String(96), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    client_ip = Column(String(64), nullable=False)
    path = Column(String(512), nullable=False)
    method = Column(String(16), nullable=False)
    tool_name = Column(String(255), nullable=True)
    merchant_uid = Column(String(255), nullable=True)
    credential_source = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, index=True)
    error_code = Column(String(100), nullable=True)


class MerchantSubscription(Base):
    """Self-serve merchant subscription for billing integration."""
    __tablename__ = "merchant_subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    merchant_email = Column(String(255), nullable=False, index=True)

    # Stripe
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    stripe_price_id = Column(String(255), nullable=True)

    # Plan
    plan_tier = Column(String(50), default="free")  # free, pro, enterprise
    status = Column(String(50), default="incomplete")  # incomplete, active, past_due, canceled

    # Loystar connection
    loystar_email = Column(String(255), nullable=True)
    loystar_connected = Column(Boolean, default=False)
    loystar_connected_at = Column(DateTime(timezone=True), nullable=True)

    # MCP server URL (generated after onboarding)
    mcp_server_url = Column(String(512), nullable=True)

    # Billing
    current_period_start = Column(DateTime(timezone=True), nullable=True)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)

    # Rate limits (tier-specific)
    rate_limit_requests = Column(Integer, default=60)
    max_merchants = Column(Integer, default=1)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_subscription_email", "merchant_email"),
        Index("idx_subscription_stripe", "stripe_customer_id"),
        Index("idx_subscription_status", "status"),
    )


class CustomerMemory(Base):
    """Long-term memory embedding for customers"""
    __tablename__ = "customer_memories"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id = Column(UUID(as_uuid=True), ForeignKey("customers.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    
    # Memory content
    memory_type = Column(String(100), nullable=False)  # support_ticket, complaint, preference, etc.
    content = Column(Text, nullable=False)
    
    # Embedding reference (stored in vector DB, this is a reference)
    vector_id = Column(String(255))
    
    # Metadata
    source = Column(String(100))  # support_ticket, whatsapp, email, etc.
    importance_score = Column(Float, default=0.5)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    customer = relationship("Customer")
    workspace = relationship("Workspace")
    
    __table_args__ = (
        Index("idx_memory_customer", "customer_id"),
        Index("idx_memory_workspace", "workspace_id"),
        Index("idx_memory_type", "memory_type"),
    )
