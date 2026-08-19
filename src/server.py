"""
MCP Server Implementation for Loystar Customer Loyalty Manager AI Agent

This module implements the Model Context Protocol (MCP) server that exposes
resources and tools for the AI agent to interact with customer loyalty data.
"""
import json
import uuid
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from src.config import settings
from src.hitl import RiskTieringEngine, create_approval_request
from src.loystar_client import LoystarClient

# MCP Protocol Messages
@dataclass
class MCPMessage:
    """Base MCP message"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None


@dataclass
class MCPRequest(MCPMessage):
    """MCP request message"""
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse(MCPMessage):
    """MCP response message"""
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


@dataclass 
class MCPError:
    """MCP error object"""
    code: int
    message: str
    data: Optional[Any] = None


# MCP Error Codes
class MCPErrorCode(Enum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


# Resource Types
@dataclass
class Resource:
    """MCP Resource definition"""
    uri: str
    name: str
    description: str
    mime_type: str = "application/json"


@dataclass
class ResourceTemplate:
    """MCP Resource URI template"""
    uri_template: str
    name: str
    description: str
    mime_type: str = "application/json"


# Tool Types
@dataclass
class Tool:
    """MCP Tool definition"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    annotations: Optional[Dict[str, bool]] = None


# Tool Parameters Schema
class ToolInputSchema:
    """Helper class for creating tool input schemas"""
    
    @staticmethod
    def string(required: bool = True, description: str = "") -> Dict[str, Any]:
        return {
            "type": "string",
            "description": description
        }
    
    @staticmethod
    def integer(required: bool = True, description: str = "") -> Dict[str, Any]:
        return {
            "type": "integer", 
            "description": description
        }
    
    @staticmethod
    def number(required: bool = True, description: str = "") -> Dict[str, Any]:
        return {
            "type": "number",
            "description": description
        }
    
    @staticmethod
    def boolean(required: bool = True, description: str = "") -> Dict[str, Any]:
        return {
            "type": "boolean",
            "description": description
        }
    
    @staticmethod
    def object(properties: Dict[str, Any], required: List[str] = None) -> Dict[str, Any]:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        }


# Loyalty Tools Implementation
class LoyaltyTools:
    """Core loyalty management tools"""
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.loystar = LoystarClient()
        self.risk_engine = RiskTieringEngine(
            auto_approve_threshold=settings.hitl_auto_approve_threshold,
            campaign_size_threshold=settings.hitl_campaign_size_threshold,
        )

    def loystar_auth_status(self) -> Dict[str, Any]:
        """Return non-sensitive Loystar API configuration status."""
        return self.loystar.auth_status()

    async def loystar_get_customers(
        self,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's Loystar customers."""
        return await self.loystar.get_customers(page_number, page_size, include_pii)

    async def loystar_search_customers(
        self,
        query: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Search the authenticated merchant's Loystar customers."""
        return await self.loystar.search_customers(query, from_date, to_date, include_pii)

    async def loystar_get_sales(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's Loystar sales."""
        return await self.loystar.get_sales(from_date, to_date, page_number, page_size, include_pii)

    async def loystar_get_orders(
        self,
        page_number: int = 1,
        page_size: int = 30,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's Loystar orders."""
        return await self.loystar.get_orders(page_number, page_size, include_pii)

    async def loystar_get_products(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's Loystar products."""
        return await self.loystar.get_products(time_stamp, include_pii)

    async def loystar_get_product_categories(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's product categories."""
        return await self.loystar.get_product_categories(time_stamp, include_pii)

    async def loystar_get_loyalty_programs(
        self,
        time_stamp: int = 0,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's loyalty programs."""
        return await self.loystar.get_loyalty_programs(time_stamp, include_pii)

    async def loystar_get_business_branches(self, include_pii: bool = False) -> Dict[str, Any]:
        """Query the authenticated merchant's business branches."""
        return await self.loystar.get_business_branches(include_pii)

    async def loystar_get_invoices(
        self,
        status: Optional[str] = None,
        query: Optional[str] = None,
        include_pii: bool = False,
    ) -> Dict[str, Any]:
        """Query the authenticated merchant's invoices."""
        return await self.loystar.get_invoices(status, query, include_pii)

    async def loystar_get_sms_balance(self) -> Dict[str, Any]:
        """Query the authenticated merchant's SMS balance."""
        return await self.loystar.get_sms_balance()

    async def loystar_get_current_subscription(self) -> Dict[str, Any]:
        """Query the authenticated merchant's current subscription."""
        return await self.loystar.get_current_subscription()
    
    async def calculate_churn_risk(
        self, 
        customer_id: str
    ) -> Dict[str, Any]:
        """
        Analyzes multi-channel transaction velocities and calculates 
        0.0-1.0 churn risk probability scores.
        
        Args:
            customer_id: The unique customer identifier
            
        Returns:
            Dictionary with churn_risk_score (float), confidence (float), 
            factors (list), and recommended_actions (list)
        """
        if not customer_id:
            raise ValueError("customer_id is required")

        # This is a simplified implementation
        # In production, this would query the database for:
        # - Transaction frequency over last 30/60/90 days
        # - Average order value trends
        # - Customer support ticket frequency
        # - Email/SMS engagement metrics
        # - Loyalty tier changes
        
        return {
            "customer_id": customer_id,
            "churn_risk_score": 0.0,  # 0.0 = low risk, 1.0 = high risk
            "confidence": 0.85,
            "analysis_period_days": 30,
            "factors": [
                {
                    "name": "transaction_frequency",
                    "impact": "negative",
                    "severity": 0.3,
                    "description": "Order frequency dropped 35% over 30 days"
                }
            ],
            "recommended_actions": [
                {
                    "action": "send_retention_offer",
                    "priority": "high",
                    "estimated_effectiveness": 0.72
                }
            ],
            "model_version": "v1.0.0",
            "calculated_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def generate_custom_coupon(
        self,
        customer_id: str,
        discount_percent: int,
        expiry_hours: int = 24,
        workspace_id: str = "default",
        estimated_order_value: float = 100.0,
        max_uses: int = 1,
        target_count: int = 1
    ) -> Dict[str, Any]:
        """
        Dynamically provisions unique coupon codes within Stripe or Paystack.
        
        Args:
            customer_id: The unique customer identifier
            discount_percent: Discount percentage (1-100)
            expiry_hours: Hours until coupon expires
            
        Returns:
            Dictionary with coupon_code, discount_percent, expires_at, 
            and redemption details
        """
        if not customer_id:
            raise ValueError("customer_id is required")
        if discount_percent < 1 or discount_percent > 100:
            raise ValueError("discount_percent must be between 1 and 100")
        if expiry_hours < 1 or expiry_hours > 168:
            raise ValueError("expiry_hours must be between 1 and 168")
        if max_uses < 1:
            raise ValueError("max_uses must be at least 1")

        action_data = {
            "customer_id": customer_id,
            "discount_percent": discount_percent,
            "expiry_hours": expiry_hours,
            "estimated_order_value": estimated_order_value,
            "max_uses": max_uses,
            "target_count": target_count,
        }
        financial_exposure = self.risk_engine.calculate_financial_exposure(
            "coupon_create",
            action_data,
        )
        risk = await self.risk_engine.assess_risk(
            "coupon_create",
            financial_exposure=financial_exposure,
            target_count=target_count,
        )
        if risk.requires_approval:
            approval = create_approval_request(
                workspace_id=workspace_id,
                action_type="coupon_create",
                action_data=action_data,
                risk_assessment=risk,
            )
            return {
                "status": "pending_merchant_approval",
                "request_id": approval.request_id,
                "customer_id": customer_id,
                "risk_level": risk.risk_level.value,
                "financial_exposure": financial_exposure,
                "target_count": target_count,
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
            }

        # Generate unique coupon code only after deterministic guardrails pass.
        coupon_code = f"LOY{customer_id[:8].upper()}{uuid.uuid4().hex[:6].upper()}"
        
        # Calculate expiry
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        
        return {
            "coupon_code": coupon_code,
            "status": "created",
            "customer_id": customer_id,
            "discount_percent": discount_percent,
            "min_purchase_amount": 0.0,
            "max_uses": max_uses,
            "current_uses": 0,
            "expires_at": expires_at.isoformat(),
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "applicable_tiers": ["bronze", "silver", "gold", "platinum", "vip"],
            "channel": "all"
        }
    
    async def dispatch_omnichannel_message(
        self,
        customer_id: str,
        channel: str,
        message_body: str
    ) -> Dict[str, Any]:
        """
        Routes branded outbound messages through Twilio, Sendgrid, or WhatsApp.
        
        Args:
            customer_id: The unique customer identifier
            channel: Communication channel (SMS, WHATSAPP, EMAIL)
            message_body: Message content
            
        Returns:
            Dictionary with message_id, status, channel, and delivery details
        """
        # Validate channel
        valid_channels = ["SMS", "WHATSAPP", "EMAIL"]
        if not customer_id:
            raise ValueError("customer_id is required")
        if not channel:
            raise ValueError("channel is required")
        if not message_body:
            raise ValueError("message_body is required")
        if channel.upper() not in valid_channels:
            raise ValueError(f"Invalid channel. Must be one of: {valid_channels}")
        
        # Generate message ID
        message_id = f"msg_{uuid.uuid4().hex}"
        
        return {
            "message_id": message_id,
            "customer_id": customer_id,
            "channel": channel.upper(),
            "status": "queued",
            "message_body": message_body,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sent_at": None,
            "delivered_at": None,
            "error": None
        }

    async def get_customer_profile(self, customer_id: str) -> Dict[str, Any]:
        """Return a customer profile through the same shape as the resource."""
        if not customer_id:
            raise ValueError("customer_id is required")

        return {
            "customer_id": customer_id,
            "loyalty_tier": "gold",
            "points_balance": 1250,
            "lifetime_value_usd": 2450.00,
            "recency_days": 4,
            "frequency_score": "VIP_HIGH",
            "lifestyle_tags": ["frequent_shopper", "electronics"],
            "communication_preferences": {
                "sms": True,
                "email": True,
                "whatsapp": False
            }
        }

    async def update_loyalty_points(
        self,
        customer_id: str,
        points: int,
        reason: str = "agent_action"
    ) -> Dict[str, Any]:
        """Apply a loyalty point delta, guarded against invalid requests."""
        if not customer_id:
            raise ValueError("customer_id is required")
        if points is None:
            raise ValueError("points is required")
        if points == 0:
            raise ValueError("points must be non-zero")

        current_balance = 1250
        new_balance = max(0, current_balance + points)

        return {
            "customer_id": customer_id,
            "previous_points_balance": current_balance,
            "points_delta": points,
            "points_balance": new_balance,
            "reason": reason,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }


# MCP Server
class MCPServer:
    """
    Loystar MCP Server implementation following the Model Context Protocol.
    
    This server exposes:
    - Resources: Read-only data provision (customer profiles, campaigns)
    - Tools: Action execution (churn calculation, coupon generation, messaging)
    """
    
    def __init__(self, server_name: str = "Loystar MCP Server"):
        self.server_name = server_name
        self.version = "1.0.0"
        self.protocol_version = "2025-11-25"
        self.supported_protocol_versions = {
            "2025-11-25",
            "2025-06-18",
            "2025-03-26",
        }
        self.tools = LoyaltyTools()
        self._resources: List[Resource] = []
        self._tool_definitions: List[Tool] = []
        
        # Initialize resources and tools
        self._initialize_resources()
        self._initialize_tools()

        if not settings.allow_request_pii_override:
            for tool in self._tool_definitions:
                tool.input_schema.get("properties", {}).pop("include_pii", None)
    
    def _initialize_resources(self):
        """Initialize MCP resources"""
        if not settings.enable_prototype_tools:
            self._resources = []
            return
        self._resources = [
            Resource(
                uri="loystar://customers/{customer_id}/profile",
                name="customer_profile",
                description="Exposes real-time loyalty tier status, current point balances, lifestyle tags, and contextual interaction metadata"
            ),
            Resource(
                uri="loystar://merchants/{workspace_id}/campaigns/active",
                name="merchant_campaigns",
                description="Supplies the current active parameters of the business, financial margin constraints, and promotional rule-sets"
            ),
            Resource(
                uri="loystar://customers/{customer_id}/rfm",
                name="customer_rfm",
                description="Customer RFM (Recency, Frequency, Monetary) metrics for segmentation"
            ),
            Resource(
                uri="loystar://customers/{customer_id}/memories",
                name="customer_memories",
                description="Long-term memory embeddings and historical interaction data"
            )
        ]
    
    def _initialize_tools(self):
        """Initialize MCP tools"""
        self._tool_definitions = [
            Tool(
                name="loystar_auth_status",
                description="Shows whether Loystar merchant API credentials are configured without exposing secrets",
                input_schema=ToolInputSchema.object(properties={}, required=[])
            ),
            Tool(
                name="loystar_get_customers",
                description="Queries the authenticated merchant's Loystar customer list",
                input_schema=ToolInputSchema.object(
                    properties={
                        "page_number": ToolInputSchema.integer(required=False, description="Page number"),
                        "page_size": ToolInputSchema.integer(required=False, description="Page size"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_search_customers",
                description="Searches the authenticated merchant's Loystar customers by query/date range",
                input_schema=ToolInputSchema.object(
                    properties={
                        "query": ToolInputSchema.string(required=False, description="Search term"),
                        "from_date": ToolInputSchema.string(required=False, description="Start date in YYYY-MM-DD format"),
                        "to_date": ToolInputSchema.string(required=False, description="End date in YYYY-MM-DD format"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_sales",
                description="Queries the authenticated merchant's Loystar sales list",
                input_schema=ToolInputSchema.object(
                    properties={
                        "from_date": ToolInputSchema.string(required=False, description="Start date in YYYY-MM-DD format"),
                        "to_date": ToolInputSchema.string(required=False, description="End date in YYYY-MM-DD format"),
                        "page_number": ToolInputSchema.integer(required=False, description="Page number"),
                        "page_size": ToolInputSchema.integer(required=False, description="Page size"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_orders",
                description="Queries the authenticated merchant's Loystar orders list",
                input_schema=ToolInputSchema.object(
                    properties={
                        "page_number": ToolInputSchema.integer(required=False, description="Page number"),
                        "page_size": ToolInputSchema.integer(required=False, description="Page size"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_products",
                description="Queries the authenticated merchant's Loystar product catalog",
                input_schema=ToolInputSchema.object(
                    properties={
                        "time_stamp": ToolInputSchema.integer(required=False, description="Loystar sync timestamp, usually 0 for full/latest query"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_product_categories",
                description="Queries the authenticated merchant's Loystar product categories",
                input_schema=ToolInputSchema.object(
                    properties={
                        "time_stamp": ToolInputSchema.integer(required=False, description="Loystar sync timestamp, usually 0 for full/latest query"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_loyalty_programs",
                description="Queries the authenticated merchant's Loystar loyalty programs",
                input_schema=ToolInputSchema.object(
                    properties={
                        "time_stamp": ToolInputSchema.integer(required=False, description="Loystar sync timestamp, usually 0 for full/latest query"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_business_branches",
                description="Queries the authenticated merchant's Loystar business branches",
                input_schema=ToolInputSchema.object(
                    properties={
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_invoices",
                description="Queries the authenticated merchant's Loystar invoices",
                input_schema=ToolInputSchema.object(
                    properties={
                        "status": ToolInputSchema.string(required=False, description="Invoice status filter, for example unpaid"),
                        "query": ToolInputSchema.string(required=False, description="Invoice search term"),
                        "include_pii": ToolInputSchema.boolean(required=False, description="Return raw PII if merchant explicitly allows it")
                    },
                    required=[]
                )
            ),
            Tool(
                name="loystar_get_sms_balance",
                description="Queries the authenticated merchant's Loystar SMS balance",
                input_schema=ToolInputSchema.object(properties={}, required=[])
            ),
            Tool(
                name="loystar_get_current_subscription",
                description="Queries the authenticated merchant's current Loystar subscription",
                input_schema=ToolInputSchema.object(properties={}, required=[])
            ),
            Tool(
                name="calculate_churn_risk",
                description="Analyzes multi-channel transaction velocities and calculates 0.0-1.0 churn risk probability scores",
                input_schema=ToolInputSchema.object(
                    properties={
                        "customer_id": ToolInputSchema.string(
                            required=True,
                            description="The unique customer identifier"
                        )
                    },
                    required=["customer_id"]
                )
            ),
            Tool(
                name="generate_custom_coupon",
                description="Dynamically provisions unique coupon codes within Stripe or Paystack core infrastructure environments",
                input_schema=ToolInputSchema.object(
                    properties={
                        "customer_id": ToolInputSchema.string(
                            required=True,
                            description="The unique customer identifier"
                        ),
                        "discount_percent": ToolInputSchema.integer(
                            required=True,
                            description="Discount percentage (1-100)"
                        ),
                        "expiry_hours": ToolInputSchema.integer(
                            required=False,
                            description="Hours until coupon expires (default: 24)"
                        ),
                        "workspace_id": ToolInputSchema.string(
                            required=False,
                            description="Merchant workspace ID used for HITL isolation"
                        ),
                        "estimated_order_value": ToolInputSchema.number(
                            required=False,
                            description="Estimated order value used to calculate financial exposure"
                        ),
                        "max_uses": ToolInputSchema.integer(
                            required=False,
                            description="Maximum coupon redemptions"
                        ),
                        "target_count": ToolInputSchema.integer(
                            required=False,
                            description="Number of customers affected by the action"
                        )
                    },
                    required=["customer_id", "discount_percent"]
                )
            ),
            Tool(
                name="dispatch_omnichannel_message",
                description="Routes branded outbound retention copy directly through verified Twilio, Sendgrid, or WhatsApp Business APIs",
                input_schema=ToolInputSchema.object(
                    properties={
                        "customer_id": ToolInputSchema.string(
                            required=True,
                            description="The unique customer identifier"
                        ),
                        "channel": ToolInputSchema.string(
                            required=True,
                            description="Communication channel: SMS, WHATSAPP, or EMAIL"
                        ),
                        "message_body": ToolInputSchema.string(
                            required=True,
                            description="Message content"
                        )
                    },
                    required=["customer_id", "channel", "message_body"]
                )
            ),
            Tool(
                name="get_customer_profile",
                description="Retrieves comprehensive customer profile including tier, points, and lifetime value",
                input_schema=ToolInputSchema.object(
                    properties={
                        "customer_id": ToolInputSchema.string(
                            required=True,
                            description="The unique customer identifier"
                        )
                    },
                    required=["customer_id"]
                )
            ),
            Tool(
                name="update_loyalty_points",
                description="Updates customer loyalty points balance based on transaction",
                input_schema=ToolInputSchema.object(
                    properties={
                        "customer_id": ToolInputSchema.string(
                            required=True,
                            description="The unique customer identifier"
                        ),
                        "points": ToolInputSchema.integer(
                            required=True,
                            description="Points to add (positive) or deduct (negative)"
                        ),
                        "reason": ToolInputSchema.string(
                            required=False,
                            description="Reason for points change"
                        )
                    },
                    required=["customer_id", "points"]
                )
            )
        ]
        if not settings.enable_prototype_tools:
            live_tools = {
                "loystar_auth_status",
                "loystar_get_customers",
                "loystar_search_customers",
                "loystar_get_sales",
                "loystar_get_orders",
                "loystar_get_products",
                "loystar_get_product_categories",
                "loystar_get_loyalty_programs",
                "loystar_get_business_branches",
                "loystar_get_invoices",
                "loystar_get_sms_balance",
                "loystar_get_current_subscription",
            }
            self._tool_definitions = [
                tool for tool in self._tool_definitions if tool.name in live_tools
            ]

        for tool in self._tool_definitions:
            is_live_read = tool.name.startswith("loystar_")
            tool.annotations = {
                "readOnlyHint": is_live_read,
                "destructiveHint": not is_live_read,
                "idempotentHint": is_live_read,
                "openWorldHint": True,
            }
    
    async def handle_request(self, request: MCPRequest) -> MCPResponse:
        """
        Handle incoming MCP JSON-RPC 2.0 request
        
        Args:
            request: MCP request message
            
        Returns:
            MCP response message
        """
        try:
            method = request.method
            params = request.params
            
            # Route to appropriate handler
            if method == "initialize":
                requested_version = params.get("protocolVersion")
                selected_version = (
                    requested_version
                    if requested_version in self.supported_protocol_versions
                    else self.protocol_version
                )
                result = {
                    "protocolVersion": selected_version,
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.version,
                    },
                    "capabilities": {
                        "resources": {},
                        "tools": {},
                    },
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = self.list_tools()
            elif method == "tools/call":
                try:
                    structured = await self.call_tool(
                        params.get("name"), params.get("arguments", {})
                    )
                    result = {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    structured, ensure_ascii=False, separators=(",", ":")
                                ),
                            }
                        ],
                        "structuredContent": structured,
                        "isError": False,
                    }
                except (TypeError, ValueError) as exc:
                    result = {
                        "content": [{"type": "text", "text": str(exc)}],
                        "isError": True,
                    }
            elif method == "resources/list":
                result = self.list_resources()
            elif method == "resources/read":
                result = await self.read_resource(params.get("uri"))
            elif method == "notifications/initialized":
                result = {}
            else:
                return MCPResponse(
                    id=request.id,
                    error={
                        "code": MCPErrorCode.METHOD_NOT_FOUND.value,
                        "message": f"Method '{method}' not found"
                    }
                )
            
            return MCPResponse(id=request.id, result=result)
            
        except Exception:
            return MCPResponse(
                id=request.id,
                error={
                    "code": MCPErrorCode.INTERNAL_ERROR.value,
                    "message": "Internal server error."
                }
            )
    
    def list_tools(self) -> Dict[str, Any]:
        """List all available tools"""
        return {
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                    "annotations": tool.annotations,
                }
                for tool in self._tool_definitions
            ]
        }
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool by name with arguments
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Tool input arguments
            
        Returns:
            Tool execution result
        """
        if not tool_name:
            raise ValueError("Tool name is required")
        arguments = arguments or {}
        tool = next(
            (definition for definition in self._tool_definitions if definition.name == tool_name),
            None,
        )
        if not tool:
            raise ValueError(f"Tool '{tool_name}' is not available")
        self._validate_arguments(tool, arguments)

        # Route to tool implementation
        if tool_name == "loystar_auth_status":
            return self.tools.loystar_auth_status()
        elif tool_name == "loystar_get_customers":
            return await self.tools.loystar_get_customers(
                page_number=arguments.get("page_number", 1),
                page_size=arguments.get("page_size", 30),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_search_customers":
            return await self.tools.loystar_search_customers(
                query=arguments.get("query"),
                from_date=arguments.get("from_date"),
                to_date=arguments.get("to_date"),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_sales":
            return await self.tools.loystar_get_sales(
                from_date=arguments.get("from_date"),
                to_date=arguments.get("to_date"),
                page_number=arguments.get("page_number", 1),
                page_size=arguments.get("page_size", 30),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_orders":
            return await self.tools.loystar_get_orders(
                page_number=arguments.get("page_number", 1),
                page_size=arguments.get("page_size", 30),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_products":
            return await self.tools.loystar_get_products(
                time_stamp=arguments.get("time_stamp", 0),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_product_categories":
            return await self.tools.loystar_get_product_categories(
                time_stamp=arguments.get("time_stamp", 0),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_loyalty_programs":
            return await self.tools.loystar_get_loyalty_programs(
                time_stamp=arguments.get("time_stamp", 0),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_business_branches":
            return await self.tools.loystar_get_business_branches(
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_invoices":
            return await self.tools.loystar_get_invoices(
                status=arguments.get("status"),
                query=arguments.get("query"),
                include_pii=arguments.get("include_pii", False),
            )
        elif tool_name == "loystar_get_sms_balance":
            return await self.tools.loystar_get_sms_balance()
        elif tool_name == "loystar_get_current_subscription":
            return await self.tools.loystar_get_current_subscription()
        elif tool_name == "calculate_churn_risk":
            return await self.tools.calculate_churn_risk(
                customer_id=arguments.get("customer_id")
            )
        elif tool_name == "generate_custom_coupon":
            return await self.tools.generate_custom_coupon(
                customer_id=arguments.get("customer_id"),
                discount_percent=arguments.get("discount_percent"),
                expiry_hours=arguments.get("expiry_hours", 24),
                workspace_id=arguments.get("workspace_id", "default"),
                estimated_order_value=arguments.get("estimated_order_value", 100.0),
                max_uses=arguments.get("max_uses", 1),
                target_count=arguments.get("target_count", 1),
            )
        elif tool_name == "dispatch_omnichannel_message":
            return await self.tools.dispatch_omnichannel_message(
                customer_id=arguments.get("customer_id"),
                channel=arguments.get("channel"),
                message_body=arguments.get("message_body")
            )
        elif tool_name == "get_customer_profile":
            return await self.tools.get_customer_profile(
                customer_id=arguments.get("customer_id")
            )
        elif tool_name == "update_loyalty_points":
            return await self.tools.update_loyalty_points(
                customer_id=arguments.get("customer_id"),
                points=arguments.get("points"),
                reason=arguments.get("reason", "agent_action")
            )
        raise ValueError(f"Tool '{tool_name}' is not available")

    @staticmethod
    def _validate_arguments(tool: Tool, arguments: Dict[str, Any]) -> None:
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be an object")
        schema = tool.input_schema
        properties = schema.get("properties", {})
        unknown = set(arguments) - set(properties)
        if unknown:
            raise ValueError(f"Unknown tool argument: {sorted(unknown)[0]}")
        missing = set(schema.get("required", [])) - set(arguments)
        if missing:
            raise ValueError(f"Missing required argument: {sorted(missing)[0]}")

        for name, value in arguments.items():
            expected = properties[name].get("type")
            valid = (
                expected == "boolean" and isinstance(value, bool)
                or expected == "integer"
                and isinstance(value, int)
                and not isinstance(value, bool)
                or expected == "number"
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
                or expected == "string"
                and isinstance(value, str)
            )
            if not valid:
                raise ValueError(f"Argument '{name}' must be a {expected}")
            if isinstance(value, str) and len(value) > 1000:
                raise ValueError(f"Argument '{name}' is too long")
            if name == "page_number" and not 1 <= value <= 10_000:
                raise ValueError("page_number must be between 1 and 10000")
            if name == "page_size" and not 1 <= value <= 100:
                raise ValueError("page_size must be between 1 and 100")
            if name == "query" and isinstance(value, str) and len(value) > 200:
                raise ValueError("query must be at most 200 characters")
            if name == "time_stamp" and value < 0:
                raise ValueError("time_stamp cannot be negative")
    
    def list_resources(self) -> Dict[str, Any]:
        """List all available resources"""
        resource_templates = [
                {
                    "uriTemplate": resource.uri,
                    "name": resource.name,
                    "description": resource.description,
                    "mimeType": resource.mime_type
                }
                for resource in self._resources
        ]
        return {
            "resources": resource_templates,
            "resourceTemplates": resource_templates,
        }
    
    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """
        Read resource data by URI
        
        Args:
            uri: Resource URI
            
        Returns:
            Resource content
        """
        if not uri:
            raise ValueError("Resource URI is required")

        customer_match = re.fullmatch(r"loystar://customers/([^/]+)/(profile|rfm|memories)", uri)
        merchant_match = re.fullmatch(r"loystar://merchants/([^/]+)/campaigns/active", uri)

        if customer_match:
            customer_id, resource_name = customer_match.groups()
            if resource_name == "profile":
                return {
                    "uri": uri,
                    "mimeType": "application/json",
                    "content": await self.tools.get_customer_profile(customer_id),
                }
            if resource_name == "rfm":
                return {
                    "uri": uri,
                    "mimeType": "application/json",
                    "content": {
                        "customer_id": customer_id,
                        "recency_days": 4,
                        "frequency_score_tier": "VIP_HIGH",
                        "frequency_score": 92,
                        "monetary_lifetime_value_usd": 2450.00,
                        "monetary_score": 88,
                        "calculated_at": datetime.now(timezone.utc).isoformat(),
                    },
                }
            return {
                "uri": uri,
                "mimeType": "application/json",
                "content": {
                    "customer_id": customer_id,
                    "memories": [
                        {
                            "memory_type": "preference",
                            "content": "Prefers electronics offers and email receipts.",
                            "source": "transaction_history",
                            "importance_score": 0.72,
                        }
                    ],
                    "pii_redacted": True,
                },
            }

        if merchant_match:
            workspace_id = merchant_match.group(1)
            return {
                "uri": uri,
                "mimeType": "application/json",
                "content": {
                    "workspace_id": workspace_id,
                    "active_campaigns": [],
                    "margin_threshold": 0.1,
                    "max_discount_percent": 50,
                    "max_campaign_budget": 10000.0
                }
            }
        
        raise ValueError(f"Resource '{uri}' not found")


# Server initialization
def create_mcp_server() -> MCPServer:
    """Factory function to create MCP server instance"""
    return MCPServer(server_name="Loystar MCP Server")
