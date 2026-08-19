from __future__ import annotations

"""
Human-in-the-Loop (HITL) Governance Framework for Loystar

This module implements the quantitative risk-tiering engine and 
pause/resume state machine for autonomous action control.
"""
import json
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    import redis.asyncio as redis
else:
    redis = None


class RiskLevel(str, Enum):
    """Risk classification levels"""
    AUTONOMOUS = "autonomous"
    ESCALATED = "escalated"


class ApprovalStatus(str, Enum):
    """HITL approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class RiskAssessment:
    """Risk assessment for an action"""
    action_type: str
    financial_exposure: float
    target_count: int
    risk_level: RiskLevel = RiskLevel.AUTONOMOUS
    requires_approval: bool = False
    approval_timeout_hours: int = 24
    

@dataclass
class ApprovalRequest:
    """Approval request to be sent to merchant"""
    request_id: str
    workspace_id: str
    action_type: str
    action_data: Dict[str, Any]
    financial_exposure: float
    target_count: int
    risk_level: RiskLevel
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    rejected_by: Optional[str] = None
    approval_notes: Optional[str] = None
    webhook_payload: Optional[Dict[str, Any]] = None


class RiskTieringEngine:
    """
    Quantitative risk-tiering engine that classifies actions
    into Autonomous or Escalated tiers.
    """
    
    def __init__(
        self,
        auto_approve_threshold: float = 100.0,
        campaign_size_threshold: int = 50,
        redis_client: Optional[redis.Redis] = None
    ):
        self.auto_approve_threshold = auto_approve_threshold
        self.campaign_size_threshold = campaign_size_threshold
        self.redis_client = redis_client
    
    async def assess_risk(
        self,
        action_type: str,
        financial_exposure: float = 0.0,
        target_count: int = 1,
        **kwargs
    ) -> RiskAssessment:
        """
        Assess the risk level of an action.
        
        Args:
            action_type: Type of action (e.g., 'coupon_create', 'campaign_send')
            financial_exposure: Total financial value at risk
            target_count: Number of customers affected
            
        Returns:
            RiskAssessment with classification
        """
        # Determine if approval is required
        requires_approval = (
            financial_exposure > self.auto_approve_threshold or
            target_count > self.campaign_size_threshold
        )
        
        # Classify risk level
        risk_level = (
            RiskLevel.ESCALATED if requires_approval 
            else RiskLevel.AUTONOMOUS
        )
        
        return RiskAssessment(
            action_type=action_type,
            financial_exposure=financial_exposure,
            target_count=target_count,
            risk_level=risk_level,
            requires_approval=requires_approval
        )
    
    def calculate_financial_exposure(
        self,
        action_type: str,
        action_data: Dict[str, Any]
    ) -> float:
        """
        Calculate financial exposure for an action.
        
        Args:
            action_type: Type of action
            action_data: Action parameters
            
        Returns:
            Total financial exposure in USD
        """
        if action_type == "coupon_create":
            # Calculate potential revenue loss from discount
            discount_percent = action_data.get("discount_percent", 0)
            # Estimate average order value
            avg_order_value = action_data.get("estimated_order_value", 100.0)
            max_uses = action_data.get("max_uses", 1)
            
            return (discount_percent / 100) * avg_order_value * max_uses
        
        elif action_type == "campaign_send":
            # Calculate campaign budget
            target_size = action_data.get("target_size", 0)
            discount_value = action_data.get("discount_value", 5.0)
            
            return target_size * discount_value
        
        elif action_type == "points_award":
            # Calculate points value (assuming 100 points = $1)
            points = action_data.get("points", 0)
            return points / 100
        
        return 0.0


class ApprovalQueue:
    """
    Redis-backed pause/resume queue for HITL requests.
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        queue_prefix: str = "loystar:hitl:queue"
    ):
        self.redis = redis_client
        self.queue_prefix = queue_prefix
    
    async def enqueue_request(self, request: ApprovalRequest) -> str:
        """
        Enqueue a HITL approval request.
        
        Args:
            request: Approval request to enqueue
            
        Returns:
            Request ID
        """
        queue_key = f"{self.queue_prefix}:pending"
        request_key = f"{self.queue_prefix}:request:{request.request_id}"
        
        # Store request data
        await self.redis.set(
            request_key,
            json.dumps({
                "request_id": request.request_id,
                "workspace_id": request.workspace_id,
                "action_type": request.action_type,
                "action_data": request.action_data,
                "financial_exposure": request.financial_exposure,
                "target_count": request.target_count,
                "risk_level": request.risk_level.value,
                "status": request.status.value,
                "created_at": request.created_at.isoformat(),
                "expires_at": request.expires_at.isoformat() if request.expires_at else None
            }),
            ex=86400  # 24 hour TTL
        )
        
        # Add to pending queue
        await self.redis.zadd(
            queue_key,
            {request.request_id: datetime.now(timezone.utc).timestamp()}
        )
        
        return request.request_id
    
    async def get_pending_requests(
        self,
        workspace_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get pending approval requests for a workspace.
        
        Args:
            workspace_id: Workspace ID
            limit: Maximum number of requests to return
            
        Returns:
            List of pending requests
        """
        queue_key = f"{self.queue_prefix}:pending"
        
        # Get request IDs from queue
        request_ids = await self.redis.zrange(queue_key, 0, limit - 1)
        
        requests = []
        for request_id in request_ids:
            request_key = f"{self.queue_prefix}:request:{request_id}"
            data = await self.redis.get(request_key)
            
            if data:
                request_data = json.loads(data)
                if request_data.get("workspace_id") == workspace_id:
                    requests.append(request_data)
        
        return requests
    
    async def approve_request(
        self,
        request_id: str,
        approved_by: str,
        notes: Optional[str] = None
    ) -> bool:
        """
        Approve a HITL request.
        
        Args:
            request_id: Request ID
            approved_by: User who approved
            notes: Optional approval notes
            
        Returns:
            True if successful
        """
        request_key = f"{self.queue_prefix}:request:{request_id}"
        data = await self.redis.get(request_key)
        
        if not data:
            return False
        
        request_data = json.loads(data)
        request_data["status"] = ApprovalStatus.APPROVED.value
        request_data["approved_by"] = approved_by
        request_data["approval_notes"] = notes
        request_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Update request
        await self.redis.set(request_key, json.dumps(request_data))
        
        # Remove from pending queue
        queue_key = f"{self.queue_prefix}:pending"
        await self.redis.zrem(queue_key, request_id)
        
        # Add to approved queue
        approved_key = f"{self.queue_prefix}:approved"
        await self.redis.zadd(
            approved_key,
            {request_id: datetime.now(timezone.utc).timestamp()}
        )
        
        return True
    
    async def reject_request(
        self,
        request_id: str,
        rejected_by: str,
        notes: Optional[str] = None
    ) -> bool:
        """
        Reject a HITL request.
        
        Args:
            request_id: Request ID
            rejected_by: User who rejected
            notes: Optional rejection notes
            
        Returns:
            True if successful
        """
        request_key = f"{self.queue_prefix}:request:{request_id}"
        data = await self.redis.get(request_key)
        
        if not data:
            return False
        
        request_data = json.loads(data)
        request_data["status"] = ApprovalStatus.REJECTED.value
        request_data["rejected_by"] = rejected_by
        request_data["approval_notes"] = notes
        request_data["updated_at"] = datetime.utcnow().isoformat()
        
        # Update request
        await self.redis.set(request_key, json.dumps(request_data))
        
        # Remove from pending queue
        queue_key = f"{self.queue_prefix}:pending"
        await self.redis.zrem(queue_key, request_id)
        
        return True


class WebhookNotifier:
    """
    Interactive webhook notifier for merchant approval.
    """
    
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
    
    async def send_approval_request(
        self,
        request: ApprovalRequest
    ) -> Dict[str, Any]:
        """
        Send approval request to merchant webhook.
        
        Args:
            request: Approval request
            
        Returns:
            Webhook delivery status
        """
        if not self.webhook_url:
            return {
                "status": "no_webhook",
                "message": "No webhook URL configured"
            }
        
        # Create signed payload
        payload = {
            "request_id": request.request_id,
            "action_type": request.action_type,
            "action_data": request.action_data,
            "financial_exposure": request.financial_exposure,
            "target_count": request.target_count,
            "risk_level": request.risk_level.value,
            "created_at": request.created_at.isoformat(),
            "expires_at": request.expires_at.isoformat() if request.expires_at else None,
            "actions": {
                "approve": f"POST /api/v1/hitl/approve/{request.request_id}?approved=true",
                "reject": f"POST /api/v1/hitl/approve/{request.request_id}?approved=false"
            }
        }
        
        # In production, this would send an HTTP POST request
        # For now, return the payload
        
        return {
            "status": "queued",
            "webhook_url": self.webhook_url,
            "payload": payload
        }


def create_approval_request(
    workspace_id: str,
    action_type: str,
    action_data: Dict[str, Any],
    risk_assessment: RiskAssessment,
    approval_timeout_hours: int = 24
) -> ApprovalRequest:
    """
    Factory function to create an approval request.
    
    Args:
        workspace_id: Workspace ID
        action_type: Type of action
        action_data: Action parameters
        risk_assessment: Risk assessment result
        approval_timeout_hours: Hours until request expires
        
    Returns:
        ApprovalRequest instance
    """
    request_id = f"hitl_{uuid.uuid4().hex}"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=approval_timeout_hours)
    
    return ApprovalRequest(
        request_id=request_id,
        workspace_id=workspace_id,
        action_type=action_type,
        action_data=action_data,
        financial_exposure=risk_assessment.financial_exposure,
        target_count=risk_assessment.target_count,
        risk_level=risk_assessment.risk_level,
        expires_at=expires_at
    )
