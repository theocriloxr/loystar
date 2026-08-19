"""
Identity Resolution Engine for Loystar

This module implements the multi-channel identity resolution using
deterministic matching and probabilistic clustering.
"""
import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import phonenumbers


class MatchConfidence(str, Enum):
    """Match confidence levels"""
    HIGH = "high"        # > 98%
    MEDIUM = "medium"    # 80-98%
    LOW = "low"          # < 80%
    NONE = "none"


@dataclass
class IdentityMatch:
    """Identity match result"""
    source_id: str
    source_platform: str
    target_customer_id: str
    confidence: MatchConfidence
    confidence_score: float
    match_factors: List[str] = field(default_factory=list)


@dataclass
class CustomerIdentity:
    """Customer identity record"""
    customer_id: str
    workspace_id: str
    
    # Platform-specific IDs
    stripe_customer_id: Optional[str] = None
    paystack_customer_id: Optional[str] = None
    
    # Contact information
    email: Optional[str] = None
    phone: Optional[str] = None
    phone_e164: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)


class IdentityResolutionEngine:
    """
    Multi-channel identity resolution engine.
    
    Uses deterministic cascade matching and probabilistic 
    clustering to link customer identities across platforms.
    """
    
    def __init__(self, match_threshold: float = 0.80):
        self.match_threshold = match_threshold
    
    def normalize_phone(self, phone: str, region: str = None) -> Tuple[str, str]:
        """
        Normalize phone number to E.164 format.
        
        Args:
            phone: Phone number string
            region: Country code (e.g., 'NG', 'US')
            
        Returns:
            Tuple of (E.164 formatted number, country code)
        """
        try:
            parsed = phonenumbers.parse(phone, region)
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            country_code = phonenumbers.region_code_for_number(parsed)
            return e164, country_code
        except phonenumbers.NumberParseException:
            return phone, region
    
    def hash_phone(self, phone: str) -> str:
        """Create SHA-256 hash of phone number."""
        e164, _ = self.normalize_phone(phone)
        return hashlib.sha256(e164.encode()).hexdigest()
    
    def normalize_email(self, email: str) -> str:
        """Normalize email address (lowercase, strip whitespace)."""
        return email.lower().strip()
    
    def hash_email(self, email: str) -> str:
        """Create SHA-256 hash of email address."""
        normalized = self.normalize_email(email)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def match_by_email(
        self,
        email: str,
        existing_identities: List[CustomerIdentity]
    ) -> List[IdentityMatch]:
        """Match customer by email address."""
        normalized_email = self.normalize_email(email)
        matches = []
        
        for identity in existing_identities:
            if identity.email and self.normalize_email(identity.email) == normalized_email:
                matches.append(IdentityMatch(
                    source_id=email,
                    source_platform="email",
                    target_customer_id=identity.customer_id,
                    confidence=MatchConfidence.HIGH,
                    confidence_score=0.99,
                    match_factors=["email_exact"]
                ))
        
        return matches
    
    def match_by_phone(
        self,
        phone: str,
        existing_identities: List[CustomerIdentity],
        location_context: Optional[Dict[str, Any]] = None
    ) -> List[IdentityMatch]:
        """Match customer by phone number with location context."""
        e164, country_code = self.normalize_phone(phone)
        matches = []
        
        for identity in existing_identities:
            match_factors = []
            confidence_score = 0.0
            
            if identity.phone_e164 == e164:
                match_factors.append("phone_e164_exact")
                confidence_score = 0.99
            elif location_context and identity.phone:
                orig_e164, orig_country = self.normalize_phone(identity.phone)
                if orig_e164 == e164:
                    match_factors.append("phone_original_exact")
                    confidence_score = 0.98
                if orig_country == country_code:
                    match_factors.append("same_country")
                    confidence_score += 0.05
            
            if match_factors:
                confidence = (
                    MatchConfidence.HIGH if confidence_score > 0.98
                    else MatchConfidence.MEDIUM if confidence_score > 0.80
                    else MatchConfidence.LOW
                )
                
                matches.append(IdentityMatch(
                    source_id=phone,
                    source_platform="phone",
                    target_customer_id=identity.customer_id,
                    confidence=confidence,
                    confidence_score=confidence_score,
                    match_factors=match_factors
                ))
        
        return matches
    
    def resolve_identity(
        self,
        platform: str,
        external_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        location_context: Optional[Dict[str, Any]] = None,
        existing_identities: Optional[List[CustomerIdentity]] = None
    ) -> Tuple[Optional[str], List[IdentityMatch]]:
        """Resolve customer identity across platforms."""
        if existing_identities is None:
            return None, []
        
        all_matches = []
        
        if email:
            email_matches = self.match_by_email(email, existing_identities)
            all_matches.extend(email_matches)
        
        if phone:
            phone_matches = self.match_by_phone(phone, existing_identities, location_context)
            all_matches.extend(phone_matches)
        
        if not all_matches:
            return None, []
        
        best_match = max(all_matches, key=lambda m: m.confidence_score)
        
        if best_match.confidence_score >= self.match_threshold:
            return best_match.target_customer_id, all_matches
        
        return None, all_matches


def create_identity(
    customer_id: str,
    workspace_id: str,
    stripe_customer_id: Optional[str] = None,
    paystack_customer_id: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None
) -> CustomerIdentity:
    """Factory function to create a customer identity record."""
    engine = IdentityResolutionEngine()
    
    phone_e164 = None
    if phone:
        phone_e164, _ = engine.normalize_phone(phone)
    
    return CustomerIdentity(
        customer_id=customer_id,
        workspace_id=workspace_id,
        stripe_customer_id=stripe_customer_id,
        paystack_customer_id=paystack_customer_id,
        email=email,
        phone=phone,
        phone_e164=phone_e164
    )
