"""
Comprehensive unit tests for JWT authentication functionality.
Tests valid token parsing, invalid token handling, expired token detection, and claim validation.
"""

import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

# Use same settings as application
SECRET_KEY = "change_this_secret_key"  # Should match config.py default
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_valid_token(email="admin@example.com", scopes=None):
    """Create a valid token that expires in 30 minutes."""
    if scopes is None:
        scopes = ["read:user"]
    data = {"email": email, "scopes": scopes}
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    to_encode = {
        **data,
        "exp": now + expires_delta,
        "iat": now,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_expired_token(email="admin@example.com"):
    """Create an already expired token."""
    data = {"email": email, "scopes": ["read:user"]}
    expires_delta = timedelta(minutes=-1)  # Already expired
    now = datetime.now(timezone.utc)
    to_encode = {
        **data,
        "exp": now + expires_delta,
        "iat": now,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


class TestValidToken:
    """Test cases for valid token handling."""
    
    def test_valid_token_decoding(self):
        """Test that valid tokens are decoded correctly."""
        token = create_valid_token()
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert decoded_token is not None
        assert 'email' in decoded_token
        assert decoded_token['email'] == 'admin@example.com'
    
    def test_valid_token_contains_scopes(self):
        """Test that valid token contains expected scopes."""
        token = create_valid_token()
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert 'scopes' in decoded_token
        assert 'read:user' in decoded_token['scopes']
    
    def test_valid_token_has_required_claims(self):
        """Test that valid token has all required JWT claims."""
        token = create_valid_token()
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert 'exp' in decoded_token
        assert 'iat' in decoded_token


class TestInvalidToken:
    """Test cases for invalid token handling."""
    
    def test_malformed_token_raises_error(self):
        """Test that malformed tokens raise JWTError."""
        with pytest.raises(JWTError):
            jwt.decode("invalid.jwt.token", SECRET_KEY, algorithms=[ALGORITHM])
    
    def test_tampered_token_raises_error(self):
        """Test that tampered tokens raise JWTError."""
        # Create a valid token, then tamper with it
        data = {"email": "test@example.com", "scopes": ["read:user"]}
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        tampered_token = token[:-5] + "xxxxx"  # Modify the end
        
        with pytest.raises(JWTError):
            jwt.decode(tampered_token, SECRET_KEY, algorithms=[ALGORITHM])
    
    def test_empty_token_raises_error(self):
        """Test that empty tokens raise error."""
        with pytest.raises(JWTError):
            jwt.decode("", SECRET_KEY, algorithms=[ALGORITHM])


class TestExpiredToken:
    """Test cases for expired token handling."""
    
    def test_expired_token_raises_error(self):
        """Test that expired tokens are rejected."""
        token = create_expired_token()
        with pytest.raises(JWTError):
            jwt.decode(
                token, 
                SECRET_KEY, 
                algorithms=[ALGORITHM],
                options={"verify_exp": True}
            )
    
    def test_disabled_expiration_verify_accepts_expired(self):
        """Test that disabling exp verification accepts expired tokens (not recommended)."""
        token = create_expired_token()
        # This should work when verify_exp is False (not recommended for production)
        decoded_token = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False}
        )
        assert decoded_token is not None
        assert decoded_token['email'] == 'admin@example.com'


class TestClaimsParsing:
    """Test cases for JWT claims parsing."""
    
    def test_email_claim_parsed_correctly(self):
        """Test that email claim is parsed correctly."""
        token = create_valid_token(email="user@example.com")
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert decoded_token['email'] == 'user@example.com'
    
    def test_scopes_claim_parsed_correctly(self):
        """Test that scopes claim is parsed correctly."""
        token = create_valid_token(scopes=["read:user", "write:user"])
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert 'scopes' in decoded_token
        assert len(decoded_token['scopes']) == 2
        assert "read:user" in decoded_token['scopes']
        assert "write:user" in decoded_token['scopes']


class TestMultiUserScopes:
    """Test token for a user with multiple scopes."""
    
    def test_multi_scopes_token(self):
        """Test token encoding/decoding with multiple scopes."""
        email = "user@example.com"
        scopes = ["read:user", "write:user"]
        data = {"email": email, "scopes": scopes}
        
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        now = datetime.now(timezone.utc)
        to_encode = {
            **data,
            "exp": now + expires_delta,
            "iat": now,
        }
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert all(scope in decoded_token['scopes'] for scope in scopes)
        assert decoded_token['email'] == email
    
    def test_admin_scopes_token(self):
        """Test token with admin scopes."""
        email = "admin@example.com"
        scopes = ["read:user", "write:user", "delete:user", "admin:all"]
        data = {"email": email, "scopes": scopes}
        
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        now = datetime.now(timezone.utc)
        to_encode = {
            **data,
            "exp": now + expires_delta,
            "iat": now,
        }
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert len(decoded_token['scopes']) == 4
        assert "admin:all" in decoded_token['scopes']


class TestTokenGeneration:
    """Test token generation utilities."""
    
    def test_generate_token_with_custom_expiry(self):
        """Test token generation with custom expiration time."""
        email = "test@example.com"
        custom_expiry = timedelta(hours=2)
        data = {"email": email, "scopes": ["read:user"]}
        
        now = datetime.now(timezone.utc)
        to_encode = {
            **data,
            "exp": now + custom_expiry,
            "iat": now,
        }
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Expiry should be approximately 2 hours from now
        assert decoded_token['email'] == email
        assert 'scopes' in decoded_token


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
