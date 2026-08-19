"""
Encryption helpers for storing Loystar merchant credentials at rest.

Uses AES-256-GCM with a key derived from OAUTH_ENCRYPTION_KEY via PBKDF2.
Each encryption produces a unique nonce; ciphertext includes the nonce + tag
so no additional state is needed.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from src.config import settings


def _derive_key(master_key: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte AES key using PBKDF2-SHA256."""
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        raise RuntimeError(
            "cryptography package is required for encrypted storage. "
            "Install it: pip install cryptography"
        )

    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(master_key.encode("utf-8"))
    return key, salt


def get_encryption_key() -> str:
    """Return the configured encryption key or raise."""
    key = settings.oauth_encryption_key
    if not key:
        raise RuntimeError(
            "OAUTH_ENCRYPTION_KEY is not configured. "
            "Generate one with: openssl rand -hex 32"
        )
    # Hash the user-provided key to get a consistent-length master secret
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def encrypt_credentials(credentials_json: str) -> str:
    """Encrypt a JSON string of LoystarCredentials.

    Returns a base64-encoded payload: salt + nonce + ciphertext + tag
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("cryptography package is required. Install it: pip install cryptography")

    master_key = get_encryption_key()
    key, salt = _derive_key(master_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, credentials_json.encode("utf-8"), None)

    # Pack: salt(16) + nonce(12) + ciphertext
    payload = salt + nonce + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_credentials(encrypted: str) -> str:
    """Decrypt a base64-encoded payload back to the original JSON string."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("cryptography package is required. Install it: pip install cryptography")

    master_key = get_encryption_key()
    payload = base64.urlsafe_b64decode(encrypted)
    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext = payload[28:]

    key, _ = _derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
