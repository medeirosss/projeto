from __future__ import annotations

from typing import Optional

from app.security.crypto_service import decrypt_secret, encrypt_secret, is_encrypted

# Backward-compatible wrappers kept for any legacy imports.
# Clean v2 no longer creates or stores a local encryption key file.
# Encryption uses APP_SECRET_KEY through app.security.crypto_service.

def encrypt_value(value: Optional[str]) -> str:
    return encrypt_secret(value)


def decrypt_value(value: Optional[str]) -> str:
    return decrypt_secret(value)
