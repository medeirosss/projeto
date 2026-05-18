from __future__ import annotations

import base64
import os
from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken

ENC_PREFIX = "ENC:"


def _normalize_key(raw: str) -> bytes:
    """Return a valid Fernet key.

    APP_SECRET_KEY should preferably be a Fernet/base64 32-byte key. For lab
    environments we also accept arbitrary text and derive a deterministic key.
    """
    key = (raw or "").strip()
    if not key or key == "change_this_fernet_key":
        key = "centric-dev-only-change-me"
    try:
        Fernet(key.encode())
        return key.encode()
    except Exception:
        digest = sha256(key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    return Fernet(_normalize_key(os.getenv("APP_SECRET_KEY", "")))


def encrypt_secret(value: str | None) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text.startswith(ENC_PREFIX):
        return text
    return ENC_PREFIX + _get_fernet().encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str | None) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if not text.startswith(ENC_PREFIX):
        return text
    token = text[len(ENC_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def is_encrypted(value: str | None) -> bool:
    return bool(value) and str(value).startswith(ENC_PREFIX)
