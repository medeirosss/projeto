from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt

JWT_ALGORITHM = "HS256"
JWT_COOKIE_NAME = os.getenv("JWT_COOKIE_NAME", "centric_session")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


def _secret() -> str:
    secret = os.getenv("APP_SECRET_KEY", "")
    if not secret:
        raise RuntimeError("APP_SECRET_KEY não configurada.")
    return secret


def create_access_token(subject: str, role: str, groups: list[str] | None = None, must_change_password: bool = False, auth_type: str = "ad") -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "groups": groups or [],
        "must_change_password": bool(must_change_password),
        "auth_type": auth_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
        "type": "access",
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise RuntimeError("Sessão expirada.") from exc
    except jwt.InvalidTokenError as exc:
        raise RuntimeError("Sessão inválida.") from exc
