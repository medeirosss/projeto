from __future__ import annotations

import hashlib
import hmac
import os
import secrets


def get_registration_token() -> str:
    return os.getenv("MAGI_RUNNER_REGISTRATION_TOKEN", "CHANGE_ME")


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, secret_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), secret_hash)


def new_runner_uuid() -> str:
    return "RUNNER-" + secrets.token_hex(12).upper()


def new_job_uuid() -> str:
    return "JOB-" + secrets.token_hex(12).upper()


def new_runner_secret() -> str:
    return secrets.token_urlsafe(48)
