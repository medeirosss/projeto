from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_payload(license_data: Dict[str, Any]) -> bytes:
    payload = {k: v for k, v in license_data.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_public_key(path: Path):
    public_key_bytes = path.read_bytes()
    return serialization.load_pem_public_key(public_key_bytes)


def verify_signature(license_data: Dict[str, Any], public_key_path: Path) -> Tuple[bool, str]:
    signature_b64 = license_data.get("signature")
    if not signature_b64:
        return False, "Arquivo de licença sem assinatura digital."
    try:
        signature = base64.b64decode(signature_b64)
        public_key = _load_public_key(public_key_path)
        public_key.verify(
            signature,
            canonical_payload(license_data),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True, "Assinatura válida."
    except (InvalidSignature, ValueError, TypeError):
        return False, "Assinatura digital inválida."
    except FileNotFoundError:
        return False, "Chave pública de licenciamento não encontrada."


def validate_license_file(license_file: Path, public_key_file: Path) -> Dict[str, Any]:
    now = datetime.utcnow()
    if not license_file.exists():
        return {
            "valid": False,
            "status": "missing",
            "status_message": "Licença não encontrada. Entre em contato com o suporte.",
            "last_validation_at": now,
        }

    try:
        license_data = json.loads(license_file.read_text(encoding="utf-8"))
    except Exception:
        return {
            "valid": False,
            "status": "invalid",
            "status_message": "Arquivo de licença inválido. Entre em contato com o suporte.",
            "last_validation_at": now,
        }

    ok, message = verify_signature(license_data, public_key_file)
    if not ok:
        return {
            "valid": False,
            "status": "invalid_signature",
            "status_message": f"{message} Entre em contato com o suporte.",
            "last_validation_at": now,
            "raw_license": license_data,
        }

    expected_domain = os.getenv("EXPECTED_AD_DOMAIN", "").strip().lower()
    license_domain = str(license_data.get("domain_name") or license_data.get("domain") or "").strip().lower()
    if expected_domain and license_domain and expected_domain != license_domain:
        return {
            "valid": False,
            "status": "domain_mismatch",
            "status_message": "Licença não pertence ao domínio configurado. Entre em contato com o suporte.",
            "last_validation_at": now,
            "raw_license": license_data,
        }

    expires_at = license_data.get("expires_at")
    if expires_at:
        try:
            expiry = date.fromisoformat(expires_at)
            if expiry < date.today():
                return {
                    "valid": False,
                    "status": "expired",
                    "status_message": "Licença expirada. Entre em contato com o suporte.",
                    "last_validation_at": now,
                    "raw_license": license_data,
                }
        except ValueError:
            return {
                "valid": False,
                "status": "invalid_expiration",
                "status_message": "Data de expiração da licença inválida. Entre em contato com o suporte.",
                "last_validation_at": now,
                "raw_license": license_data,
            }

    modules = license_data.get("modules") or {}
    if isinstance(modules, list):
        modules = {name: True for name in modules}

    return {
        "valid": True,
        "status": "valid",
        "status_message": "Licença válida.",
        "license_id": license_data.get("license_id"),
        "customer_id": license_data.get("customer_id"),
        "customer_name": license_data.get("customer") or license_data.get("customer_name"),
        "domain_name": license_domain,
        "license_type": license_data.get("license_type"),
        "license_mode": license_data.get("license_mode", "offline"),
        "expires_at": expires_at,
        "modules": modules,
        "max_users": license_data.get("max_users"),
        "max_endpoints": license_data.get("max_endpoints"),
        "last_validation_at": now,
        "raw_license": license_data,
    }
