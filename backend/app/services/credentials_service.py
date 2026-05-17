from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from app.repositories.credentials_repository import (
    disable_stored_credential,
    get_stored_credential_by_name,
    list_stored_credentials,
    save_stored_credential,
)
from app.security.crypto_service import decrypt_secret, encrypt_secret

PUBLIC_MASK = "********"


def _public_row(item: Dict[str, Any], include_secret: bool = False) -> Dict[str, Any]:
    row = deepcopy(item)
    secret = decrypt_secret(row.pop("secret_encrypted", ""))
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    row["metadata"] = metadata
    row["has_password"] = bool(secret)
    # Compatibilidade com o frontend e com o action_service atual.
    row["password"] = secret if include_secret else (PUBLIC_MASK if secret else "")
    row["type"] = row.get("type") or row.get("credential_type") or "generic"
    # Campos públicos úteis para WinRM, sem expor senha.
    if row["type"] == "winrm":
        row["winrm_host"] = metadata.get("host") or ""
        row["winrm_port"] = metadata.get("port") or 5985
        row["winrm_use_https"] = bool(metadata.get("use_https", False))
        row["winrm_transport"] = metadata.get("transport") or "ntlm"
    return row


def list_credentials(include_secret: bool = False) -> List[Dict[str, Any]]:
    return [_public_row(item, include_secret=include_secret) for item in list_stored_credentials()]


def get_credential_by_name(name: str, include_secret: bool = False) -> Dict[str, Any] | None:
    item = get_stored_credential_by_name(name)
    if not item:
        return None
    return _public_row(item, include_secret=include_secret)


def save_credential(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(payload or {})
    password = str(data.pop("password", "") or "")

    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    # Permite que o frontend envie estes campos diretamente.
    if str(data.get("type") or data.get("credential_type") or "").lower() == "winrm":
        metadata.update({
            "host": str(data.pop("winrm_host", metadata.get("host", "")) or "").strip(),
            "port": int(str(data.pop("winrm_port", metadata.get("port", 5985)) or 5985)),
            "use_https": bool(data.pop("winrm_use_https", metadata.get("use_https", False))),
            "transport": str(data.pop("winrm_transport", metadata.get("transport", "ntlm")) or "ntlm").strip().lower(),
        })
    data["metadata"] = metadata

    # Se o usuário deixar vazio ou enviar a máscara, preserva a senha atual no banco.
    if password and password != PUBLIC_MASK:
        data["secret_encrypted"] = encrypt_secret(password)
    else:
        data["secret_encrypted"] = ""
    saved = save_stored_credential(data)
    return _public_row(saved, include_secret=False)


def delete_credential(cred_id: str) -> bool:
    # Soft delete: mantém histórico/referência, mas remove da seleção da aplicação.
    return disable_stored_credential(cred_id)
