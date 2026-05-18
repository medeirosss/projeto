from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.database.connection import get_db_session

ROLE_PRIORITY = {"viewer": 1, "operator": 2, "admin": 3}


def _normalize_role(role: str | None) -> str:
    role = (role or "viewer").strip().lower()
    return role if role in ROLE_PRIORITY else "viewer"


def _best_role(roles: list[str]) -> str:
    if not roles:
        return "viewer"
    return max((_normalize_role(r) for r in roles), key=lambda r: ROLE_PRIORITY[r])


def count_enabled_authorizers() -> int:
    with get_db_session() as db:
        users = db.execute(text("SELECT COUNT(*) FROM auth_allowed_users WHERE enabled = true")).scalar_one()
        groups = db.execute(text("SELECT COUNT(*) FROM auth_allowed_groups WHERE enabled = true")).scalar_one()
        return int(users or 0) + int(groups or 0)


def get_allowed_user_role(username: str) -> Optional[str]:
    username = (username or "").strip().lower()
    with get_db_session() as db:
        row = db.execute(
            text("""
                SELECT role FROM auth_allowed_users
                WHERE enabled = true AND lower(username) = :username
                LIMIT 1
            """),
            {"username": username},
        ).mappings().first()
        return _normalize_role(row["role"]) if row else None


def get_allowed_group_roles(user_groups: list[str]) -> list[str]:
    names = [g.strip().lower() for g in user_groups or [] if g and g.strip()]
    if not names:
        return []
    with get_db_session() as db:
        rows = db.execute(
            text("""
                SELECT role FROM auth_allowed_groups
                WHERE enabled = true AND lower(group_name) = ANY(:groups)
            """),
            {"groups": names},
        ).mappings().all()
        return [_normalize_role(row["role"]) for row in rows]


def resolve_authorized_role(username: str, groups: list[str]) -> Optional[str]:
    # Bootstrap for new/lab installations: when no allowed user/group exists yet,
    # the first successfully authenticated AD user can enter as admin and configure access.
    # Disable by setting AUTH_BOOTSTRAP_EMPTY_ADMINS=false.
    import os
    if count_enabled_authorizers() == 0 and os.getenv("AUTH_BOOTSTRAP_EMPTY_ADMINS", "true").lower() == "true":
        return "admin"

    roles: list[str] = []
    user_role = get_allowed_user_role(username)
    if user_role:
        roles.append(user_role)
    roles.extend(get_allowed_group_roles(groups))
    if not roles:
        return None
    return _best_role(roles)


def list_allowed_users() -> List[Dict[str, Any]]:
    with get_db_session() as db:
        return [dict(row) for row in db.execute(text("SELECT id, username, role, enabled, created_at FROM auth_allowed_users ORDER BY username")).mappings().all()]


def upsert_allowed_user(username: str, role: str, enabled: bool = True) -> Dict[str, Any]:
    username = (username or "").strip()
    if not username:
        raise RuntimeError("Username obrigatório.")
    role = _normalize_role(role)
    with get_db_session() as db:
        row = db.execute(
            text("""
                INSERT INTO auth_allowed_users(username, role, enabled)
                VALUES(:username, :role, :enabled)
                ON CONFLICT(username) DO UPDATE SET role = EXCLUDED.role, enabled = EXCLUDED.enabled
                RETURNING id, username, role, enabled, created_at
            """),
            {"username": username, "role": role, "enabled": enabled},
        ).mappings().one()
        return dict(row)


def delete_allowed_user(item_id: int) -> bool:
    with get_db_session() as db:
        result = db.execute(text("DELETE FROM auth_allowed_users WHERE id = :id"), {"id": item_id})
        return result.rowcount > 0


def list_allowed_groups() -> List[Dict[str, Any]]:
    with get_db_session() as db:
        return [dict(row) for row in db.execute(text("SELECT id, group_name, role, enabled, created_at FROM auth_allowed_groups ORDER BY group_name")).mappings().all()]


def upsert_allowed_group(group_name: str, role: str, enabled: bool = True) -> Dict[str, Any]:
    group_name = (group_name or "").strip()
    if not group_name:
        raise RuntimeError("Nome do grupo obrigatório.")
    role = _normalize_role(role)
    with get_db_session() as db:
        row = db.execute(
            text("""
                INSERT INTO auth_allowed_groups(group_name, role, enabled)
                VALUES(:group_name, :role, :enabled)
                ON CONFLICT(group_name) DO UPDATE SET role = EXCLUDED.role, enabled = EXCLUDED.enabled
                RETURNING id, group_name, role, enabled, created_at
            """),
            {"group_name": group_name, "role": role, "enabled": enabled},
        ).mappings().one()
        return dict(row)


def delete_allowed_group(item_id: int) -> bool:
    with get_db_session() as db:
        result = db.execute(text("DELETE FROM auth_allowed_groups WHERE id = :id"), {"id": item_id})
        return result.rowcount > 0


def write_login_audit(username: str, source_ip: str, result: str, reason: str = "") -> None:
    with get_db_session() as db:
        db.execute(
            text("""
                INSERT INTO login_audit_log(username, source_ip, login_result, reason)
                VALUES(:username, :source_ip, :login_result, :reason)
            """),
            {"username": username, "source_ip": source_ip, "login_result": result, "reason": reason},
        )

# ---- Local bootstrap users -------------------------------------------------
# Local users are used only for first access / break-glass access.
# User passwords are never stored in plain text. The database stores only a
# salted PBKDF2-SHA256 password hash.

from app.security.password_service import hash_password, verify_password


def ensure_local_auth_schema() -> None:
    with get_db_session() as db:
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS auth_local_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'admin',
                enabled BOOLEAN DEFAULT TRUE,
                must_change_password BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        existing = db.execute(text("SELECT COUNT(*) FROM auth_local_users WHERE lower(username) = 'admin'" )).scalar_one()
        if int(existing or 0) == 0:
            db.execute(
                text("""
                    INSERT INTO auth_local_users(username, password_hash, role, enabled, must_change_password)
                    VALUES(:username, :password_hash, 'admin', true, true)
                """),
                {"username": "admin", "password_hash": hash_password("admin")},
            )


def authenticate_local_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    username = (username or "").strip().lower()
    if not username:
        return None
    ensure_local_auth_schema()
    with get_db_session() as db:
        row = db.execute(
            text("""
                SELECT id, username, password_hash, role, enabled, must_change_password
                FROM auth_local_users
                WHERE lower(username) = :username
                LIMIT 1
            """),
            {"username": username},
        ).mappings().first()
        if not row or not row["enabled"]:
            return None
        if not verify_password(password or "", row["password_hash"]):
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "role": _normalize_role(row["role"]),
            "must_change_password": bool(row["must_change_password"]),
        }


def change_local_user_password(username: str, current_password: str, new_password: str) -> None:
    username = (username or "").strip().lower()
    if len(new_password or "") < 8:
        raise RuntimeError("A nova senha precisa ter pelo menos 8 caracteres.")
    user = authenticate_local_user(username, current_password)
    if not user:
        raise RuntimeError("Senha atual inválida.")
    with get_db_session() as db:
        db.execute(
            text("""
                UPDATE auth_local_users
                SET password_hash = :password_hash,
                    must_change_password = false,
                    updated_at = CURRENT_TIMESTAMP
                WHERE lower(username) = :username
            """),
            {"username": username, "password_hash": hash_password(new_password)},
        )


def local_user_must_change_password(username: str) -> bool:
    username = (username or "").strip().lower()
    ensure_local_auth_schema()
    with get_db_session() as db:
        row = db.execute(
            text("SELECT must_change_password FROM auth_local_users WHERE lower(username) = :username LIMIT 1"),
            {"username": username},
        ).mappings().first()
        return bool(row and row["must_change_password"])
