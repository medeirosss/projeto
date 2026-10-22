from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from app.auth.ldap_service import authenticate_and_get_groups
from app.config import FRONTEND_DIR
from app.repositories.auth_repository import (
    authenticate_local_user,
    change_local_user_password,
    delete_allowed_group,
    delete_allowed_user,
    list_allowed_groups,
    list_allowed_users,
    resolve_authorized_role,
    upsert_allowed_group,
    upsert_allowed_user,
    write_login_audit,
)
from app.security.jwt_service import JWT_COOKIE_NAME, JWT_EXPIRE_MINUTES, create_access_token, decode_access_token

router = APIRouter(tags=["auth"])


@router.get("/login")
async def login_page():
    return FileResponse(FRONTEND_DIR / "login.html")


@router.get("/change-password")
async def change_password_page():
    return FileResponse(FRONTEND_DIR / "change_password.html")


@router.post("/api/auth/login")
async def login(request: Request, response: Response, payload: Dict[str, Any] = Body(...)):
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    source_ip = request.client.host if request.client else ""
    try:
        # 1) Local bootstrap/break-glass login. Default first access: admin/admin.
        #    The password is validated against a salted hash stored in PostgreSQL.
        local_user = authenticate_local_user(username, password)
        if local_user:
            token = create_access_token(
                local_user["username"],
                local_user["role"],
                [],
                must_change_password=local_user["must_change_password"],
                auth_type="local",
            )
            response.set_cookie(
                key=JWT_COOKIE_NAME,
                value=token,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=JWT_EXPIRE_MINUTES * 60,
                path="/",
            )
            write_login_audit(local_user["username"], source_ip, "success", f"local role={local_user['role']}")
            return {
                "success": True,
                "must_change_password": local_user["must_change_password"],
                "redirect_to": "/change-password" if local_user["must_change_password"] else "/",
                "user": {"username": local_user["username"], "display_name": local_user["username"], "role": local_user["role"], "auth_type": "local"},
            }

        # 2) Normal AD login.
        ad_user = authenticate_and_get_groups(username, password)
        role = resolve_authorized_role(ad_user["username"], ad_user.get("groups") or [])
        if not role:
            write_login_audit(username, source_ip, "denied", "Usuário autenticado no AD, mas sem autorização local.")
            raise HTTPException(status_code=403, detail="Usuário autenticado no AD, mas não autorizado na aplicação.")
        token = create_access_token(ad_user["username"], role, ad_user.get("groups") or [], auth_type="ad")
        response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=JWT_EXPIRE_MINUTES * 60,
            path="/",
        )
        write_login_audit(ad_user["username"], source_ip, "success", f"ad role={role}")
        return {"success": True, "redirect_to": "/", "user": {"username": ad_user["username"], "display_name": ad_user.get("display_name"), "role": role, "auth_type": "ad"}}
    except HTTPException:
        raise
    except Exception as exc:
        write_login_audit(username, source_ip, "failed", str(exc))
        raise HTTPException(status_code=401, detail=str(exc))


@router.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(JWT_COOKIE_NAME, path="/")
    return {"success": True}


@router.get("/api/auth/me")
async def me(request: Request):
    token = request.cookies.get(JWT_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return {"authenticated": True, "user": {"username": payload.get("sub"), "role": payload.get("role"), "groups": payload.get("groups", []), "auth_type": payload.get("auth_type"), "must_change_password": payload.get("must_change_password", False)}}


@router.post("/api/auth/change-password")
async def api_change_password(request: Request, response: Response, payload: Dict[str, Any] = Body(...)):
    token = request.cookies.get(JWT_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    try:
        token_payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    if token_payload.get("auth_type") != "local":
        raise HTTPException(status_code=400, detail="Troca de senha local permitida apenas para usuários locais.")
    username = str(token_payload.get("sub") or "")
    current_password = str(payload.get("current_password") or "")
    new_password = str(payload.get("new_password") or "")
    confirm_password = str(payload.get("confirm_password") or "")
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="A confirmação da senha não confere.")
    try:
        change_local_user_password(username, current_password, new_password)
        new_token = create_access_token(username, str(token_payload.get("role") or "admin"), [], must_change_password=False, auth_type="local")
        response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=new_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=JWT_EXPIRE_MINUTES * 60,
            path="/",
        )
        write_login_audit(username, request.client.host if request.client else "", "password_changed", "local bootstrap password changed")
        return {"success": True, "redirect_to": "/"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/api/auth/allowed-users")
async def api_list_allowed_users():
    return {"users": list_allowed_users()}


@router.post("/api/auth/allowed-users")
async def api_save_allowed_user(payload: Dict[str, Any] = Body(...)):
    try:
        return {"user": upsert_allowed_user(str(payload.get("username") or ""), str(payload.get("role") or "viewer"), bool(payload.get("enabled", True)))}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/api/auth/allowed-users/{item_id}")
async def api_delete_allowed_user(item_id: int):
    if not delete_allowed_user(item_id):
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    return {"success": True}


@router.get("/api/auth/allowed-groups")
async def api_list_allowed_groups():
    return {"groups": list_allowed_groups()}


@router.post("/api/auth/allowed-groups")
async def api_save_allowed_group(payload: Dict[str, Any] = Body(...)):
    try:
        return {"group": upsert_allowed_group(str(payload.get("group_name") or ""), str(payload.get("role") or "viewer"), bool(payload.get("enabled", True)))}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/api/auth/allowed-groups/{item_id}")
async def api_delete_allowed_group(item_id: int):
    if not delete_allowed_group(item_id):
        raise HTTPException(status_code=404, detail="Grupo não encontrado.")
    return {"success": True}
