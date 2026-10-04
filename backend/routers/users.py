"""User management endpoints (invite / list / delete)."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from auth_helpers import hash_password
from database import db
from deps import require_role, tenant_filter, write_audit
from models import UserInvite

router = APIRouter(tags=["users"])


def validate_invite_authorization(user: dict, body: UserInvite) -> None:
    """Enforce tenant and role boundaries for user invitations."""
    if user["role"] != "owner" and body.tenant != user["tenant"]:
        raise HTTPException(status_code=403, detail="Cannot invite users into another tenant")
    if user["role"] != "owner" and body.role == "owner":
        raise HTTPException(status_code=403, detail="Only the owner can grant the owner role")


@router.get("/users")
async def list_users(user: dict = Depends(require_role("owner", "admin"))):
    users = await db.users.find(tenant_filter(user), {"_id": 0, "password_hash": 0}).to_list(100)
    return users


@router.post("/users")
async def invite_user(
    body: UserInvite,
    request: Request,
    user: dict = Depends(require_role("owner", "admin")),
):
    validate_invite_authorization(user, body)
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = secrets.token_hex(16)
    await db.users.insert_one({
        "id": user_id,
        "email": body.email,
        "name": body.name,
        "role": body.role,
        "tenant": body.tenant,
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "invited_by": user["email"],
    })
    await write_audit(user["email"], "user_invite", body.email, request, body.tenant)
    return {"message": "User invited", "email": body.email, "role": body.role}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    user: dict = Depends(require_role("owner", "admin")),
):
    target_filter = {"id": user_id}
    if user["role"] != "owner":
        target_filter["tenant"] = user["tenant"]
    target = await db.users.find_one(target_filter)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "owner":
        raise HTTPException(status_code=400, detail="Cannot remove the owner")
    delete_filter = {"id": user_id}
    if user["role"] != "owner":
        delete_filter["tenant"] = user["tenant"]
    result = await db.users.delete_one(delete_filter)
    if getattr(result, "deleted_count", 0) != 1:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(user["email"], "user_delete", target["email"], request, target["tenant"])
    return {"message": "User removed"}
