import ipaddress

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from datetime import datetime, timezone
from pydantic import BaseModel
from typing import Optional

from db import db_manager
from auth import get_password_hash, verify_password, get_current_user, get_current_user_allow_expired, require_role
from policies import get_password_policy, validate_password
from audit import log_action
from logging_config import get_logger
from crypto import encrypt_secret
from identity import (
    any_contact_email_in_use,
    email_in_use,
    is_valid_email_format,
    normalize_email,
)
from session_revocation import revoke_user_refresh_tokens, is_sensitive_role_downgrade
from routers.socc import purge_user_socc_data

logger = get_logger("UsersRouter")

router = APIRouter(prefix="/users", tags=["users"])
FIELD_EXCLUDED = 0
PASSWORD_RESET_NOT_REQUIRED = False


class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    name: str
    email: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    name: Optional[str] = None
    is_active: Optional[bool] = None
    suspension_reason: Optional[str] = None
    force_password_reset: Optional[bool] = None
    email: Optional[str] = None
    allowed_ips: Optional[list[str]] = None


class UserPreferencesUpdate(BaseModel):
    password: Optional[str] = None
    preferred_lang: Optional[str] = None
    avatar_base64: Optional[str] = None
    avatar_fit: Optional[str] = None
    bio: Optional[str] = None
    recovery_email: Optional[str] = None
    notification_center: Optional[dict] = None


class ThirdPartyKeysUpdate(BaseModel):
    keys: dict


ALLOWED_SERVICES = {
    "virustotal", "abuseipdb", "shodan", "alienvault",
    "greynoise", "urlscan", "blacklistmaster", "abusech", "pulsedive", "ip2location"
}

VALID_ROLES = {"admin", "manager", "tech"}


def _normalize_notification_center(value: Optional[dict]) -> dict:
    payload = value if isinstance(value, dict) else {}
    preferences_raw = payload.get("preferences") if isinstance(payload.get("preferences"), dict) else {}

    def _normalize_ids(raw: object) -> list[str]:
        items = raw if isinstance(raw, list) else []
        normalized: list[str] = []
        for item in items:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
            if len(normalized) >= 500:
                break
        return normalized

    return {
        "read_ids": _normalize_ids(payload.get("read_ids")),
        "archived_ids": _normalize_ids(payload.get("archived_ids")),
        "preferences": {
            "critical": preferences_raw.get("critical", True) is not False,
            "system": preferences_raw.get("system", True) is not False,
            "intelligence": preferences_raw.get("intelligence", True) is not False,
        },
    }


@router.get("")
async def list_users(current_user: dict = Depends(require_role(["admin"]))):
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")
    users_cursor = db.users.find({}, {"password_hash": FIELD_EXCLUDED, "password_history": FIELD_EXCLUDED, "_id": FIELD_EXCLUDED})
    return await users_cursor.to_list(length=100)


@router.post("")
async def create_user(request: Request, user: UserCreate, current_user: dict = Depends(require_role(["admin"]))):
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    if await db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    normalized_email = normalize_email(user.email)
    if normalized_email:
        if not is_valid_email_format(normalized_email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        if await email_in_use(db, normalized_email):
            raise HTTPException(status_code=400, detail="Email already in use")

    if user.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role specified")

    policy = await get_password_policy(db)
    errors = validate_password(user.password, policy)
    if errors:
        raise HTTPException(status_code=400, detail=errors[0])

    password_hash = get_password_hash(user.password)
    new_user = {
        "username": user.username,
        "password_hash": password_hash,
        "role": user.role,
        "name": user.name,
        "email": normalized_email,
        "normalized_email": normalized_email,
        "preferred_lang": "pt",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "password_history": [password_hash],
        "password_changed_at": datetime.now(timezone.utc),
        "force_password_reset": PASSWORD_RESET_NOT_REQUIRED,
        "extra_permissions": [],
        "notification_center": _normalize_notification_center(None),
    }
    await db.users.insert_one(new_user)
    ip = request.client.host if request.client else ""
    await log_action(db, user=current_user["username"], action="user_created",
                     target=user.username, ip=ip, result="success",
                     detail=f"role={user.role}")
    return {"status": "success", "message": f"User {user.username} created successfully"}


@router.put("/me")
async def update_my_preferences(
    prefs: UserPreferencesUpdate,
    current_user: dict = Depends(get_current_user_allow_expired),
):
    """
    Update own preferences (language, avatar, password).
    Uses allow_expired so users with expired/force-reset passwords can still
    change their credentials.
    """
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    username = current_user["username"]
    update_data = {}
    provided_fields = getattr(prefs, "model_fields_set", set())

    if "preferred_lang" in provided_fields and prefs.preferred_lang is not None:
        update_data["preferred_lang"] = prefs.preferred_lang
    if "avatar_base64" in provided_fields:
        update_data["avatar_base64"] = prefs.avatar_base64
    if "avatar_fit" in provided_fields and prefs.avatar_fit is not None:
        update_data["avatar_fit"] = "contain" if prefs.avatar_fit == "contain" else "cover"
    if "bio" in provided_fields:
        update_data["bio"] = str(prefs.bio).strip()[:500] if prefs.bio is not None else None
    if "recovery_email" in provided_fields:
        normalized_recovery_email = normalize_email(prefs.recovery_email)
        if normalized_recovery_email and not is_valid_email_format(normalized_recovery_email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        if await any_contact_email_in_use(db, normalized_recovery_email, exclude_username=username):
            raise HTTPException(status_code=400, detail="Email already in use")
        update_data["recovery_email"] = normalized_recovery_email
        update_data["normalized_recovery_email"] = normalized_recovery_email
    if "notification_center" in provided_fields and prefs.notification_center is not None:
        update_data["notification_center"] = _normalize_notification_center(prefs.notification_center)

    password_changed = False
    if "password" in provided_fields and prefs.password is not None:
        policy = await get_password_policy(db)
        errors = validate_password(prefs.password, policy)
        if errors:
            raise HTTPException(status_code=400, detail=errors[0])

        # Check password history
        user_doc = await db.users.find_one({"username": username})
        history = user_doc.get("password_history", []) if user_doc else []
        history_count = policy.get("history_count", 5)
        for old_hash in history[-history_count:]:
            if verify_password(prefs.password, old_hash):
                raise HTTPException(
                    status_code=400,
                    detail="password_reuse_denied",
                )

        new_hash = get_password_hash(prefs.password)
        update_data["password_hash"] = new_hash
        update_data["password_changed_at"] = datetime.now(timezone.utc)
        update_data["force_password_reset"] = False

        # Append to history, keep only last history_count entries
        new_history = (history + [new_hash])[-history_count:]
        update_data["password_history"] = new_history
        password_changed = True

    if not update_data:
        return {"status": "success", "message": "No fields to update"}

    await db.users.update_one({"username": username}, {"$set": update_data})

    if password_changed:
        revoked_count = await revoke_user_refresh_tokens(db, username)
        await log_action(db, user=username, action="password_changed",
                         target=username, result="success",
                         detail=f"revoked_sessions={revoked_count}")

    return {"status": "success", "message": "Preferences updated successfully"}


@router.get("/me/audit-logs")
async def get_my_audit_logs(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
):
    """Returns the authenticated user's own audit log entries."""
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")
    items = await db.audit_log.find(
        {"user": current_user["username"]},
        {"_id": 0},
    ).sort("timestamp", -1).limit(limit).to_list(length=limit)
    for item in items:
        ts = item.get("timestamp")
        if hasattr(ts, "isoformat"):
            item["timestamp"] = ts.isoformat()
    return items


@router.get("/me/third-party-keys")
async def get_third_party_keys(current_user: dict = Depends(get_current_user)):
    """Returns which third-party services the user has configured (without exposing key values)."""
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")
    user_doc = await db.users.find_one({"username": current_user["username"]})
    stored = user_doc.get("third_party_keys", {}) if user_doc else {}
    return {
        svc: {"configured": svc in stored and bool(stored[svc])}
        for svc in ALLOWED_SERVICES
    }


@router.patch("/me/third-party-keys")
async def update_third_party_keys(
    request: Request,
    body: ThirdPartyKeysUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Save or update encrypted third-party API keys for the current user."""
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    invalid = set(body.keys.keys()) - ALLOWED_SERVICES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid services: {', '.join(invalid)}")

    user_doc = await db.users.find_one({"username": current_user["username"]})
    existing = user_doc.get("third_party_keys", {}) if user_doc else {}
    changed_services: list[str] = []
    configured_services: list[str] = []
    removed_services: list[str] = []

    for svc, value in body.keys.items():
        if value and value.strip():
            existing[svc] = encrypt_secret(value.strip())
            changed_services.append(svc)
            configured_services.append(svc)
        elif svc in existing:
            del existing[svc]
            changed_services.append(svc)
            removed_services.append(svc)

    await db.users.update_one(
        {"username": current_user["username"]},
        {"$set": {"third_party_keys": existing}}
    )
    ip = request.client.host if request.client else ""
    detail_parts = []
    if configured_services:
        detail_parts.append(f"configured={','.join(sorted(configured_services))}")
    if removed_services:
        detail_parts.append(f"removed={','.join(sorted(removed_services))}")
    detail_parts.append(f"changed={len(changed_services)}")
    await log_action(
        db,
        user=current_user["username"],
        action="third_party_keys_updated",
        target=current_user["username"],
        ip=ip,
        result="success",
        detail="; ".join(detail_parts),
    )
    return {"status": "success", "message": "Third-party keys updated"}


@router.delete("/{username}")
async def delete_user(request: Request, username: str, current_user: dict = Depends(require_role(["admin"]))):
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    if current_user["username"] == username:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    revoked_count = await revoke_user_refresh_tokens(db, username)
    result = await db.users.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    # LGPD erasure — purge the user's SOC Copilot data (provider keys, sessions,
    # history) in the plugin. Never blocks the delete if the plugin is down.
    socc_purged = await purge_user_socc_data(username)

    ip = request.client.host if request.client else ""
    await log_action(db, user=current_user["username"], action="user_deleted",
                     target=username, ip=ip, result="success",
                     detail=f"revoked_sessions={revoked_count}; socc_purged={socc_purged}")
    return {"status": "success", "message": f"User {username} deleted successfully"}


@router.put("/{username}")
async def update_user(
    request: Request,
    username: str,
    user_update: UserUpdate,
    current_user: dict = Depends(require_role(["admin"])),
):
    db = db_manager.db
    if db is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    existing = await db.users.find_one({"username": username})
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = {}
    revoke_sessions = False
    if user_update.name is not None:
        update_data["name"] = user_update.name
    if user_update.role is not None:
        if user_update.role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail="Invalid role specified")
        if (current_user["username"] == username
                and existing.get("role") == "admin"
                and user_update.role != "admin"):
            raise HTTPException(status_code=400, detail="You cannot demote your own admin account")
        update_data["role"] = user_update.role
        revoke_sessions = revoke_sessions or is_sensitive_role_downgrade(existing.get("role"), user_update.role)
    if user_update.password is not None:
        policy = await get_password_policy(db)
        errors = validate_password(user_update.password, policy)
        if errors:
            raise HTTPException(status_code=400, detail=errors[0])
        new_hash = get_password_hash(user_update.password)
        update_data["password_hash"] = new_hash
        update_data["password_changed_at"] = datetime.now(timezone.utc)
        update_data["force_password_reset"] = False
        history = existing.get("password_history", [])
        history_count = policy.get("history_count", 5)
        update_data["password_history"] = (history + [new_hash])[-history_count:]
        revoke_sessions = True
    if user_update.is_active is not None:
        if current_user["username"] == username and user_update.is_active is False:
            raise HTTPException(status_code=400, detail="You cannot suspend your own account")
        update_data["is_active"] = user_update.is_active
        if user_update.is_active is False:
            revoke_sessions = True
            reason = (user_update.suspension_reason or "").strip()
            if reason:
                update_data["suspension_reason"] = reason[:500]
            else:
                update_data["suspension_reason"] = None
            update_data["suspended_at"] = datetime.now(timezone.utc)
            update_data["suspended_by"] = current_user["username"]
        else:
            update_data["suspension_reason"] = None
            update_data["suspended_at"] = None
            update_data["suspended_by"] = None
    if user_update.force_password_reset is not None:
        update_data["force_password_reset"] = user_update.force_password_reset
        if user_update.force_password_reset is True:
            revoke_sessions = True
    if user_update.email is not None:
        normalized_email = normalize_email(user_update.email)
        if normalized_email and not is_valid_email_format(normalized_email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        if await email_in_use(db, normalized_email, exclude_username=username):
            raise HTTPException(status_code=400, detail="Email already in use")
        update_data["email"] = normalized_email
        update_data["normalized_email"] = normalized_email
    if user_update.allowed_ips is not None:
        # Validate each entry as IP, CIDR, or IPv6
        validated = []
        for entry in user_update.allowed_ips:
            entry = entry.strip()
            if not entry:
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
                validated.append(entry)
            except ValueError:
                try:
                    ipaddress.ip_address(entry)
                    validated.append(entry)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid IP/CIDR: {entry}")
        update_data["allowed_ips"] = validated

    if not update_data:
        return {"status": "success", "message": "No fields to update"}

    await db.users.update_one({"username": username}, {"$set": update_data})
    revoked_count = await revoke_user_refresh_tokens(db, username) if revoke_sessions else 0

    # LGPD erasure on deactivation — a suspended user's stored provider keys and
    # chat data should not linger. Purge the plugin's socc data for this user.
    socc_purged = None
    if update_data.get("is_active") is False:
        socc_purged = await purge_user_socc_data(username)

    ip = request.client.host if request.client else ""
    # Emit granular audit events
    if "role" in update_data:
        await log_action(db, user=current_user["username"], action="role_changed",
                         target=username, ip=ip, result="success",
                         detail=f"new_role={update_data['role']}; revoked_sessions={revoked_count}")
    if update_data.get("force_password_reset") is True:
        await log_action(db, user=current_user["username"], action="password_reset_forced",
                         target=username, ip=ip, result="success",
                         detail=f"revoked_sessions={revoked_count}")
    if "is_active" in update_data:
        action_name = "user_reactivated" if update_data["is_active"] else "user_suspended"
        detail = f"revoked_sessions={revoked_count}"
        if update_data["is_active"] is False:
            detail += f"; socc_purged={socc_purged}"
            if update_data.get("suspension_reason"):
                detail += f"; reason={update_data['suspension_reason']}"
        await log_action(db, user=current_user["username"], action=action_name,
                         target=username, ip=ip, result="success",
                         detail=detail)
    else:
        await log_action(db, user=current_user["username"], action="user_updated",
                         target=username, ip=ip, result="success",
                         detail=f"revoked_sessions={revoked_count}")

    return {"status": "success", "message": f"User {username} updated successfully"}
