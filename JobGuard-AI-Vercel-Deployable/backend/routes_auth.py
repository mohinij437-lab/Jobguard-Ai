"""Authentication, session management, and isolated Evidence Locker API routes."""
from __future__ import annotations

import os
import re
import json
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, Optional

from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from .auth import (
    SESSION_SECONDS,
    authenticate,
    change_password,
    create_user,
    delete_user,
    delete_user_report,
    get_user_id_by_email,
    get_user_reports,
    get_user_report_by_id,
    issue_auth_token,
    reset_password,
    revoke_other_sessions,
    revoke_session,
    save_user_report,
    update_profile,
    validate_session,
    verify_email,
)

router = APIRouter()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UPPER_RE = re.compile(r"[A-Z]")
_DIGIT_RE = re.compile(r"[0-9]")


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=254)
    mobile: str = Field(default="", max_length=20)
    password: str = Field(..., min_length=10, max_length=128)
    terms_accepted: bool


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)
    remember_me: bool = False


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    mobile: str = Field(default="", max_length=20)
    notifications: bool = True


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=10, max_length=128)


class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class PasswordResetConfirmRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=300)
    new_password: str = Field(..., min_length=10, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=300)


class SaveReportRequest(BaseModel):
    report: Dict[str, Any]
    report_id: Optional[str] = None


def _cookie_secure() -> bool:
    default_secure = (
        "true"
        if (os.getenv("ENVIRONMENT", "").lower() == "production" or os.getenv("VERCEL") == "1")
        else "false"
    )
    return os.getenv("COOKIE_SECURE", default_secure).lower() == "true"


def _app_base_url() -> str:
    explicit = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
    if explicit:
        return explicit
    vercel_host = (
        os.getenv("VERCEL_PROJECT_PRODUCTION_URL", "").strip()
        or os.getenv("VERCEL_URL", "").strip()
    ).rstrip("/")
    if vercel_host:
        return vercel_host if vercel_host.startswith(("http://", "https://")) else f"https://{vercel_host}"
    return ""


def _send_email(to_email: str, subject: str, text: str) -> tuple[bool, str]:
    host = os.getenv("SMTP_HOST", "").strip()
    from_email = os.getenv("SMTP_FROM", "").strip()
    if not host or not from_email:
        return False, "Email delivery is not configured."
    try:
        message = EmailMessage()
        message["From"] = from_email
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(text)
        port = int(os.getenv("SMTP_PORT", "587"))
        username = os.getenv("SMTP_USERNAME", "").strip()
        password = os.getenv("SMTP_PASSWORD", "")
        use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
        smtp = smtplib.SMTP_SSL(host, port, timeout=10) if use_ssl else smtplib.SMTP(host, port, timeout=10)
        with smtp:
            if not use_ssl:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
        return True, "Email sent."
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        return False, f"Email delivery failed: {type(exc).__name__}"


def _validate_password_strength(password: str, prefix: str = "Password") -> None:
    if len(set(password)) < 4 or not _UPPER_RE.search(password) or not _DIGIT_RE.search(password):
        raise HTTPException(
            status_code=400,
            detail=f"{prefix} must include uppercase letters, numbers, and varied characters.",
        )


def _require_session(jg_session: Optional[str]) -> Dict[str, Any]:
    if not jg_session:
        raise HTTPException(status_code=401, detail="Authentication required.")
    user = validate_session(jg_session)
    if not user:
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    return user


@router.post("/api/auth/register")
async def register_endpoint(payload: RegisterRequest, response: Response) -> Dict[str, Any]:
    if not payload.terms_accepted:
        raise HTTPException(status_code=400, detail="Accept the terms and privacy policy to continue.")
    if not _EMAIL_RE.match(payload.email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    _validate_password_strength(payload.password, "Password")
    try:
        user = create_user(payload.full_name, payload.email, payload.mobile, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    token = issue_auth_token(user["id"], "session", SESSION_SECONDS)
    response.set_cookie(
        "jg_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        max_age=SESSION_SECONDS,
        path="/",
    )
    verif_tok = issue_auth_token(user["id"], "email_verify", 60 * 60 * 24)
    base_url = _app_base_url()
    delivery_available = bool(
        base_url
        and os.getenv("SMTP_HOST", "").strip()
        and os.getenv("SMTP_FROM", "").strip()
    )
    delivery_succeeded = False
    if base_url:
        delivery_succeeded, _ = _send_email(
            user["email"],
            "Verify your JobGuard AI account",
            f"Verify your account using this secure link:\n{base_url}/?verify_email={verif_tok}\n",
        )
    return {
        "user": user,
        "email_verification": {
            "available": delivery_succeeded,
            "delivery_available": delivery_available,
            "message": "Verification instructions sent." if delivery_succeeded else (
                "Email delivery is not configured. Account verification cannot be completed until email delivery is configured."
                if not delivery_available else "Verification email delivery failed."
            ),
        },
    }


@router.post("/api/auth/login")
async def login_endpoint(payload: LoginRequest, response: Response) -> Dict[str, Any]:
    user = authenticate(payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    lifetime = SESSION_SECONDS * 30 if payload.remember_me else SESSION_SECONDS
    token = issue_auth_token(user["id"], "session", lifetime)
    response.set_cookie(
        "jg_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        max_age=lifetime,
        path="/",
    )
    return {"user": user}


@router.post("/api/auth/logout")
async def logout_endpoint(
    response: Response,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    if jg_session:
        revoke_session(jg_session)
    response.delete_cookie("jg_session", path="/")
    return {"logged_out": True}


@router.get("/api/auth/me")
async def auth_me_endpoint(jg_session: Optional[str] = Cookie(default=None)) -> Dict[str, Any]:
    return {"user": _require_session(jg_session)}


@router.patch("/api/auth/profile")
async def update_profile_endpoint(
    payload: ProfileUpdateRequest,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    updated = update_profile(user["id"], payload.full_name, payload.mobile, payload.notifications)
    return {"user": updated}


@router.post("/api/auth/password")
async def password_change_endpoint(
    payload: PasswordChangeRequest,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    _validate_password_strength(payload.new_password, "New password")
    if not change_password(user["id"], payload.current_password, payload.new_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    if jg_session:
        revoke_other_sessions(user["id"], jg_session)
    return {"changed": True}


@router.post("/api/auth/forgot-password")
async def forgot_password_endpoint(payload: PasswordResetRequest) -> Dict[str, Any]:
    user_id = get_user_id_by_email(payload.email)
    delivery_available = bool(
        os.getenv("SMTP_HOST", "").strip()
        and os.getenv("SMTP_FROM", "").strip()
        and _app_base_url()
    )
    if user_id and delivery_available:
        reset_token = issue_auth_token(user_id, "password_reset", 60 * 60)
        base_url = _app_base_url()
        _send_email(
            payload.email.strip().lower(),
            "Reset your JobGuard AI password",
            f"Use this secure one-time link to reset your password:\n{base_url}/?reset_password={reset_token}\n",
        )
    return {
        "message": (
            "If an account exists for that email, password reset instructions are available."
            if delivery_available
            else "Password recovery is unavailable because email delivery is not configured."
        ),
        "delivery_available": delivery_available,
    }


@router.post("/api/auth/reset-password")
async def reset_password_endpoint(payload: PasswordResetConfirmRequest) -> Dict[str, Any]:
    _validate_password_strength(payload.new_password, "Password")
    if not reset_password(payload.token, payload.new_password):
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired.")
    return {"reset": True}


@router.post("/api/auth/verify-email")
async def verify_email_endpoint(
    payload: Optional[VerifyEmailRequest] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    effective_token = (payload.token if payload else token) or ""
    if not effective_token or not verify_email(effective_token):
        raise HTTPException(status_code=400, detail="Verification token is invalid or expired.")
    return {"verified": True}


@router.post("/api/reports/save")
async def save_report_endpoint(
    payload: SaveReportRequest,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    serialized_size = len(json.dumps(payload.report, ensure_ascii=False).encode("utf-8"))
    if serialized_size > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Saved report exceeds the 2 MB maximum.")
    try:
        saved = save_user_report(user["id"], payload.report, payload.report_id)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"saved": True, "item": saved}


@router.get("/api/reports")
async def get_reports_endpoint(
    limit: int = 50,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    reports = get_user_reports(user["id"], limit=min(100, max(1, limit)))
    return {"reports": reports}


@router.get("/api/reports/{report_id}")
async def get_report_endpoint(
    report_id: str,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    report = get_user_report_by_id(user["id"], report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found or access denied.")
    return {"item": report}


@router.delete("/api/reports/{report_id}")
async def delete_report_endpoint(
    report_id: str,
    jg_session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    deleted = delete_user_report(user["id"], report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found or access denied.")
    return {"deleted": True, "report_id": report_id}


@router.delete("/api/auth/account")
async def delete_account_endpoint(
    jg_session: Optional[str] = Cookie(default=None),
    response: Response = None,
) -> Dict[str, Any]:
    user = _require_session(jg_session)
    delete_user(user["id"])
    if response:
        response.delete_cookie("jg_session", path="/")
    return {"deleted": True}
