"""JobGuard AI FastAPI Backend Application.

Hardened for high efficiency (GZip compression, bounded streaming uploads, LRU-cached structural checks)
and defense-in-depth security (explicit CORS allowlist, strict security headers, rate limiting).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .auth import init_auth_database
from .evidence_engine import build_verification_report
from .extractor import extract_structured_job_data, extract_text_from_document_bytes
from .ml_classifier import get_ml_metadata
from .providers import close_http_client, get_provider_status_summary
from .routes_auth import router as auth_router
from .routes_protection import read_bounded_upload, router as protection_router
from .schemas import (
    DocumentExtractionResponse,
    ExtractedJobData,
    ExtractRequest,
    URLInspectionResult,
    URLInspectRequest,
    VerificationReport,
    VerifyRequest,
)
from .security import (
    MAX_UPLOAD_BYTES,
    InMemoryRateLimiter,
    redact_sensitive_info,
    sanitize_plain_text,
    validate_upload_file,
)
from .url_inspector import inspect_url_structurally

logger = logging.getLogger("jobguard")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    init_auth_database()
    yield
    await close_http_client()


app = FastAPI(
    lifespan=_lifespan,
    title="JobGuard AI — Evidence-Based Job & Recruitment Verification API",
    description="Before You Trust the Offer, Verify the Evidence.",
    version="1.2.0",
)

# Explicit safe default CORS origins (never wildcard '*' by default)
default_origins = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"
configured_origins = os.getenv("CORS_ORIGINS")
if configured_origins is None and (
    os.getenv("ENVIRONMENT", "").lower() == "production" or os.getenv("VERCEL") == "1"
):
    allowed_origins: list[str] = []
else:
    allowed_origins = [
        o.strip().rstrip("/")
        for o in (configured_origins or default_origins).split(",")
        if o.strip()
    ]

for _env_key in ("VERCEL_URL", "VERCEL_BRANCH_URL", "VERCEL_PROJECT_PRODUCTION_URL"):
    _host = os.getenv(_env_key, "").strip().rstrip("/")
    if _host:
        _origin = _host if _host.startswith(("http://", "https://")) else f"https://{_host}"
        if _origin not in allowed_origins:
            allowed_origins.append(_origin)

_app_base_origin = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
if _app_base_origin and _app_base_origin not in allowed_origins:
    allowed_origins.append(_app_base_origin)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization"],
)

rate_limiter = InMemoryRateLimiter(max_requests=120, window_seconds=60)
auth_rate_limiter = InMemoryRateLimiter(max_requests=30, window_seconds=60)
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
app.include_router(auth_router)
app.include_router(protection_router)


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    client_ip = forwarded_for or (request.client.host if request.client else "local")
    if request.url.path.startswith("/api/"):
        allowed, retry_after = rate_limiter.allow(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                headers={"Retry-After": str(retry_after)},
            )
    if request.method in {"POST", "PATCH", "DELETE"} and request.url.path.startswith("/api/auth/"):
        allowed, retry_after = auth_rate_limiter.allow(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Authentication rate limit exceeded. Retry after {retry_after}s."},
                headers={"Retry-After": str(retry_after)},
            )
    if request.method in {"POST", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin:
            origin = origin.rstrip("/")
            fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
            fwd_host = (
                request.headers.get("x-forwarded-host", "").split(",")[0].strip()
                or request.headers.get("host", "").strip()
            )
            scheme = fwd_proto or request.url.scheme
            netloc = fwd_host or request.url.netloc
            same_origin = f"{scheme}://{netloc}".rstrip("/")
            raw_same_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
            if origin not in {same_origin, raw_same_origin} and origin not in allowed_origins:
                return JSONResponse(status_code=403, content={"detail": "Origin is not allowed."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), payment=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


@app.get("/api/health")
async def health_check() -> Dict[str, object]:
    return {
        "status": "ok",
        "service": "JobGuard AI",
        "version": "1.2.0",
        "tagline": "Before You Trust the Offer, Verify the Evidence.",
        "local_mode_ready": True,
        "call_scam_detection": True,
        "providers": get_provider_status_summary(),
    }


@app.get("/api/providers/status")
async def providers_status() -> Dict[str, object]:
    return {
        "providers": get_provider_status_summary(),
        "note": "All external providers are optional. Core verification runs locally without API keys.",
    }


@app.get("/api/ml/info")
async def ml_info() -> Dict[str, object]:
    return get_ml_metadata()


@app.post("/api/extract", response_model=ExtractedJobData)
async def extract_fields_endpoint(payload: ExtractRequest) -> ExtractedJobData:
    clean_text = sanitize_plain_text(payload.text)
    if not clean_text and not (payload.job_url and payload.job_url.strip()):
        raise HTTPException(status_code=400, detail="Provide job text or a job URL to extract fields.")
    return extract_structured_job_data(
        clean_text, job_url=payload.job_url, language_hint=payload.language_hint
    )


@app.post("/api/extract/document", response_model=DocumentExtractionResponse)
async def extract_document_endpoint(file: UploadFile = File(...)) -> DocumentExtractionResponse:
    content = await read_bounded_upload(file, MAX_UPLOAD_BYTES)
    valid, result = validate_upload_file(file.filename or "", len(content), content)
    if not valid:
        raise HTTPException(status_code=400, detail=result)

    try:
        raw_text, file_type, warnings = extract_text_from_document_bytes(
            file.filename or "upload.txt", content
        )
    except ValueError as exc:
        logger.warning("Document extraction failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    clean_text = sanitize_plain_text(raw_text)
    redacted_text, redaction_counts = redact_sensitive_info(clean_text)
    extracted = extract_structured_job_data(clean_text)

    return DocumentExtractionResponse(
        filename=file.filename or "document",
        file_type=file_type,
        extracted_text=clean_text,
        redacted_text=redacted_text,
        redaction_counts=redaction_counts,
        warnings=warnings,
        extracted_fields=extracted,
    )


@app.post("/api/inspect-url", response_model=URLInspectionResult)
async def inspect_url_endpoint(payload: URLInspectRequest) -> URLInspectionResult:
    return inspect_url_structurally(payload.url)


@app.post("/api/verify", response_model=VerificationReport)
async def verify_job_endpoint(payload: VerifyRequest) -> VerificationReport:
    if not (payload.text and payload.text.strip()) and not (payload.job_url and payload.job_url.strip()):
        raise HTTPException(
            status_code=400,
            detail="Please provide job advertisement text, recruiter message, or a job URL to verify.",
        )
    return await build_verification_report(payload)


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return FileResponse(index_path, headers={"Cache-Control": "no-cache"})
    return HTMLResponse(
        "<h1>JobGuard AI Backend Running</h1><p>API docs available at <a href='/docs'>/docs</a>.</p>"
    )


@app.get("/assets/{asset_name}")
async def serve_vite_asset(asset_name: str):
    asset_path = (FRONTEND_DIST / "assets" / asset_name).resolve()
    assets_dir = (FRONTEND_DIST / "assets").resolve()
    if assets_dir not in asset_path.parents:
        raise HTTPException(status_code=404, detail="Not found")
    if not asset_path.exists():
        raise HTTPException(status_code=404, detail="Asset not found")
    media_type = "text/css" if asset_name.endswith(".css") else "application/javascript"
    return FileResponse(asset_path, media_type=media_type, headers={"Cache-Control": "public, max-age=31536000, immutable"})


ALLOWED_STATIC_ASSETS = {
    "styles.css": "text/css",
    "data.js": "application/javascript",
    "engine.js": "application/javascript",
    "app.js": "application/javascript",
}


@app.get("/{asset_name}")
async def serve_static_asset(asset_name: str):
    media_type = ALLOWED_STATIC_ASSETS.get(asset_name)
    if not media_type:
        raise HTTPException(status_code=404, detail="Not found")
    asset_path = FRONTEND_DIST / asset_name
    if asset_path.exists():
        return FileResponse(asset_path, media_type=media_type, headers={"Cache-Control": "public, max-age=3600"})
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        if asset_name == "app.js":
            for js_f in sorted(assets_dir.glob("*.js"), key=lambda p: p.stat().st_size, reverse=True):
                return FileResponse(js_f, media_type=media_type, headers={"Cache-Control": "public, max-age=3600"})
        elif asset_name == "styles.css":
            for css_f in sorted(assets_dir.glob("*.css"), key=lambda p: p.stat().st_size, reverse=True):
                return FileResponse(css_f, media_type=media_type, headers={"Cache-Control": "public, max-age=3600"})
    raise HTTPException(status_code=404, detail=f"{asset_name} not found")
