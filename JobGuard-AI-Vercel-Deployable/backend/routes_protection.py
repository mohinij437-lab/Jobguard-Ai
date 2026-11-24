"""Call Guard, Fraud Intelligence, and Community Scam Database API routes."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .call_analyzer import (
    MAX_AUDIO_BYTES,
    analyze_call_recording_or_transcript,
    attempt_server_transcription,
    extract_audio_metadata,
    validate_audio_upload,
)
from .fraud_intelligence import (
    analyze_audio_metadata,
    analyze_text as analyze_fraud_text,
    search_community,
    submit_community_report,
)
from .security import sanitize_plain_text

router = APIRouter()


class CallTranscriptRequest(BaseModel):
    transcript: str = Field(..., min_length=3, max_length=25000)
    language_hint: str = Field(default="auto")
    interface_language: str = Field(default="en")
    redact_sensitive: bool = Field(default=True)
    is_demo: bool = Field(default=False)


class FraudTextRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=25000)
    input_type: str = Field(default="message", max_length=40)


class CommunityReportRequest(BaseModel):
    indicator: str = Field(..., min_length=3, max_length=2048)
    report_type: str = Field(..., min_length=2, max_length=40)
    description: str = Field(default="", max_length=500)


async def read_bounded_upload(file: UploadFile, max_bytes: int) -> bytes:
    """Read uploaded file with a hard memory ceiling to prevent memory exhaustion DoS."""
    chunks: list[bytes] = []
    total = 0
    chunk_size = 256 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MB).",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/call/analyze-transcript")
async def analyze_call_transcript_endpoint(payload: CallTranscriptRequest) -> Dict[str, Any]:
    """Analyze a call transcript directly across multiple languages."""
    return analyze_call_recording_or_transcript(
        transcript=sanitize_plain_text(payload.transcript),
        language_hint=payload.language_hint,
        interface_language=payload.interface_language,
        redact_sensitive=payload.redact_sensitive,
        is_demo=payload.is_demo,
    )


@router.post("/api/fraud/intelligence")
async def fraud_intelligence_endpoint(payload: FraudTextRequest) -> Dict[str, Any]:
    """Analyze UPI/payment text, QR payloads, screenshot OCR text, or suspicious messages."""
    clean = sanitize_plain_text(payload.text)
    if not clean:
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")
    return analyze_fraud_text(clean, payload.input_type)


@router.post("/api/fraud/audio-assessment")
async def audio_assessment_endpoint(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Inspect uploaded audio metadata transparently without fabricated deepfake percentages."""
    raw = await read_bounded_upload(file, MAX_AUDIO_BYTES)
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded audio file is empty.")
    return analyze_audio_metadata(file.filename or "audio.wav", len(raw))


@router.post("/api/community/report")
async def community_report_endpoint(payload: CommunityReportRequest) -> Dict[str, Any]:
    """Record a user-submitted scam indicator into the community directory."""
    try:
        return submit_community_report(payload.indicator, payload.report_type, payload.description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/community/search")
async def community_search_endpoint(q: str = "") -> Dict[str, Any]:
    return {"reports": search_community(q)}


@router.post("/api/call/analyze")
async def analyze_call_recording_endpoint(
    file: UploadFile | None = File(default=None),
    transcript: str = Form(default=""),
    language_hint: str = Form(default="auto"),
    interface_language: str = Form(default="en"),
    redact_sensitive: bool = Form(default=True),
    is_demo: bool = Form(default=False),
) -> Dict[str, Any]:
    """Upload a call recording (WAV/MP3/M4A/OGG/WEBM) and/or transcript for multilingual scam detection."""
    audio_meta: Dict[str, Any] | None = None
    stt_status = "User / Browser Provided"
    stt_provider = "user_or_browser_stt"
    effective_transcript = sanitize_plain_text(transcript) if transcript else ""

    if file is not None and file.filename:
        raw = await read_bounded_upload(file, MAX_AUDIO_BYTES)
        ok, err_or_ext = validate_audio_upload(file.filename, len(raw))
        if not ok:
            raise HTTPException(status_code=400, detail=err_or_ext)
        audio_meta = extract_audio_metadata(file.filename, raw)
        if not effective_transcript:
            stt_text, stt_status, stt_provider = attempt_server_transcription(
                file.filename, raw, language_hint=language_hint
            )
            effective_transcript = sanitize_plain_text(stt_text or "")

    if not audio_meta and not effective_transcript:
        raise HTTPException(
            status_code=400,
            detail="Please upload a call recording audio file or provide a call transcript.",
        )

    return analyze_call_recording_or_transcript(
        transcript=effective_transcript,
        audio_metadata=audio_meta,
        transcription_status=stt_status,
        transcription_provider=stt_provider,
        language_hint=language_hint,
        interface_language=interface_language,
        redact_sensitive=redact_sensitive,
        is_demo=is_demo,
    )
