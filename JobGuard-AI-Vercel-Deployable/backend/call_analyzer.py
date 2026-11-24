"""Multilingual Call Recording Scam Detection Engine (Audio Metadata + Optional STT + Voice-Scam Analysis).

All regexes are precompiled at module import, language detection is LRU-cached,
and analysis is decomposed into focused helper functions for maintainability and speed.
"""
from __future__ import annotations

import io
import logging
import os
import re
import uuid
import wave
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from .schemas import DetectionIndicator, EvidenceStatus, RiskLevel, Severity
from .security import redact_sensitive_info, sanitize_plain_text
from .url_inspector import extract_urls_from_text, inspect_url_structurally

logger = logging.getLogger("jobguard.call_analyzer")

ALLOWED_AUDIO_EXTENSIONS = frozenset({".wav", ".mp3", ".m4a", ".ogg", ".webm", ".aac", ".flac"})
MAX_AUDIO_BYTES = 25 * 1024 * 1024  # 25 MB

UPI_ID_RE = re.compile(r"\b[a-zA-Z0-9._-]{2,}@(?:upi|ybl|okaxis|okicici|okhdfcbank|oksbi|paytm|ibl|axl|apl)\b", re.I)
AMOUNT_RE = re.compile(r"(?:₹|Rs\.?|INR|\$|€|EUR|USD)\s*\d[\d,]*(?:\.\d+)?|\b\d[\d,]*\s*(?:rupees|rs|inr|dollars|euros|रुपये|रुपए|रुपया)\b", re.I)
PHONE_RE = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|\+\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{3,4}\b")
ORG_CALLER_RE = re.compile(
    r"(?i)(?:calling\s+from|speaking\s+from|from\s+the\s+|this\s+is\s+[A-Z][a-z]+\s+from\s+|मैं\s+|कंपनी\s*[:\-]\s*)"
    r"([A-Za-z\u0900-\u097F][A-Za-z0-9\u0900-\u097F&.\- ]{2,45}?)(?=\s*(?:\.|,|and|regarding|about|hr|team|se\s+bol|से\s+बोल|$))"
)

# Precompiled script/language detection regexes
SCRIPT_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("ta", re.compile(r"[\u0B80-\u0BFF]")),
    ("te", re.compile(r"[\u0C00-\u0C7F]")),
    ("bn", re.compile(r"[\u0980-\u09FF]")),
    ("gu", re.compile(r"[\u0A80-\u0AFF]")),
    ("kn", re.compile(r"[\u0C80-\u0CFF]")),
)
DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
MARATHI_RE = re.compile(r"नोंदणी|सांगा|तुमचे|पैसे\s+पाठवा|नोकरीसाठी|काढू\s+नका")
SPANISH_CALL_RE = re.compile(r"\b(?:hola|tarifa\s+de\s+registro|dep[oó]sito\s+de\s+seguridad|c[oó]digo\s+otp|no\s+cuelgues|trabajo\s+sin\s+entrevista|cuenta\s+bancaria|enviar\s+dinero)\b", re.I)
FRENCH_CALL_RE = re.compile(r"\b(?:bonjour|frais\s+d'inscription|d[eé]p[oô]t\s+de\s+garantie|code\s+otp|ne\s+raccrochez\s+pas|sans\s+entretien|compte\s+bancaire)\b", re.I)
HINGLISH_CALL_RE = re.compile(r"\b(?:aapka|aapke|batao|bataiye|karo|karein|turant|bhejo|bhej|rupaye|jama|paisa|naukri|phone\s+mat\s+katna|kisi\s+ko\s+mat\s+batana|pehle|fees)\b", re.I)

LANGUAGE_LABELS: Dict[str, str] = {
    "en": "English", "hi": "Hindi (हिंदी)", "hinglish": "Hinglish (Hindi + English)",
    "ta": "Tamil (தமிழ்)", "te": "Telugu (తెలుగు)", "bn": "Bengali (বাংলা)",
    "mr": "Marathi (मराठी)", "gu": "Gujarati (ગુજરાતી)", "kn": "Kannada (ಕನ್ನಡ)",
    "es": "Spanish (Español)", "fr": "French (Français)",
}

NEGATION_RE = re.compile(
    r"(?i)(?:never|do\s+not|don't|does\s+not|doesn't|no\s+need\s+to|we\s+will\s+not|zero|"
    r"कभी\s+नहीं|न\s+दें|नहीं\s+मांग|मत\s+बताना|nunca|ne\s+jamais)\s*(?:pay|charge|share|tell|ask|send|install)?\s*$"
)
CALL_DISCLAIMER_RE = re.compile(
    r"(?i)(?:never\s+(?:share|tell|pay)\s+(?:your\s+)?(?:otp|upi\s+pin|registration\s+fee|security\s+deposit)|"
    r"we\s+do\s+not\s+charge\s+any\s+fee|no\s+fee\s+is\s+charged|"
    r"हम\s+कोई\s+फीस\s+नहीं\s+लेते|ओटीपी\s+किसी\s+को\s+न\s+बताएं)"
)


@dataclass(frozen=True)
class CallScamRule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    explanation: str
    reason_it_matters: str
    suggested_action: str


CALL_SCAM_RULES: Tuple[CallScamRule, ...] = (
    CallScamRule(
        "call_otp_pin_theft", "Live Call OTP / UPI PIN / Banking Credential Theft", Severity.CRITICAL,
        re.compile(
            r"(?i)\b(?:(?:read|tell|share|give|dictate|send|batao|bataiye)\s+(?:me\s+)?(?:the\s+|your\s+|apna\s+)?(?:6[\s-]digit\s+)?(?:otp|upi\s+pin|atm\s+pin|cvv|mpin|verification\s+code|bank\s+password)|"
            r"(?:otp|upi\s+pin|atm\s+pin|cvv)\s+(?:batao|bataiye|share\s+karo|de\s+do)|"
            r"(?:dame|dime|env[ií]a)\s+(?:el\s+|tu\s+)?(?:c[oó]digo\s+otp|pin|contrase[nñ]a)|"
            r"(?:donnez|dites|envoyez)[\s-](?:moi\s+)?(?:le\s+|votre\s+)?(?:code\s+otp|code\s+pin|mot\s+de\s+passe))\b|"
            r"(?:ओटीपी|यूपीआई\s+पिन|एटीएम\s+पिन|पासवर्ड)\s*(?:बताइए|बताओ|शेयर\s+करें|सांगा|द्या)|"
            r"ஓடிபி|யுபிஐ\s*பின்|ఓటీపీ|యూపీఐ\s*పిన్|ওটিপি|ইউপিআই\s*পিন|ઓટીપી|ಒಟಿಪಿ"
        ),
        "Caller asks you to read out or share an OTP, UPI PIN, ATM PIN, CVV, or banking password during the phone call.",
        "No legitimate HR department, bank, or government officer will ever ask for an OTP or UPI PIN over a call.",
        "Hang up immediately. Never read out SMS codes or enter your UPI PIN while on a call.",
    ),
    CallScamRule(
        "call_advance_job_fee", "Recruitment Advance Fee / Security Deposit Demand on Call", Severity.CRITICAL,
        re.compile(
            r"(?i)\b(?:(?:pay|transfer|send|deposit|jama\s+karo|bhejo)\s+(?:a\s+|the\s+)?(?:₹|Rs\.?|INR|\$|€)?\s*\d[\d,]*\s*(?:only\s+)?(?:refundable\s+)?(?:registration|processing|interview|verification|joining|security|laptop|kit)\s*(?:fee|fees|deposit|charge)|"
            r"(?:registration\s+fee|security\s+deposit|processing\s+fee|laptop\s+deposit)\s*(?:of\s+(?:₹|Rs\.?|\$|€)?\s*\d+|jama\s+karo|bhejo|dena\s+hoga|on\s+upi)|"
            r"tarifa\s+de\s+registro|dep[oó]sito\s+de\s+seguridad|frais\s+d'inscription|d[eé]p[oô]t\s+de\s+garantie)\b|"
            r"(?:रजिस्ट्रेशन\s+फीस|सिक्योरिटी\s+डिपॉजिट|प्रोसेसिंग\s+फीस|नोंदणी\s+शुल्क|सुरक्षा\s+ठेव)|"
            r"ரெஜிஸ்ட்ரேஷன்\s*கட்டணம்|பாதுகாப்பு\s*வைப்பு|రిజిస్ట్రేషన్\s*ఫీజు|సెక్యూరిటీ\s*డిపాజిట్|রেজিস্ট্রেশন\s*ফি|সিকিউরিটি\s*ডিপোজিট|રજીસ્ટ્રેશન\s*ફી|ರಿಜಿಸ್ಟ್ರೇಷನ್\s*ಶುಲ್ಕ"
        ),
        "Caller demands an advance registration fee, security deposit, laptop deposit, or processing payment.",
        "Legitimate employers never ask candidates to transfer money or UPI deposits during a recruitment call.",
        "End the call immediately and do not transfer any money to personal UPI IDs or accounts.",
    ),
    CallScamRule(
        "call_remote_access", "Remote-Access Screen Takeover (AnyDesk / TeamViewer)", Severity.CRITICAL,
        re.compile(r"(?i)\b(?:install|download|open)\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer)|\b(?:anydesk|teamviewer|quicksupport|rustdesk)\b.{0,45}\b(?:code|number|id|screen|verify|onboarding|refund|salary|batao|बताइए)\b"),
        "Caller instructs you to install AnyDesk, TeamViewer, or QuickSupport and share your workspace code.",
        "Remote-access apps give scammers live control of your phone or laptop to read OTPs and drain bank accounts.",
        "Refuse to install remote-access software. Disconnect from the internet and uninstall it immediately if already installed.",
    ),
    CallScamRule(
        "call_digital_arrest_authority", "Authority Impersonation / 'Digital Arrest' Coercion", Severity.CRITICAL,
        re.compile(r"(?i)\b(?:digital\s+arrest|cbi\s+(?:officer|cyber)|customs\s+(?:seized|parcel)|illegal\s+parcel\s+in\s+your\s+(?:aadhaar|name)|arrest\s+warrant\s+(?:issued|against\s+you)|money\s+laundering\s+case\s+registered|stay\s+on\s+(?:this\s+)?(?:video\s+)?call\s+(?:for\s+verification|until\s+clearance))\b|डिजिटल\s+अरेस्ट|अवैध\s+पार्सल|गिरफ्तारी\s+वारंट|पुलिस\s+केस\s+दर्ज|सीबीआई\s+अधिकारी|டிஜிட்டல்\s*அரெஸ்ட்|డిజిటల్\s*అరెస్ట్|ডিজিটাল\s*অ্যারেস্ট"),
        "Caller impersonates Police, CBI, Customs, or RBI and threatens 'Digital Arrest' or legal action.",
        "'Digital Arrest' does not exist in Indian law—law enforcement never conducts arrests over phone/video calls.",
        "Disconnect immediately. Never transfer 'verification funds'. Report the number on 1930 / cybercrime.gov.in.",
    ),
    CallScamRule(
        "call_isolation_secrecy_pressure", "Call Isolation & Secrecy Pressure Tactic", Severity.HIGH,
        re.compile(r"(?i)\b(?:do\s+not\s+(?:hang\s+up|disconnect\s+(?:the\s+)?call|tell\s+(?:anyone|your\s+family|parents))|don't\s+(?:hang\s+up|disconnect|tell\s+anyone)|stay\s+on\s+the\s+line\s+(?:and\s+)?(?:pay|transfer)|phone\s+mat\s+katna|call\s+mat\s+kaatna|kisi\s+ko\s+mat\s+batana|no\s+cuelgues|no\s+le\s+digas\s+a\s+nadie|ne\s+raccrochez\s+pas|n'en\s+parlez\s+[àa]\s+personne)\b|फोन\s+मत\s+काटना|कॉल\s+मत\s+काटिए|किसी\s+को\s+मत\s+बताना|फोन\s+ठेवू\s+नका"),
        "Caller pressures you not to hang up or not to tell family members while completing a payment or sharing codes.",
        "Keeping victims isolated prevents them from pausing, thinking clearly, or verifying with a trusted person.",
        "Hang up right away and verify the claim independently with a family member or official helpline.",
    ),
    CallScamRule(
        "call_guaranteed_job_bypass", "Guaranteed Job Selection Without Interview", Severity.HIGH,
        re.compile(r"(?i)\b(?:selected\s+without\s+(?:any\s+)?interview|no\s+interview\s+needed|direct\s+joining\s+(?:today|immediately)|bina\s+interview\s+ke\s+(?:selection|naukri|joining)|trabajo\s+sin\s+entrevista|embauch[eé]\s+sans\s+entretien)\b|बिना\s+इंटरव्यू\s+के\s+(?:नौकरी|चयन|जॉइनिंग)"),
        "Caller claims you are already selected for a job with no interview required.",
        "Fake HR callers use instant selection promises before asking for a registration or laptop deposit.",
        "Verify the vacancy directly on the company's official career website.",
    ),
    CallScamRule(
        "call_upi_collect_refund_trap", "UPI Collect / QR Scan Refund Trap on Call", Severity.CRITICAL,
        re.compile(r"(?i)\b(?:open\s+(?:google\s+pay|gpay|phonepe|paytm|upi)\s+(?:and\s+)?(?:enter\s+(?:your\s+)?upi\s+pin|approve\s+(?:the\s+)?request|scan\s+(?:the\s+)?qr)|enter\s+upi\s+pin\s+to\s+(?:receive|get|claim)\s+(?:money|salary|refund|cashback))\b|पैसे\s+पाने\s+के\s+लिए\s+यूपीआई\s+पिन\s+डालें|रिफंड\s+के\s+लिए\s+क्यूआर\s+स्कैन\s+करें"),
        "Caller guides you to open a UPI app and enter your UPI PIN or scan a QR code to 'receive' money.",
        "Entering a UPI PIN or scanning a payment QR code ALWAYS deducts money from your bank account.",
        "Decline the UPI collect request immediately and hang up.",
    ),
)


def validate_audio_upload(filename: str, size_bytes: int) -> Tuple[bool, str]:
    if not filename:
        return False, "Missing audio filename."
    ext = ("." + filename.lower().rsplit(".", 1)[-1]) if "." in filename else ""
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        return False, f"Unsupported audio format '{ext or 'unknown'}'. Allowed: WAV, MP3, M4A, OGG, WEBM, AAC, FLAC."
    if size_bytes <= 0:
        return False, "Uploaded audio file is empty."
    if size_bytes > MAX_AUDIO_BYTES:
        return False, "Audio file exceeds the 25 MB size limit."
    return True, ext


def extract_audio_metadata(filename: str, content: bytes) -> Dict[str, Any]:
    """Extract genuine acoustic & container metadata locally using wave / pydub."""
    ext = ("." + filename.lower().rsplit(".", 1)[-1]) if "." in filename else ""
    meta: Dict[str, Any] = {
        "filename": filename, "format": ext.lstrip(".").upper() or "UNKNOWN", "size_bytes": len(content),
        "duration_seconds": None, "sample_rate_hz": None, "channels": None, "avg_dbfs": None,
        "inspection_note": "Extracted locally from audio container without uploading to external servers.",
    }
    if ext == ".wav":
        try:
            with wave.open(io.BytesIO(content), "rb") as wf:
                rate = wf.getframerate()
                meta["channels"] = wf.getnchannels()
                meta["sample_rate_hz"] = rate
                meta["duration_seconds"] = round(wf.getnframes() / float(rate), 2) if rate else None
        except Exception as exc:
            logger.debug("WAV header parse skipped for %s: %s", filename, exc)
    try:
        from pydub import AudioSegment

        seg = AudioSegment.from_file(io.BytesIO(content), format=ext.lstrip(".") or None)
        meta["duration_seconds"] = meta["duration_seconds"] or round(len(seg) / 1000.0, 2)
        meta["sample_rate_hz"] = meta["sample_rate_hz"] or seg.frame_rate
        meta["channels"] = meta["channels"] or seg.channels
        if seg.dBFS != float("-inf"):
            meta["avg_dbfs"] = round(float(seg.dBFS), 1)
    except Exception as exc:
        logger.debug("pydub enrichment skipped for %s: %s", filename, exc)
    return meta


def attempt_server_transcription(
    filename: str, content: bytes, language_hint: str = "auto"
) -> Tuple[Optional[str], str, str]:
    """Return honest Check Unavailable when server STT is not configured/installed."""
    if os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY"):
        return None, EvidenceStatus.CHECK_UNAVAILABLE.value, "external_stt_configured_but_offline_fallback"
    return (
        None,
        EvidenceStatus.CHECK_UNAVAILABLE.value,
        "none (use browser Speech-to-Text or paste/edit call transcript; install local Whisper or set OPENAI_API_KEY for server STT)",
    )


@lru_cache(maxsize=256)
def detect_multilingual_call_language(text: str, hint: str = "auto") -> Tuple[str, str]:
    """Detect language code and human-readable label across 11+ languages."""
    if hint in LANGUAGE_LABELS:
        return hint, LANGUAGE_LABELS[hint]
    if not text:
        return "en", LANGUAGE_LABELS["en"]
    for code, pat in SCRIPT_PATTERNS:
        if len(pat.findall(text)) >= 4:
            return code, LANGUAGE_LABELS[code]
    if len(DEVANAGARI_RE.findall(text)) >= 4:
        code = "mr" if MARATHI_RE.search(text) else "hi"
        return code, LANGUAGE_LABELS[code]
    if SPANISH_CALL_RE.search(text):
        return "es", LANGUAGE_LABELS["es"]
    if FRENCH_CALL_RE.search(text):
        return "fr", LANGUAGE_LABELS["fr"]
    if HINGLISH_CALL_RE.search(text):
        return "hinglish", LANGUAGE_LABELS["hinglish"]
    return "en", LANGUAGE_LABELS["en"]


def _detect_call_indicators(clean_text: str) -> Tuple[List[DetectionIndicator], List[Any]]:
    indicators: List[DetectionIndicator] = []
    seen = set()
    for rule in CALL_SCAM_RULES:
        for m in rule.pattern.finditer(clean_text):
            if NEGATION_RE.search(clean_text[max(0, m.start() - 55):m.start()]):
                continue
            matched = m.group(0).strip()
            key = (rule.rule_id, matched.lower())
            if key in seen:
                continue
            seen.add(key)
            indicators.append(
                DetectionIndicator(
                    id=f"{rule.rule_id}_{len(indicators) + 1}", category=rule.category, matched_text=matched,
                    severity=rule.severity, explanation=rule.explanation, explanation_hi=rule.explanation,
                    detection_method="multilingual_call_scam_engine", reason_it_matters=rule.reason_it_matters,
                    suggested_action=rule.suggested_action,
                )
            )
            break

    url_inspections = [inspect_url_structurally(u) for u in extract_urls_from_text(clean_text)[:5]]
    for u in url_inspections:
        if u.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            indicators.append(
                DetectionIndicator(
                    id=f"call_url_{len(indicators) + 1}", category="Suspicious Link Mentioned on Call",
                    matched_text=u.submitted_url,
                    severity=Severity.CRITICAL if u.impersonated_brand else Severity.HIGH,
                    explanation=u.summary, explanation_hi=u.summary, detection_method="zero_visit_url_inspector",
                    reason_it_matters="Scammers dictate or SMS phishing URLs while keeping you on the phone.",
                    suggested_action=u.recommended_actions[0] if u.recommended_actions else "Do not open this URL.",
                )
            )
    return indicators, url_inspections


def _score_call_risk(
    clean_text: str, indicators: List[DetectionIndicator], upi_ids: List[str], has_disclaimer: bool
) -> Tuple[RiskLevel, int, str]:
    if not clean_text:
        return RiskLevel.MEDIUM, 0, "Audio metadata inspected — transcript required to evaluate call content."
    crit = sum(1 for i in indicators if i.severity == Severity.CRITICAL)
    high = sum(1 for i in indicators if i.severity == Severity.HIGH)
    med = sum(1 for i in indicators if i.severity == Severity.MEDIUM)
    raw_score = crit * 44 + high * 28 + med * 18 + (10 if (upi_ids and crit > 0) else 0)
    if has_disclaimer and crit == 0 and high == 0:
        return RiskLevel.LOW, 6, "LOW RISK — Protective anti-fraud disclaimer detected; no phone-scam indicators found."
    if crit >= 1 or high >= 2 or raw_score >= 60:
        return RiskLevel.HIGH, max(76, min(98, raw_score + (28 if raw_score < 76 else 0))), "HIGH RISK CALL SCAM — Multiple live-call fraud tactics detected."
    if high >= 1 or med >= 1 or raw_score >= 25:
        return RiskLevel.MEDIUM, max(38, min(68, raw_score + 12)), "MEDIUM RISK — Suspicious pressure or unverified claims detected on call."
    return RiskLevel.LOW, 10, "LOW RISK — No strong phone-scam indicators found in transcript."


def analyze_call_recording_or_transcript(
    transcript: str,
    audio_metadata: Optional[Dict[str, Any]] = None,
    transcription_status: str = "User / Browser Provided",
    transcription_provider: str = "user_or_browser_stt",
    language_hint: str = "auto",
    interface_language: str = "en",
    redact_sensitive: bool = True,
    is_demo: bool = False,
) -> Dict[str, Any]:
    """Extract all entities & red flags from a call recording/transcript and classify scam risk."""
    clean_text = sanitize_plain_text(transcript or "")
    lang_code, lang_label = detect_multilingual_call_language(clean_text, language_hint)
    redacted_transcript, redaction_counts = redact_sensitive_info(clean_text) if redact_sensitive else (clean_text, {})

    has_disclaimer = bool(CALL_DISCLAIMER_RE.search(clean_text))
    indicators, url_inspections = _detect_call_indicators(clean_text)
    upi_ids = list(dict.fromkeys(UPI_ID_RE.findall(clean_text)))
    amounts = list(dict.fromkeys(m.group(0).strip() for m in AMOUNT_RE.finditer(clean_text)))
    phones = list(dict.fromkeys(p.strip() for p in PHONE_RE.findall(clean_text)))
    urls = [u.submitted_url for u in url_inspections]
    org_match = ORG_CALLER_RE.search(clean_text)

    risk_level, risk_index, verdict_headline = _score_call_risk(clean_text, indicators, upi_ids, has_disclaimer)
    dump = lambda obj: obj.model_dump() if hasattr(obj, "model_dump") else obj.dict()

    return {
        "call_report_id": f"jg-call-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_demo": is_demo,
        "detected_language_code": lang_code,
        "detected_language_label": lang_label,
        "risk_index": risk_index,
        "risk_level": risk_level.value,
        "verdict_headline": verdict_headline,
        "risk_index_disclaimer": "Heuristic 0–100 Call Risk Index reflects multilingual voice-scam rules and extracted call evidence—not a calibrated probability or voice-biometric guarantee.",
        "audio_metadata": audio_metadata,
        "transcription_status": transcription_status,
        "transcription_provider": transcription_provider,
        "extracted_entities": {
            "claimed_organization": org_match.group(1).strip(" .,-") if org_match else None,
            "payment_amounts_mentioned": amounts,
            "upi_ids_mentioned": upi_ids,
            "phone_numbers_mentioned": phones,
            "urls_mentioned": urls,
            "has_anti_fraud_disclaimer": has_disclaimer,
        },
        "indicator_count": len(indicators),
        "indicators": [dump(i) for i in indicators],
        "url_inspections": [dump(u) for u in url_inspections],
        "redacted_transcript": redacted_transcript,
        "redaction_counts": redaction_counts,
        "recommended_actions": (
            [
                "Hang up immediately and block the caller's number.",
                "Do not transfer money, approve UPI collect requests, or share OTP/UPI PIN.",
                "If you installed AnyDesk/TeamViewer, turn on Airplane Mode and uninstall it immediately.",
                "If money was debited in India, call 1930 immediately and file a complaint at cybercrime.gov.in.",
            ]
            if risk_level == RiskLevel.HIGH
            else [
                "Independently verify the caller by dialing the organization's official published number.",
                "Never share OTPs, UPI PINs, or advance job fees on any follow-up call.",
            ]
        ),
        "limitations": [
            "Audio container metadata is extracted locally without uploading recordings to third-party servers.",
            "When server-side Whisper/STT API keys are not configured, transcription uses browser Speech-to-Text or user-reviewed transcripts rather than fabricating text.",
            "Acoustic metadata cannot determine whether a voice is AI-cloned/deepfaked.",
        ],
    }
