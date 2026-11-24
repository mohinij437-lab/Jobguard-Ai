"""Central deterministic fraud intelligence for inputs not covered by recruitment-only analysis."""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from functools import lru_cache
import threading
import time
from typing import Any, Dict, Iterable, List, Tuple

from .url_inspector import inspect_url_structurally

PatternRule = Tuple[str, re.Pattern, int]

CRITICAL_PATTERNS: Tuple[PatternRule, ...] = (
    ("otp_or_pin", re.compile(r"\b(otp|mpin|upi\s*pin|atm\s*pin|cvv|bank\s*password)\b", re.I), 26),
    ("remote_access", re.compile(r"\b(anydesk|teamviewer|quicksupport|screen\s*sharing)\b", re.I), 24),
    ("advance_payment", re.compile(r"\b(registration|security|processing|joining|activation|training|laptop)\s*(fee|deposit|payment|charge)\b", re.I), 22),
    ("authority_impersonation", re.compile(r"\b(digital\s*arrest|cbi|police|income\s*tax|customs|courier\s*held|kyc\s*update)\b", re.I), 22),
    ("upi_collect_request", re.compile(r"\b(upi\s*collect|collect\s*request|approve\s*the\s*request|scan\s*and\s*pay)\b", re.I), 20),
    ("upi_vpa_address", re.compile(r"\b[a-zA-Z0-9.\-_]{2,40}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|axl|upi|apl)\b", re.I), 20),
)

HIGH_PATTERNS: Tuple[PatternRule, ...] = (
    ("payment_request", re.compile(r"\b(pay|send|transfer|deposit|scan|upi)\b.{0,25}\b(₹|rs\.?|inr|\$)\s*\d", re.I | re.S), 18),
    ("isolation_pressure", re.compile(r"\b(do\s*not\s*hang\s*up|phone\s*mat\s*katna|tell\s*anyone|keep\s*this\s*secret)\b", re.I), 14),
    ("telegram_task", re.compile(r"\b(telegram|whatsapp)\b.{0,35}\b(task|rating|recharge|commission|withdraw)\b", re.I | re.S), 18),
    ("work_from_home", re.compile(r"\b(work\s*from\s*home|ghar\s+baithe)\b.{0,35}\b(without\s*interview|daily\s*income|typing)\b", re.I | re.S), 12),
)

ALL_FRAUD_PATTERNS: Tuple[PatternRule, ...] = CRITICAL_PATTERNS + HIGH_PATTERNS
INLINE_URL_RE = re.compile(r"https?://[^\s]+|(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s]*)?", re.I)

COMMUNITY_REPORTS: List[Dict[str, Any]] = []
COMMUNITY_INDEX: Dict[str, Dict[str, Any]] = {}
COMMUNITY_LOCK = threading.Lock()


def _match_fraud_patterns(clean: str, lower: str) -> Tuple[int, List[Dict[str, Any]]]:
    points = 0
    findings: List[Dict[str, Any]] = []
    for category, pattern, weight in ALL_FRAUD_PATTERNS:
        match = pattern.search(lower)
        if match:
            points += weight
            findings.append({
                "category": category,
                "matched_text": clean[max(0, match.start() - 20):match.end() + 30].strip(),
                "severity": "critical" if weight >= 20 else "high",
                "explanation": f"Matched a known {category.replace('_', ' ')} fraud pattern.",
            })
    return points, findings


def _inspect_embedded_urls(lower: str) -> Tuple[int, List[Dict[str, Any]]]:
    points = 0
    findings: List[Dict[str, Any]] = []
    for url in INLINE_URL_RE.findall(lower)[:5]:
        result = inspect_url_structurally(url.rstrip(".,);"))
        if result.risk_index >= 60:
            points += 28
            findings.append({"category": "suspicious_url", "matched_text": result.submitted_url, "severity": "critical", "explanation": result.summary})
        elif result.risk_index >= 25:
            points += 12
            findings.append({"category": "url_warning", "matched_text": result.submitted_url, "severity": "medium", "explanation": result.summary})
    return points, findings


def _classify_fraud_level(points: int, findings: List[Dict[str, Any]]) -> Tuple[str, str]:
    level = "CRITICAL" if points >= 76 else "HIGH RISK" if points >= 55 else "SUSPICIOUS" if points >= 25 else "SAFE"
    if level in ("SAFE", "SUSPICIOUS"):
        return level, "No strong fraud pattern detected"
    cats = {f["category"] for f in findings}
    if "otp_or_pin" in cats:
        return level, "Credential and OTP theft"
    if "upi_collect_request" in cats:
        return level, "UPI payment scam"
    if "telegram_task" in cats:
        return level, "Prepaid task scam"
    return level, "Recruitment or impersonation fraud"


def analyze_text(text: str, input_type: str = "message") -> Dict[str, Any]:
    """Run deterministic fraud pattern and URL inspection on generic text inputs."""
    clean = (text or "").strip()
    lower = clean.lower()
    pat_pts, pat_findings = _match_fraud_patterns(clean, lower)
    url_pts, url_findings = _inspect_embedded_urls(lower)
    findings = pat_findings + url_findings
    points = min(100, pat_pts + url_pts)
    level, category = _classify_fraud_level(points, findings)
    return {
        "input_type": input_type,
        "risk_percentage": points,
        "risk_category": level,
        "fraud_category": category,
        "explanation": (
            f"Detected {len(findings)} suspicious signal(s) indicating {category.lower()}."
            if findings
            else "No strong deterministic fraud patterns were detected in the submitted content."
        ),
        "evidence": findings,
        "recommended_actions": (
            ["Do not send money, share OTP/UPI PIN, or click unverified links.", "Report suspected fraud at cybercrime.gov.in or call 1930 in India."]
            if points >= 55
            else ["Verify the sender independently via an official website or published helpline."]
        ),
    }

def analyze_audio_metadata(filename: str, size_bytes: int) -> Dict[str, Any]:
    """Honest fallback: content authenticity cannot be inferred from filename/size."""
    suspicious_extensions = filename.lower().endswith((".wav", ".mp3", ".m4a", ".ogg", ".webm"))
    return {
        "assessment": "Unable to establish voice authenticity",
        "synthetic_voice_confidence": 0,
        "manipulation_indicators": [],
        "status": "UNVERIFIED",
        "limitations": [
            "No synthetic-voice model is configured.",
            "Filename and file size are not evidence of AI voice cloning.",
            "An on-device or licensed deepfake model is required for an authentic audio analysis.",
        ],
        "accepted_format": suspicious_extensions,
        "file_size_bytes": size_bytes,
    }


def submit_community_report(indicator: str, report_type: str, description: str = "") -> Dict[str, Any]:
    clean = indicator.strip()
    if len(clean) < 3:
        raise ValueError("Indicator is too short.")
    digest = hashlib.sha256(clean.lower().encode()).hexdigest()[:16]
    now = time.time()
    with COMMUNITY_LOCK:
        for existing in COMMUNITY_REPORTS:
            if existing["fingerprint"] == digest:
                existing["reports"] += 1
                existing["updated_at"] = now
                return existing
        report = {
            "fingerprint": digest,
            "indicator": clean,
            "report_type": report_type,
            "description": description[:500],
            "reports": 1,
            "verification_status": "UNVERIFIED — community report",
            "created_at": now,
            "updated_at": now,
        }
        COMMUNITY_REPORTS.append(report)
        return dict(report)


def search_community(query: str) -> List[Dict[str, Any]]:
    needle = query.lower().strip()
    with COMMUNITY_LOCK:
        return [
            dict(r) for r in COMMUNITY_REPORTS
            if not needle or needle in r["indicator"].lower() or needle in r["description"].lower()
        ][-50:]
