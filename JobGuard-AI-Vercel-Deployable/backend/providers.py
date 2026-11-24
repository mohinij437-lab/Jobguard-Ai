"""Optional, environment-variable-gated external verification providers.

Uses a shared pooled httpx.AsyncClient and an in-memory TTL cache for efficiency,
while guaranteeing graceful fallback and honest 'Check Unavailable' reporting when
disabled, unconfigured, or unreachable.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

import httpx

from .schemas import EvidenceRecord, EvidenceStatus

logger = logging.getLogger("jobguard.providers")

DEFAULT_TIMEOUT = 5.0
CACHE_TTL_SECONDS = 300.0

_http_client: Optional[httpx.AsyncClient] = None
_response_cache: OrderedDict[str, Tuple[float, EvidenceRecord]] = OrderedDict()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def get_http_client() -> httpx.AsyncClient:
    """Return a shared, connection-pooled AsyncClient for external provider calls."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=25),
            follow_redirects=False,
        )
    return _http_client


async def close_http_client() -> None:
    """Gracefully close the shared AsyncClient on application shutdown."""
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


def _cache_get(key: str) -> Optional[EvidenceRecord]:
    entry = _response_cache.get(key)
    if entry and (time.monotonic() - entry[0]) < CACHE_TTL_SECONDS:
        return entry[1]
    if entry:
        _response_cache.pop(key, None)
    return None


def _cache_set(key: str, record: EvidenceRecord) -> EvidenceRecord:
    if len(_response_cache) >= 256:
        _response_cache.clear()
    _response_cache[key] = (time.monotonic(), record)
    return record


def _unavailable_record(
    check_name: str, source: str, observed: str, explanation: str, uncertainty: str
) -> EvidenceRecord:
    return EvidenceRecord(
        check_name=check_name,
        source_examined=source,
        source_type="external_verification",
        observed_result=observed,
        status=EvidenceStatus.CHECK_UNAVAILABLE,
        timestamp=_now_iso(),
        explanation=explanation,
        residual_uncertainty=uncertainty,
    )


def get_provider_status_summary() -> Dict[str, Dict[str, Any]]:
    """Return honest configuration status of all optional external providers."""
    return {
        "greenhouse_boards": {"enabled": _env_true("ENABLE_GREENHOUSE_CHECK"), "requires_key": False, "env_var": "ENABLE_GREENHOUSE_CHECK=true"},
        "lever_postings": {"enabled": _env_true("ENABLE_LEVER_CHECK"), "requires_key": False, "env_var": "ENABLE_LEVER_CHECK=true"},
        "gleif_lei": {"enabled": _env_true("ENABLE_GLEIF_CHECK"), "requires_key": False, "env_var": "ENABLE_GLEIF_CHECK=true"},
        "opencorporates": {"enabled": bool(os.getenv("OPENCORPORATES_API_KEY")), "requires_key": True, "env_var": "OPENCORPORATES_API_KEY"},
        "iana_rdap": {"enabled": _env_true("ENABLE_RDAP_CHECK"), "requires_key": False, "env_var": "ENABLE_RDAP_CHECK=true"},
        "cloudflare_doh_mx": {"enabled": _env_true("ENABLE_DOH_MX_CHECK"), "requires_key": False, "env_var": "ENABLE_DOH_MX_CHECK=true"},
        "google_safe_browsing": {"enabled": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")), "requires_key": True, "env_var": "GOOGLE_SAFE_BROWSING_API_KEY"},
        "virustotal": {"enabled": bool(os.getenv("VIRUSTOTAL_API_KEY")), "requires_key": True, "env_var": "VIRUSTOTAL_API_KEY"},
    }


async def check_greenhouse_vacancy(
    board_token: Optional[str], role_title: Optional[str], requisition_id: Optional[str]
) -> EvidenceRecord:
    """Check allowlisted Greenhouse public job board API when enabled."""
    name = "Greenhouse Public Job Board Check"
    if not _env_true("ENABLE_GREENHOUSE_CHECK") or not board_token:
        return _unavailable_record(
            name,
            "boards-api.greenhouse.io (allowlisted ATS)",
            "External Greenhouse lookup is disabled or no board token is mapped.",
            "Live Greenhouse ATS verification is optional (set ENABLE_GREENHOUSE_CHECK=true).",
            "Vacancy existence on Greenhouse was not checked.",
        )

    cache_key = f"gh:{board_token}:{(role_title or '').lower()}:{requisition_id or ''}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    url = f"https://boards-api.greenhouse.io/v1/boards/{board_token}/jobs"
    try:
        resp = await get_http_client().get(url)
        resp.raise_for_status()
        jobs = resp.json().get("jobs", [])
    except Exception as exc:
        logger.debug("Greenhouse lookup unavailable for %s: %s", board_token, exc)
        return _unavailable_record(
            name, url, f"Provider unreachable ({type(exc).__name__}).",
            "Could not reach Greenhouse public API; no vacancy claim is marked confirmed.",
            "Network or provider outage prevented live ATS verification.",
        )

    matched = next(
        (
            j for j in jobs
            if (requisition_id and str(j.get("id", "")) == requisition_id)
            or (role_title and role_title.lower() in (j.get("title") or "").lower())
        ),
        None,
    )
    if matched:
        return _cache_set(
            cache_key,
            EvidenceRecord(
                check_name=name, source_examined=url, source_type="external_verification",
                observed_result=f"Matched live posting: '{matched.get('title')}' (ID: {matched.get('id')}).",
                supporting_quotation=matched.get("absolute_url"),
                status=EvidenceStatus.CONFIRMED_BY_SOURCE, timestamp=_now_iso(),
                explanation="Independently located a matching active role on the employer's public Greenhouse board.",
                residual_uncertainty="Confirm that the recruiter contacting you is genuinely affiliated with this posting.",
            ),
        )
    return _cache_set(
        cache_key,
        EvidenceRecord(
            check_name=name, source_examined=url, source_type="external_verification",
            observed_result=f"Checked {len(jobs)} public postings; no exact match for role/requisition ID.",
            status=EvidenceStatus.UNVERIFIED, timestamp=_now_iso(),
            explanation="The advertised role was not found on the public Greenhouse board.",
            residual_uncertainty="Absence from a public board does not by itself prove fraud.",
        ),
    )


async def check_lever_vacancy(company_slug: Optional[str], role_title: Optional[str]) -> EvidenceRecord:
    """Check allowlisted Lever public job postings API when enabled."""
    name = "Lever Public Job Postings Check"
    if not _env_true("ENABLE_LEVER_CHECK") or not company_slug:
        return _unavailable_record(
            name, "api.lever.co (allowlisted ATS)",
            "Lever ATS check is disabled or employer slug is unavailable.",
            "Live Lever ATS verification is optional (enable with ENABLE_LEVER_CHECK=true).",
            "Vacancy existence on Lever was not checked.",
        )

    cache_key = f"lever:{company_slug}:{(role_title or '').lower()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    url = f"https://api.lever.co/v0/postings/{company_slug}?mode=json"
    try:
        resp = await get_http_client().get(url)
        resp.raise_for_status()
        postings = resp.json()
    except Exception as exc:
        logger.debug("Lever lookup unavailable for %s: %s", company_slug, exc)
        return _unavailable_record(
            name, url, f"Provider unreachable ({type(exc).__name__}).",
            "Could not reach Lever public API.", "Live ATS check could not be completed.",
        )

    match = next((p for p in postings if role_title and role_title.lower() in (p.get("text") or "").lower()), None)
    status = EvidenceStatus.CONFIRMED_BY_SOURCE if match else EvidenceStatus.UNVERIFIED
    return _cache_set(
        cache_key,
        EvidenceRecord(
            check_name=name, source_examined=url, source_type="external_verification",
            observed_result=f"Matched live Lever posting: '{match.get('text')}'." if match else f"Checked {len(postings)} postings; no match found.",
            supporting_quotation=match.get("hostedUrl") if match else None,
            status=status, timestamp=_now_iso(),
            explanation="Independently located a matching posting on Lever." if match else "No matching public Lever posting was located.",
            residual_uncertainty="Still verify recruiter identity separately." if match else "Role may be private, filled, or hosted elsewhere.",
        ),
    )


async def check_gleif_employer(employer_name: Optional[str]) -> EvidenceRecord:
    """Check GLEIF public Legal Entity Identifier (LEI) API when enabled."""
    name = "GLEIF Legal Entity Check"
    if not _env_true("ENABLE_GLEIF_CHECK") or not employer_name:
        return _unavailable_record(
            name, "api.gleif.org (Global LEI Foundation)",
            "GLEIF live corporate check is disabled or employer name is missing.",
            "External GLEIF LEI lookup is optional (set ENABLE_GLEIF_CHECK=true).",
            "Live global corporate registration was not queried.",
        )

    cache_key = f"gleif:{employer_name.lower()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    url = "https://api.gleif.org/api/v1/lei-records"
    try:
        resp = await get_http_client().get(url, params={"filter[entity.legalName]": employer_name, "page[size]": 1})
        resp.raise_for_status()
        data = resp.json().get("data", [])
    except Exception as exc:
        logger.debug("GLEIF lookup unavailable for %s: %s", employer_name, exc)
        return _unavailable_record(
            name, url, f"GLEIF API unreachable ({type(exc).__name__}).",
            "Could not query GLEIF public API.", "Corporate registration status remains unverified externally.",
        )

    if data:
        rec = data[0]
        legal_name = rec.get("attributes", {}).get("entity", {}).get("legalName", {}).get("name")
        return _cache_set(
            cache_key,
            EvidenceRecord(
                check_name=name, source_examined=url, source_type="external_verification",
                observed_result=f"Matched GLEIF entity '{legal_name}' (LEI: {rec.get('id')}).",
                status=EvidenceStatus.CONFIRMED_BY_SOURCE, timestamp=_now_iso(),
                explanation="Found a registered legal entity matching the employer name in GLEIF.",
                residual_uncertainty="Entity existence does not prove the job offer is genuinely from that entity.",
            ),
        )
    return _cache_set(
        cache_key,
        EvidenceRecord(
            check_name=name, source_examined=url, source_type="external_verification",
            observed_result="No matching LEI record returned.",
            status=EvidenceStatus.UNVERIFIED, timestamp=_now_iso(),
            explanation="Many legitimate small and mid-sized companies do not hold a global LEI.",
            residual_uncertainty="Absence from GLEIF does not imply fraud.",
        ),
    )


async def check_cloudflare_mx(domain: Optional[str]) -> EvidenceRecord:
    """Check MX records via Cloudflare DNS-over-HTTPS when enabled."""
    name = "DNS MX Record Check (Cloudflare DoH)"
    if not _env_true("ENABLE_DOH_MX_CHECK") or not domain:
        return _unavailable_record(
            name, "cloudflare-dns.com/dns-query",
            "Live MX record lookup is disabled or no email domain provided.",
            "Optional DNS-over-HTTPS MX lookup is disabled (set ENABLE_DOH_MX_CHECK=true).",
            "Mail server configuration for the domain was not queried.",
        )

    cache_key = f"mx:{domain.lower()}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    url = "https://cloudflare-dns.com/dns-query"
    try:
        resp = await get_http_client().get(url, params={"name": domain, "type": "MX"}, headers={"Accept": "application/dns-json"})
        resp.raise_for_status()
        answers = resp.json().get("Answer", [])
    except Exception as exc:
        logger.debug("Cloudflare DoH MX unavailable for %s: %s", domain, exc)
        return _unavailable_record(
            name, url, f"Cloudflare DoH unreachable ({type(exc).__name__}).",
            "Could not query DNS MX records.", "Email domain mail-exchange capability could not be checked.",
        )

    if answers:
        mx_list = ", ".join(a.get("data", "") for a in answers[:3])
        return _cache_set(
            cache_key,
            EvidenceRecord(
                check_name=name, source_examined=url, source_type="external_verification",
                observed_result=f"Active MX records found for '{domain}': {mx_list}.",
                status=EvidenceStatus.CONFIRMED_BY_SOURCE, timestamp=_now_iso(),
                explanation="The email domain has valid DNS mail-exchange records.",
                residual_uncertainty="Having MX records does not guarantee the domain belongs to the claimed employer.",
            ),
        )
    return _cache_set(
        cache_key,
        EvidenceRecord(
            check_name=name, source_examined=url, source_type="external_verification",
            observed_result=f"No MX records found for '{domain}'.",
            status=EvidenceStatus.SUSPICIOUS_SIGNAL, timestamp=_now_iso(),
            explanation="The recruiter email domain has no configured MX records to receive replies.",
            residual_uncertainty="Check for typos in the email domain.",
        ),
    )


async def check_url_reputation(url_to_check: Optional[str]) -> EvidenceRecord:
    """Check Google Safe Browsing or VirusTotal only when API keys are configured."""
    name = "External URL Reputation Check (Safe Browsing / VirusTotal)"
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not url_to_check or not gsb_key:
        return _unavailable_record(
            name, "Google Safe Browsing / VirusTotal (unconfigured)",
            "External threat-intelligence API keys are not configured.",
            "Core URL safety relies on local zero-visit structural inspection.",
            "External blocklist reputation was not queried.",
        )

    cache_key = f"gsb:{url_to_check}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
    payload = {
        "client": {"clientId": "jobguard-ai", "clientVersion": "1.2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}],
        },
    }
    try:
        resp = await get_http_client().post(endpoint, json=payload)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except Exception as exc:
        logger.debug("Safe Browsing unavailable: %s", exc)
        return _unavailable_record(
            name, "safebrowsing.googleapis.com", f"Safe Browsing API unreachable ({type(exc).__name__}).",
            "External reputation check could not be completed.", "Rely on structural URL analysis.",
        )

    if matches:
        return _cache_set(
            cache_key,
            EvidenceRecord(
                check_name=name, source_examined="safebrowsing.googleapis.com", source_type="external_verification",
                observed_result=f"Flagged by Google Safe Browsing ({matches[0].get('threatType')}).",
                status=EvidenceStatus.SUSPICIOUS_SIGNAL, timestamp=_now_iso(),
                explanation="External threat intelligence flagged this URL as malicious or social engineering.",
                residual_uncertainty="Do not visit this URL.",
            ),
        )
    return _cache_set(
        cache_key,
        EvidenceRecord(
            check_name=name, source_examined="safebrowsing.googleapis.com", source_type="external_verification",
            observed_result="No threat matches returned by Google Safe Browsing.",
            status=EvidenceStatus.UNVERIFIED, timestamp=_now_iso(),
            explanation="Not currently listed in Google Safe Browsing; newly created phishing domains may not yet be indexed.",
            residual_uncertainty="Absence from blocklists is not proof of legitimacy.",
        ),
    )
