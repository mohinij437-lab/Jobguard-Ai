"""Layer F: Zero-visit structural URL and domain security inspection engine.

Modular, precompiled-regex, LRU-cached structural inspector that never automatically
opens or fetches user-submitted URLs.
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import ParseResult, urlparse

from .schemas import RiskLevel, Severity, URLInspectionResult, URLSignal

MULTI_PART_TLDS = frozenset(
    {
        "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
        "co.uk", "org.uk", "com.au", "co.jp", "com.sg", "com.br", "co.nz",
    }
)

SUSPICIOUS_TLDS = frozenset(
    {
        "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
        "buzz", "icu", "vip", "monster", "shop", "live", "online", "site", "club", "win",
    }
)

KNOWN_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly",
        "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "lnkd.in", "wa.me",
    }
)

PROTECTED_EMPLOYER_BRANDS: Dict[str, Tuple[str, ...]] = {
    "infosys": ("infosys.com",),
    "tcs": ("tcs.com",),
    "wipro": ("wipro.com",),
    "hcltech": ("hcltech.com",),
    "hcl": ("hcltech.com", "hcl.com"),
    "accenture": ("accenture.com",),
    "cognizant": ("cognizant.com",),
    "capgemini": ("capgemini.com",),
    "techmahindra": ("techmahindra.com",),
    "google": ("google.com", "careers.google.com", "abc.xyz"),
    "microsoft": ("microsoft.com", "careers.microsoft.com"),
    "amazon": ("amazon.jobs", "amazon.com", "amazon.in"),
    "meta": ("metacareers.com", "meta.com"),
    "flipkart": ("flipkartcareers.com", "flipkart.com"),
    "zoho": ("zohocorp.com", "zoho.com"),
    "deloitte": ("deloitte.com",),
    "pwc": ("pwc.com", "pwc.in"),
    "kpmg": ("kpmg.com",),
    "ey": ("ey.com",),
    "ibm": ("ibm.com",),
    "oracle": ("oracle.com",),
    "razorpay": ("razorpay.com",),
    "swiggy": ("swiggy.com",),
    "zomato": ("zomato.com",),
    "paytm": ("paytm.com",),
    "reliance": ("ril.com", "jio.com"),
    "jio": ("jio.com", "ril.com"),
    "tata": ("tata.com", "tcs.com", "tatamotors.com"),
    "linkedin": ("linkedin.com",),
    "naukri": ("naukri.com",),
    "internshala": ("internshala.com",),
    "indeed": ("indeed.com", "indeed.co.in"),
    "greenhouse": ("greenhouse.io",),
    "lever": ("lever.co",),
}

OFFICIAL_DOMAINS_SET = frozenset(d for doms in PROTECTED_EMPLOYER_BRANDS.values() for d in doms)

URL_EXTRACT_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\)\]]+"
    r"|\b(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|io|co|xyz|top|click|icu|vip|online|site|live|shop|info|jobs|co\.in|gov\.in|ly|at|gy|cc|me)(?:/[^\s<>\"'\)\]]*)?",
    re.IGNORECASE,
)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
RECRUITMENT_PHISHING_RE = re.compile(
    r"\b(?:career|careers|jobs|hire|hiring|recruit|recruitment|verify|verification|"
    r"offer|onboarding|register|registration|apply|portal|hr|interview|login|signin|kyc|fee|deposit)\b",
    re.IGNORECASE,
)
REDIRECT_QUERY_RE = re.compile(r"(?:redirect|url=|next=|return=|token=|otp=|session=|ref=http)", re.I)


def extract_urls_from_text(text: str, limit: int = 10) -> List[str]:
    """Extract unique URLs from text without visiting them."""
    if not text:
        return []
    found: List[str] = []
    seen = set()
    for match in URL_EXTRACT_REGEX.finditer(text):
        raw = match.group(0).rstrip(".,;:!?'\"])}")
        if match.start() > 0 and text[match.start() - 1] == "@":
            continue
        key = raw.lower()
        if raw and key not in seen:
            seen.add(key)
            found.append(raw)
        if len(found) >= limit:
            break
    return found


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=512)
def extract_registrable_domain(hostname: str) -> Tuple[str, Tuple[str, ...]]:
    """Return (registrable_domain, tuple_of_subdomains)."""
    host = (hostname or "").lower().strip(".")
    if not host or _is_ip_address(host):
        return host, ()
    parts = host.split(".")
    if len(parts) < 2:
        return host, ()
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:]), tuple(parts[:-3])
    return last_two, tuple(parts[:-2])


def _evaluate_host_signals(
    parsed: ParseResult, raw_host: str, reg_domain: str, subdomains: Tuple[str, ...], is_https: bool, is_ip: bool, has_idn: bool
) -> Tuple[int, List[URLSignal]]:
    signals: List[URLSignal] = []
    points = 0

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        points += 42
        signals.append(URLSignal(signal="embedded_credentials_in_url", severity=Severity.HIGH, explanation="Contains '@' in the URL authority section to disguise the destination domain."))
    if is_ip:
        points += 45
        signals.append(URLSignal(signal="raw_ip_address", severity=Severity.HIGH, explanation="Uses a raw numeric IP address instead of a registered corporate domain."))
    if has_idn:
        points += 38
        signals.append(URLSignal(signal="punycode_or_idn_homograph", severity=Severity.HIGH, explanation="Contains Punycode ('xn--') or non-ASCII homograph characters."))
    if not is_https:
        points += 14
        signals.append(URLSignal(signal="unencrypted_http", severity=Severity.MEDIUM, explanation="Uses unencrypted HTTP instead of HTTPS."))
    if len(raw_host) > 40:
        points += 20
        signals.append(URLSignal(signal="excessively_long_hostname", severity=Severity.MEDIUM, explanation=f"Hostname is unusually long ({len(raw_host)} chars)."))
    if len(subdomains) >= 3:
        points += 22
        signals.append(URLSignal(signal="excessive_subdomains", severity=Severity.MEDIUM, explanation=f"Uses {len(subdomains)} subdomain levels before '{reg_domain}'."))

    dom_label = reg_domain.split(".")[0] if reg_domain else ""
    if dom_label.count("-") >= 2 or (dom_label.count("-") >= 1 and any(k in dom_label for k in ("career", "verify", "hire", "job", "hr", "offer"))):
        points += 22
        signals.append(URLSignal(signal="lookalike_hyphenated_domain", severity=Severity.MEDIUM, explanation=f"Domain '{reg_domain}' combines hyphens with recruitment/verification keywords."))

    tld = reg_domain.rsplit(".", 1)[-1] if "." in reg_domain else ""
    if tld in SUSPICIOUS_TLDS:
        points += 26
        signals.append(URLSignal(signal="suspicious_tld", severity=Severity.MEDIUM, explanation=f"Uses high-abuse TLD '.{tld}' common in disposable phishing portals."))
    if reg_domain in KNOWN_SHORTENERS:
        points += 24
        signals.append(URLSignal(signal="url_shortener", severity=Severity.MEDIUM, explanation=f"Uses URL shortener '{reg_domain}' which conceals the final destination."))

    return points, signals


def _evaluate_brand_and_path(
    parsed: ParseResult, raw_host: str, reg_domain: str, subdomains: Tuple[str, ...], existing_points: int
) -> Tuple[int, List[URLSignal], Optional[str], List[str]]:
    signals: List[URLSignal] = []
    points = 0
    impersonated_brand: Optional[str] = None
    official_domains: List[str] = []

    full_host_and_path = f"{raw_host}{parsed.path}".lower()
    all_tokens = set(TOKEN_SPLIT_RE.split(raw_host)) | set(TOKEN_SPLIT_RE.split((parsed.path or "").lower()))

    for brand, domains in PROTECTED_EMPLOYER_BRANDS.items():
        matched = (brand in all_tokens) if len(brand) <= 3 else (brand in full_host_and_path)
        if matched and reg_domain not in domains:
            impersonated_brand = brand.upper()
            official_domains = list(domains)
            points += 52
            signals.append(
                URLSignal(
                    signal="employer_brand_impersonation",
                    severity=Severity.CRITICAL,
                    explanation=f"References '{impersonated_brand}' in the URL, but actual registrable domain is '{reg_domain}' instead of {', '.join(domains)}.",
                )
            )
            break

    path_and_sub = f"{' '.join(subdomains)} {parsed.path}".lower()
    matched_terms = list(dict.fromkeys(RECRUITMENT_PHISHING_RE.findall(path_and_sub)))
    if matched_terms and reg_domain not in OFFICIAL_DOMAINS_SET and (existing_points + points > 0 or len(matched_terms) >= 2):
        points += min(24, 10 * len(matched_terms))
        signals.append(
            URLSignal(
                signal="suspicious_recruitment_path",
                severity=Severity.MEDIUM if len(matched_terms) == 1 else Severity.HIGH,
                explanation=f"Contains recruitment/verification keywords ({', '.join(matched_terms[:4])}) on unverified domain '{reg_domain}'.",
            )
        )

    if parsed.query and REDIRECT_QUERY_RE.search(parsed.query):
        points += 18
        signals.append(URLSignal(signal="suspicious_redirect_parameters", severity=Severity.MEDIUM, explanation=f"Query string contains redirect or session parameters ('{parsed.query[:60]}')."))

    return points, signals, impersonated_brand, official_domains


@lru_cache(maxsize=512)
def inspect_url_structurally(raw_url: str) -> URLInspectionResult:
    """Zero-visit structural inspection of a recruitment or job URL."""
    submitted = (raw_url or "").strip()
    lower_sub = submitted.lower()

    if lower_sub.startswith(("javascript:", "data:", "vbscript:", "file:")):
        scheme = lower_sub.split(":", 1)[0]
        return URLInspectionResult(
            submitted_url=submitted, normalized_url=submitted, hostname="", registrable_domain="",
            subdomains=[], scheme=scheme, is_https=False, is_ip_address=False, is_shortened=False,
            has_punycode_or_idn=False, subdomain_count=0, risk_level=RiskLevel.HIGH, risk_index=95,
            summary="Executable or non-web URI scheme detected. Never open this link.",
            signals=[URLSignal(signal="dangerous_uri_scheme", severity=Severity.CRITICAL, explanation=f"Unsafe '{scheme}:' URI scheme.")],
            recommended_actions=["Do not click or paste this address into your browser."],
            limitations=["Evaluated structurally without visiting the URL."],
        )

    with_scheme = submitted if SCHEME_RE.match(submitted) else f"http://{submitted}"
    parsed = urlparse(with_scheme)
    raw_host = (parsed.hostname or "").lower().strip(".")

    if not raw_host or ("." not in raw_host and not _is_ip_address(raw_host)):
        return URLInspectionResult(
            submitted_url=submitted, normalized_url=with_scheme, hostname=raw_host, registrable_domain=raw_host,
            subdomains=[], scheme=parsed.scheme or "invalid", is_https=parsed.scheme == "https",
            is_ip_address=False, is_shortened=False, has_punycode_or_idn=False, subdomain_count=0,
            risk_level=RiskLevel.HIGH, risk_index=80, summary="Malformed or non-standard recruitment URL structure.",
            signals=[URLSignal(signal="malformed_url", severity=Severity.HIGH, explanation="Does not resolve to a valid standard hostname.")],
            recommended_actions=["Do not open malformed links; verify on the employer's official career site."],
            limitations=["Evaluated structurally without visiting the URL."],
        )

    scheme = (parsed.scheme or "http").lower()
    is_https = scheme == "https"
    is_ip = _is_ip_address(raw_host)
    has_idn = ("xn--" in raw_host) or any(ord(ch) > 127 for ch in raw_host)
    reg_domain, subdomains = extract_registrable_domain(raw_host)

    host_pts, host_sigs = _evaluate_host_signals(parsed, raw_host, reg_domain, subdomains, is_https, is_ip, has_idn)
    brand_pts, brand_sigs, imp_brand, off_domains = _evaluate_brand_and_path(parsed, raw_host, reg_domain, subdomains, host_pts)

    signals = host_sigs + brand_sigs
    risk_index = min(98, max(5, host_pts + brand_pts))

    if risk_index >= 60 or imp_brand is not None:
        risk_level = RiskLevel.HIGH
        summary = f"High-risk structural indicators detected on '{reg_domain}'. " + (
            f"Appears to impersonate {imp_brand} (official: {', '.join(off_domains)}). " if imp_brand else ""
        ) + "Do not open or submit personal details."
    elif risk_index >= 25:
        risk_level = RiskLevel.MEDIUM
        summary = f"Structural warning signs found on '{reg_domain}'. Verify independently before clicking."
    else:
        risk_level = RiskLevel.LOW
        summary = f"No strong structural phishing signals detected in '{reg_domain}'."

    rec_actions = (
        [
            f"Do not open or enter personal details on '{reg_domain}'.",
            f"Visit {imp_brand}'s official careers page via {off_domains[0]}." if (imp_brand and off_domains) else "Navigate manually to the company's official website.",
        ]
        if risk_level == RiskLevel.HIGH
        else ["Confirm the domain matches the employer's verified corporate website before applying."]
    )

    return URLInspectionResult(
        submitted_url=submitted, normalized_url=parsed.geturl(), hostname=raw_host, registrable_domain=reg_domain,
        subdomains=list(subdomains), scheme=scheme, is_https=is_https, is_ip_address=is_ip,
        is_shortened=reg_domain in KNOWN_SHORTENERS, has_punycode_or_idn=has_idn, subdomain_count=len(subdomains),
        impersonated_brand=imp_brand, official_domains=off_domains, risk_level=risk_level, risk_index=risk_index,
        summary=summary, signals=signals, recommended_actions=rec_actions,
        limitations=[
            "Zero-visit inspection: JobGuard AI never automatically opens or fetches arbitrary user-submitted URLs.",
            "HTTPS presence does not prove a recruitment portal is genuine.",
        ],
    )
