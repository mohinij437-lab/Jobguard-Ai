"""Layers C & E: Curated Employer Identity Reference Registry & Recruiter / Email-Domain Alignment.

Uses an O(1) indexed alias dictionary and LRU caching for fast lookups.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .schemas import EvidenceStatus, ExtractedJobData
from .url_inspector import extract_registrable_domain

NON_ALNUM_SPACE_RE = re.compile(r"[^a-z0-9\s]")
WHITESPACE_RE = re.compile(r"\s+")
SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass(frozen=True)
class EmployerRegistryEntry:
    canonical_name: str
    aliases: Tuple[str, ...]
    official_website: str
    official_domains: Tuple[str, ...]
    career_portal: str
    registry_note: str
    ats_provider: Optional[str] = None
    ats_slug: Optional[str] = None


EMPLOYER_REGISTRY: Tuple[EmployerRegistryEntry, ...] = (
    EmployerRegistryEntry("Infosys Limited", ("infosys", "infosys limited", "infosys ltd"), "https://www.infosys.com", ("infosys.com",), "https://www.infosys.com/careers/", "Publicly listed Indian IT services corporation; official hiring communications use @infosys.com."),
    EmployerRegistryEntry("Tata Consultancy Services (TCS)", ("tcs", "tata consultancy services", "tata consultancy services ltd"), "https://www.tcs.com", ("tcs.com",), "https://www.tcs.com/careers", "Publicly listed IT services company; official recruitment portal is TCS NextStep / tcs.com."),
    EmployerRegistryEntry("Wipro Limited", ("wipro", "wipro limited", "wipro ltd"), "https://www.wipro.com", ("wipro.com",), "https://careers.wipro.com", "Official hiring communications use @wipro.com; Wipro never charges recruitment fees."),
    EmployerRegistryEntry("HCLTech", ("hcl", "hcltech", "hcl technologies", "hcl technologies limited"), "https://www.hcltech.com", ("hcltech.com", "hcl.com"), "https://www.hcltech.com/careers", "Official corporate domain is hcltech.com."),
    EmployerRegistryEntry("Accenture", ("accenture", "accenture india", "accenture solutions"), "https://www.accenture.com", ("accenture.com",), "https://www.accenture.com/in-en/careers", "Official hiring communications originate from @accenture.com."),
    EmployerRegistryEntry("Cognizant Technology Solutions", ("cognizant", "cts", "cognizant technology solutions"), "https://www.cognizant.com", ("cognizant.com",), "https://careers.cognizant.com", "Official hiring communications originate from @cognizant.com."),
    EmployerRegistryEntry("Capgemini", ("capgemini", "capgemini india"), "https://www.capgemini.com", ("capgemini.com",), "https://www.capgemini.com/careers/", "Official corporate domain is capgemini.com."),
    EmployerRegistryEntry("Google LLC", ("google", "google india", "google llc"), "https://www.google.com", ("google.com",), "https://www.google.com/about/careers/applications/", "Official recruiter emails end in @google.com."),
    EmployerRegistryEntry("Microsoft Corporation", ("microsoft", "microsoft india", "microsoft corporation"), "https://www.microsoft.com", ("microsoft.com",), "https://careers.microsoft.com", "Official corporate recruitment domain is microsoft.com."),
    EmployerRegistryEntry("Amazon", ("amazon", "amazon india", "amazon development centre", "aws"), "https://www.amazon.jobs", ("amazon.com", "amazon.jobs", "amazon.in"), "https://www.amazon.jobs", "Official job portal is amazon.jobs; corporate emails use @amazon.com."),
    EmployerRegistryEntry("Flipkart", ("flipkart", "flipkart internet"), "https://www.flipkartcareers.com", ("flipkart.com", "flipkartcareers.com"), "https://www.flipkartcareers.com", "Official career portal is flipkartcareers.com."),
    EmployerRegistryEntry("Zoho Corporation", ("zoho", "zoho corp", "zoho corporation"), "https://www.zoho.com", ("zohocorp.com", "zoho.com"), "https://www.zoho.com/careers/", "Official corporate domains are zohocorp.com and zoho.com."),
    EmployerRegistryEntry("Deloitte", ("deloitte", "deloitte india", "deloitte usi"), "https://www2.deloitte.com", ("deloitte.com",), "https://jobsindia.deloitte.com", "Official corporate domain is deloitte.com."),
    EmployerRegistryEntry("Razorpay", ("razorpay", "razorpay software"), "https://razorpay.com", ("razorpay.com",), "https://razorpay.com/jobs/", "Official corporate domain is razorpay.com.", ats_provider="greenhouse", ats_slug="razorpaysoftwareprivatelimited"),
)

# Precomputed O(1) exact alias lookup index
_ALIAS_INDEX: Dict[str, EmployerRegistryEntry] = {
    alias: entry for entry in EMPLOYER_REGISTRY for alias in entry.aliases
}

PERSONAL_EMAIL_PROVIDERS = frozenset(
    {
        "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
        "live.com", "rediffmail.com", "protonmail.com", "proton.me", "icloud.com", "aol.com",
    }
)


@lru_cache(maxsize=256)
def lookup_employer_in_registry(employer_name: Optional[str]) -> Optional[EmployerRegistryEntry]:
    """Match an extracted employer name against the curated local reference registry."""
    if not employer_name:
        return None
    norm = WHITESPACE_RE.sub(" ", NON_ALNUM_SPACE_RE.sub("", employer_name.lower())).strip()
    if norm in _ALIAS_INDEX:
        return _ALIAS_INDEX[norm]
    for alias, entry in _ALIAS_INDEX.items():
        if alias in norm or (len(norm) >= 3 and norm in alias):
            return entry
    return None


def analyze_recruiter_and_domain_alignment(
    extracted: ExtractedJobData,
    registry_entry: Optional[EmployerRegistryEntry],
) -> Dict[str, object]:
    """Layer E: Evaluate recruiter email, personal email usage, and domain alignment."""
    email = extracted.recruiter_email.value if extracted.recruiter_email.status == "extracted" else None
    job_url = extracted.job_url.value if extracted.job_url.status == "extracted" else None

    email_domain = email.rsplit("@", 1)[-1].lower().strip() if (email and "@" in email) else None
    is_personal_email = bool(email_domain and email_domain in PERSONAL_EMAIL_PROVIDERS)

    url_reg_domain: Optional[str] = None
    if job_url:
        ws = job_url if SCHEME_PREFIX_RE.match(job_url) else f"http://{job_url}"
        url_reg_domain, _ = extract_registrable_domain(urlparse(ws).hostname or "")

    alignment_status = EvidenceStatus.UNVERIFIED
    alignment_explanation = "No recruiter email address was provided to verify domain alignment."
    is_lookalike_email_domain = False
    domain_mismatch = False

    if email_domain:
        if registry_entry:
            if email_domain in registry_entry.official_domains:
                alignment_status = EvidenceStatus.CONFIRMED_BY_SOURCE
                alignment_explanation = (
                    f"Recruiter email domain '@{email_domain}' matches {registry_entry.canonical_name}'s "
                    f"official domain ({', '.join(registry_entry.official_domains)})."
                )
            elif is_personal_email:
                alignment_status = EvidenceStatus.SUSPICIOUS_SIGNAL
                domain_mismatch = True
                alignment_explanation = (
                    f"Claimed employer '{registry_entry.canonical_name}' uses corporate domains "
                    f"({', '.join(registry_entry.official_domains)}), but recruiter uses personal email '@{email_domain}'."
                )
            else:
                alignment_status = EvidenceStatus.INCONSISTENT
                domain_mismatch = True
                is_lookalike_email_domain = registry_entry.aliases[0] in email_domain
                alignment_explanation = (
                    f"Recruiter email domain '@{email_domain}' does not match {registry_entry.canonical_name}'s "
                    f"official domain(s) ({', '.join(registry_entry.official_domains)})."
                )
        elif is_personal_email:
            alignment_explanation = f"Recruiter uses personal email '@{email_domain}'; corporate affiliation cannot be verified from domain."
        elif url_reg_domain and email_domain != url_reg_domain and not email_domain.endswith("." + url_reg_domain):
            alignment_status = EvidenceStatus.INCONSISTENT
            domain_mismatch = True
            alignment_explanation = f"Recruiter email domain '@{email_domain}' differs from job URL domain '{url_reg_domain}'."
        else:
            alignment_explanation = f"Recruiter uses custom domain '@{email_domain}', not listed in the local reference registry."

    return {
        "email": email,
        "email_domain": email_domain,
        "is_personal_email": is_personal_email,
        "is_lookalike_email_domain": is_lookalike_email_domain,
        "domain_mismatch": domain_mismatch,
        "url_reg_domain": url_reg_domain,
        "alignment_status": alignment_status,
        "alignment_explanation": alignment_explanation,
    }
