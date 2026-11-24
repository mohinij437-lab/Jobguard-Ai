"""Core 7-Category Evidence-Based Verification Report Engine & Explainable Risk Scorer.

Uses concurrent external checks via asyncio.gather() and modular category builders
for clean maintainability, low latency, and transparent evidence reporting.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .ai_explainer import generate_grounded_explanation
from .analyzer import compare_document_consistency, run_rule_analysis
from .extractor import apply_user_field_edits, extract_structured_job_data
from .ml_classifier import run_ml_classification
from .providers import (
    check_cloudflare_mx,
    check_gleif_employer,
    check_greenhouse_vacancy,
    check_lever_vacancy,
    check_url_reputation,
)
from .schemas import (
    DetectionIndicator,
    EvidenceCategoryReport,
    EvidenceRecord,
    EvidenceStatus,
    ExtractedJobData,
    RiskLevel,
    Severity,
    URLInspectionResult,
    VerificationReport,
    VerifyRequest,
)
from .security import redact_sensitive_info, sanitize_plain_text
from .url_inspector import extract_urls_from_text, inspect_url_structurally
from .verification import (
    EmployerRegistryEntry,
    analyze_recruiter_and_domain_alignment,
    lookup_employer_in_registry,
)

PAYMENT_OR_CRED_CATEGORIES = frozenset(
    {
        "Upfront Fee / Security Deposit / Paid Onboarding Scam",
        "Advance Fee / Registration Scam",
        "Security / Equipment Deposit Scam",
        "Paid Training / Fake Internship Scam",
        "Task / App Optimization / Click-to-Earn Scam",
        "Prepaid Task & Recharge Scam",
        "Fake Check / Equipment Purchase / Gift Card Scam",
        "Money Mule / Bank Account Laundering Scam",
        "Credential Phishing / Credit Check / Malware Lure",
        "OTP / UPI PIN / Credential Theft",
        "Remote-Access Software Scam",
    }
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worst_status(records: List[EvidenceRecord]) -> EvidenceStatus:
    """Determine category overall status from its individual evidence records."""
    statuses = {r.status for r in records}
    for priority in (
        EvidenceStatus.SUSPICIOUS_SIGNAL,
        EvidenceStatus.INCONSISTENT,
        EvidenceStatus.CONFIRMED_BY_SOURCE,
        EvidenceStatus.UNVERIFIED,
    ):
        if priority in statuses:
            return priority
    return EvidenceStatus.CHECK_UNAVAILABLE


def _build_employer_category(
    extracted: ExtractedJobData,
    registry_entry: Optional[EmployerRegistryEntry],
    gleif_record: EvidenceRecord,
    ts: str,
) -> EvidenceCategoryReport:
    employer_name = extracted.employer.value if extracted.employer.status == "extracted" else None
    records: List[EvidenceRecord] = []
    if employer_name and registry_entry:
        records.append(
            EvidenceRecord(
                check_name="Curated Employer Reference Registry",
                source_examined="JobGuard AI Local Employer Reference Registry",
                source_type="curated_registry",
                observed_result=(
                    f"Matched '{registry_entry.canonical_name}' — Official website: {registry_entry.official_website}, "
                    f"Domains: {', '.join(registry_entry.official_domains)}, Career Portal: {registry_entry.career_portal}."
                ),
                supporting_quotation=extracted.employer.supporting_snippet,
                status=EvidenceStatus.CONFIRMED_BY_SOURCE,
                timestamp=ts,
                explanation=registry_entry.registry_note,
                residual_uncertainty="Being a real company does not prove this specific message came from them; check domain alignment and URL safety.",
            )
        )
    elif employer_name:
        records.append(
            EvidenceRecord(
                check_name="Curated Employer Reference Registry",
                source_examined="JobGuard AI Local Employer Reference Registry",
                source_type="curated_registry",
                observed_result=f"Employer '{employer_name}' is not listed in the local reference registry.",
                supporting_quotation=extracted.employer.supporting_snippet,
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="An unknown or unlisted company is NOT automatically fraudulent—many legitimate startups and SMEs are not in the local registry.",
                residual_uncertainty="Independently check corporate registration, LinkedIn company page, and official website.",
            )
        )
    else:
        records.append(
            EvidenceRecord(
                check_name="Employer Name Extraction",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result="No employer or company name was identified in the submitted material.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Legitimate job postings typically identify the hiring organization or authorized recruiting agency.",
                residual_uncertainty="Request the full registered legal name and website of the employer.",
            )
        )
    records.append(gleif_record)
    return EvidenceCategoryReport(
        category_number=1,
        category_id="employer_identity",
        category_name="Employer Identity",
        overall_status=_worst_status(records),
        summary=records[0].observed_result,
        records=records,
    )


def _build_vacancy_category(
    extracted: ExtractedJobData,
    gh_rec: EvidenceRecord,
    lever_rec: EvidenceRecord,
    ts: str,
) -> EvidenceCategoryReport:
    if extracted.requisition_id.status == "extracted":
        req_record = EvidenceRecord(
            check_name="Requisition / Job ID Presence",
            source_examined="User-submitted text",
            source_type="user_supplied",
            observed_result=f"Extracted Requisition/Job ID: {extracted.requisition_id.value}.",
            supporting_quotation=extracted.requisition_id.supporting_snippet,
            status=EvidenceStatus.UNVERIFIED,
            timestamp=ts,
            explanation="A requisition ID was supplied, but it has not yet been matched against a live ATS database.",
            residual_uncertainty="Search this requisition ID directly on the employer's official career portal.",
        )
    else:
        req_record = EvidenceRecord(
            check_name="Requisition / Job ID Presence",
            source_examined="User-submitted text",
            source_type="user_supplied",
            observed_result="No requisition ID or vacancy code was found in the submission.",
            status=EvidenceStatus.UNVERIFIED,
            timestamp=ts,
            explanation="Many small-company postings omit requisition IDs, while larger enterprises usually assign one.",
            residual_uncertainty="Ask for the public job posting link or requisition ID.",
        )
    records = [req_record, gh_rec, lever_rec]
    status = _worst_status(records)
    return EvidenceCategoryReport(
        category_number=2,
        category_id="vacancy_verification",
        category_name="Vacancy and Requisition Verification",
        overall_status=status,
        summary=(
            "Live ATS vacancy match confirmed."
            if status == EvidenceStatus.CONFIRMED_BY_SOURCE
            else "Vacancy could not be independently confirmed via public ATS boards."
        ),
        records=records,
    )


def _build_recruiter_category(
    extracted: ExtractedJobData,
    indicators: List[DetectionIndicator],
    ts: str,
) -> EvidenceCategoryReport:
    records: List[EvidenceRecord] = []
    messaging_ind = next(
        (i for i in indicators if "WhatsApp" in i.category or "Off-Platform" in i.category or "Text-Only" in i.category),
        None,
    )
    if messaging_ind:
        records.append(
            EvidenceRecord(
                check_name="Recruitment Communication Channel",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result="Recruiter directs candidates to off-platform chat apps (WhatsApp, Telegram, or Signal).",
                supporting_quotation=messaging_ind.matched_text,
                status=EvidenceStatus.SUSPICIOUS_SIGNAL,
                timestamp=ts,
                explanation=messaging_ind.explanation,
                residual_uncertainty="Verify whether the recruiter also communicates via an official corporate email.",
            )
        )
    if extracted.phone.status == "extracted":
        records.append(
            EvidenceRecord(
                check_name="Contact Phone Extraction",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result=f"Phone number detected: {extracted.phone.value}.",
                supporting_quotation=extracted.phone.supporting_snippet,
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Personal or mobile phone numbers cannot be independently verified without corporate directory lookup.",
                residual_uncertainty="Do not rely solely on caller ID or messaging display pictures.",
            )
        )
    if not records:
        records.append(
            EvidenceRecord(
                check_name="Recruiter Contact Details",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result="No phone number or messaging handle was provided.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Recruiter identity should be confirmed via official corporate channels.",
                residual_uncertainty="Check recruiter profile on LinkedIn and verify corporate email.",
            )
        )
    return EvidenceCategoryReport(
        category_number=3,
        category_id="recruiter_contact",
        category_name="Recruiter Contact Verification",
        overall_status=_worst_status(records),
        summary=records[0].observed_result,
        records=records,
    )


def _build_email_category(
    extracted: ExtractedJobData,
    registry_entry: Optional[EmployerRegistryEntry],
    recruiter_info: Dict[str, object],
    mx_rec: EvidenceRecord,
    ts: str,
) -> EvidenceCategoryReport:
    records = [
        EvidenceRecord(
            check_name="Recruiter Email vs. Employer Domain Alignment",
            source_examined="Extracted email & Employer Reference Registry",
            source_type="curated_registry" if registry_entry else "local_heuristic",
            observed_result=(
                f"Email: {recruiter_info['email']} (domain: {recruiter_info['email_domain']})"
                if recruiter_info["email"]
                else "No recruiter email address present."
            ),
            supporting_quotation=extracted.recruiter_email.supporting_snippet,
            status=recruiter_info["alignment_status"],  # type: ignore[arg-type]
            timestamp=ts,
            explanation=str(recruiter_info["alignment_explanation"]),
            residual_uncertainty="Pasted text cannot verify SPF/DKIM/DMARC email headers; inspect full headers in your mail client.",
        ),
        mx_rec,
    ]
    return EvidenceCategoryReport(
        category_number=4,
        category_id="email_domain_alignment",
        category_name="Email and Domain Alignment",
        overall_status=_worst_status(records),
        summary=str(recruiter_info["alignment_explanation"]),
        records=records,
    )


def _build_url_category(
    url_inspections: List[URLInspectionResult],
    registry_entry: Optional[EmployerRegistryEntry],
    rep_rec: Optional[EvidenceRecord],
    ts: str,
) -> EvidenceCategoryReport:
    records: List[EvidenceRecord] = []
    if url_inspections:
        for u_res in url_inspections:
            u_status = (
                EvidenceStatus.SUSPICIOUS_SIGNAL
                if u_res.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)
                else (
                    EvidenceStatus.CONFIRMED_BY_SOURCE
                    if (registry_entry and u_res.registrable_domain in registry_entry.official_domains)
                    else EvidenceStatus.UNVERIFIED
                )
            )
            records.append(
                EvidenceRecord(
                    check_name=f"Zero-Visit URL Structural Inspection ({u_res.registrable_domain or u_res.hostname})",
                    source_examined=u_res.submitted_url,
                    source_type="local_heuristic",
                    observed_result=u_res.summary,
                    supporting_quotation=u_res.submitted_url,
                    status=u_status,
                    timestamp=ts,
                    explanation="; ".join(s.explanation for s in u_res.signals) if u_res.signals else "No structural phishing anomalies found.",
                    residual_uncertainty="URL was never visited automatically; structural inspection cannot detect compromised pages on legitimate hosts.",
                )
            )
        if rep_rec is not None:
            records.append(rep_rec)
    else:
        records.append(
            EvidenceRecord(
                check_name="URL Extraction & Structural Inspection",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result="No job or application URLs were found in the submitted text.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Without an official application link, the career portal domain cannot be verified.",
                residual_uncertainty="Ask for the official career portal URL and inspect it before clicking.",
            )
        )
    return EvidenceCategoryReport(
        category_number=5,
        category_id="link_domain_safety",
        category_name="Link and Domain Safety",
        overall_status=_worst_status(records),
        summary=records[0].observed_result,
        records=records,
    )


def _build_payment_category(
    indicators: List[DetectionIndicator],
    has_disclaimer: bool,
    ts: str,
) -> EvidenceCategoryReport:
    pay_inds = [i for i in indicators if i.category in PAYMENT_OR_CRED_CATEGORIES or i.severity == Severity.CRITICAL]
    if pay_inds:
        records = [
            EvidenceRecord(
                check_name=ind.category,
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result=f"Detected {ind.category} ({ind.severity.value} severity).",
                supporting_quotation=ind.matched_text,
                status=EvidenceStatus.SUSPICIOUS_SIGNAL,
                timestamp=ts,
                explanation=ind.explanation,
                residual_uncertainty="Verify directly with official HR; legitimate hiring does not require upfront payments or sensitive credentials.",
            )
            for ind in pay_inds
        ]
    else:
        records = [
            EvidenceRecord(
                check_name="Upfront Payment, Deposit & Credential Request Check",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result=(
                    "Contains an explicit anti-fraud safety disclaimer stating no fees are charged."
                    if has_disclaimer
                    else "No upfront fee, security deposit, OTP/UPI PIN, or remote-access software demands detected."
                ),
                status=EvidenceStatus.CONFIRMED_BY_SOURCE if has_disclaimer else EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation=(
                    "Anti-fraud disclaimers are recognized as protective notices rather than scam triggers."
                    if has_disclaimer
                    else "Absence of payment demands in the initial message does not guarantee a fee will not be requested later."
                ),
                residual_uncertainty="Stay alert if payment, deposit, or sensitive credentials are requested in later messages or calls.",
            )
        ]
    return EvidenceCategoryReport(
        category_number=6,
        category_id="payment_sensitive_info",
        category_name="Payment and Sensitive Information Requests",
        overall_status=_worst_status(records),
        summary=records[0].observed_result,
        records=records,
    )


def _build_consistency_category(
    extracted: ExtractedJobData,
    conflicts: List[dict],
    secondary_text: str,
    ts: str,
) -> EvidenceCategoryReport:
    if conflicts:
        records = [
            EvidenceRecord(
                check_name=f"Consistency Check: {c['field']}",
                source_examined="Primary vs. Secondary Submitted Materials",
                source_type="local_heuristic",
                observed_result=c["explanation"],
                supporting_quotation=f"{c['primary_value']} <-> {c['secondary_value']}",
                status=EvidenceStatus.INCONSISTENT,
                timestamp=ts,
                explanation=c["explanation"],
                residual_uncertainty="Resolve all discrepancies directly with verified corporate HR before signing or sharing documents.",
            )
            for c in conflicts
        ]
    elif secondary_text:
        records = [
            EvidenceRecord(
                check_name="Cross-Document Field Comparison",
                source_examined="Primary & Secondary Submitted Materials",
                source_type="local_heuristic",
                observed_result="No contradictions detected across overlapping extracted fields in the two submitted materials.",
                status=EvidenceStatus.CONFIRMED_BY_SOURCE,
                timestamp=ts,
                explanation="Extracted employer, role, salary, location, and email fields did not conflict.",
                residual_uncertainty="Manual review of fine-print offer terms is still recommended.",
            )
        ]
    else:
        missing_core = [
            name
            for name in ("employer", "role", "salary", "location", "recruiter_email")
            if getattr(extracted, name).status == "missing"
        ]
        records = [
            EvidenceRecord(
                check_name="Single-Document Completeness & Consistency",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result=(
                    f"Single document submitted; {len(missing_core)} core field(s) missing ({', '.join(missing_core)})."
                    if missing_core
                    else "All core job-posting fields are present; no secondary document supplied for cross-comparison."
                ),
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Submit an offer letter or recruiter email alongside the job description to run cross-document comparison.",
                residual_uncertainty="Cross-document consistency could not be evaluated without a second source.",
            )
        ]
    return EvidenceCategoryReport(
        category_number=7,
        category_id="document_consistency",
        category_name="Document and Message Consistency",
        overall_status=_worst_status(records),
        summary=records[0].observed_result,
        records=records,
    )


def _compute_risk_assessment(
    indicators: List[DetectionIndicator],
    url_inspections: List[URLInspectionResult],
    conflicts: List[dict],
    has_disclaimer: bool,
    registry_entry: Optional[EmployerRegistryEntry],
    ml_scam_prob: float,
) -> Tuple[RiskLevel, int, str]:
    crit_cnt = high_cnt = med_cnt = low_cnt = 0
    for ind in indicators:
        if ind.severity == Severity.CRITICAL:
            crit_cnt += 1
        elif ind.severity == Severity.HIGH:
            high_cnt += 1
        elif ind.severity == Severity.MEDIUM:
            med_cnt += 1
        elif ind.severity == Severity.LOW:
            low_cnt += 1
    max_url_risk = max((u.risk_index for u in url_inspections), default=0)

    raw_score = crit_cnt * 44 + high_cnt * 32 + med_cnt * 18 + low_cnt * 10
    if max_url_risk >= 60 and crit_cnt == 0:
        raw_score = max(raw_score, max_url_risk)
    elif max_url_risk >= 25:
        raw_score += int(max_url_risk * 0.25)
    if has_disclaimer and crit_cnt == 0 and high_cnt == 0 and max_url_risk < 40:
        raw_score = min(raw_score, 10)
    if ml_scam_prob >= 0.8 and (crit_cnt + high_cnt + med_cnt) > 0:
        raw_score += 6

    if crit_cnt >= 1 or high_cnt >= 2 or raw_score >= 65:
        return (
            RiskLevel.HIGH,
            max(74, min(98, raw_score + (30 if raw_score < 74 else 0))),
            "HIGH RISK — Multiple serious fraud indicators or strong contradictory evidence.",
        )
    if high_cnt >= 1 or med_cnt >= 1 or conflicts or raw_score >= 25:
        return (
            RiskLevel.MEDIUM,
            max(36, min(68, raw_score + (14 if raw_score < 36 else 0))),
            "MEDIUM RISK — Concerning indicators or important unverified information.",
        )
    return (
        RiskLevel.LOW,
        6 if has_disclaimer else (8 if registry_entry else 12),
        "LOW RISK — No strong suspicious indicators identified (verify unconfirmed details).",
    )


def _enrich_indicators(
    indicators: List[DetectionIndicator],
    url_inspections: List[URLInspectionResult],
    recruiter_info: Dict[str, object],
    registry_entry: Optional[EmployerRegistryEntry],
    conflicts: List[dict],
) -> None:
    """Append URL, email-domain, and cross-document consistency indicators in place."""
    for u_res in url_inspections:
        if u_res.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            sig_desc = "; ".join(s.explanation for s in u_res.signals[:2]) or u_res.summary
            indicators.append(
                DetectionIndicator(
                    id=f"url_signal_{len(indicators) + 1}",
                    category="Fake Career Portal / Suspicious URL" if u_res.impersonated_brand else "Suspicious Recruitment Link",
                    matched_text=u_res.submitted_url,
                    severity=Severity.CRITICAL if u_res.impersonated_brand else (Severity.HIGH if u_res.risk_level == RiskLevel.HIGH else Severity.MEDIUM),
                    explanation=sig_desc,
                    explanation_hi=f"संदिग्ध लिंक '{u_res.registrable_domain}': बिना आधिकारिक पुष्टि के इस लिंक को न खोलें।",
                    detection_method="zero_visit_url_inspector",
                    reason_it_matters="Fraudulent career portals mimic real companies to steal resumes, identity documents, or registration fees.",
                    suggested_action=u_res.recommended_actions[0] if u_res.recommended_actions else "Do not open this link.",
                )
            )
    if recruiter_info["is_lookalike_email_domain"]:
        indicators.append(
            DetectionIndicator(
                id=f"lookalike_email_{len(indicators) + 1}", category="Lookalike Recruiter Email Domain",
                matched_text=str(recruiter_info["email"]), severity=Severity.HIGH,
                explanation=str(recruiter_info["alignment_explanation"]),
                explanation_hi="रिक्रूटर का ईमेल डोमेन कंपनी के आधिकारिक डोमेन से मेल नहीं खाता।",
                detection_method="email_domain_alignment",
                reason_it_matters="Scammers register lookalike domains to impersonate corporate HR.",
                suggested_action="Verify the recruiter's email address against the company's official corporate domain.",
            )
        )
    elif recruiter_info["domain_mismatch"] and recruiter_info["is_personal_email"] and registry_entry:
        indicators.append(
            DetectionIndicator(
                id=f"personal_email_corp_{len(indicators) + 1}", category="Personal Email Claiming Major Corporate Employer",
                matched_text=str(recruiter_info["email"]), severity=Severity.MEDIUM,
                explanation=str(recruiter_info["alignment_explanation"]),
                explanation_hi="बड़ी कंपनी के नाम पर व्यक्तिगत जीमेल/याहू ईमेल का उपयोग किया गया है।",
                detection_method="email_domain_alignment",
                reason_it_matters="Large enterprises almost always send official offers from corporate domains.",
                suggested_action="Ask the recruiter to email you from their verified corporate domain before proceeding.",
            )
        )
    for c in conflicts:
        indicators.append(
            DetectionIndicator(
                id=f"consistency_conflict_{len(indicators) + 1}", category="Document & Communication Inconsistency",
                matched_text=f"{c['primary_value']} vs {c['secondary_value']}", severity=Severity.HIGH,
                explanation=c["explanation"],
                explanation_hi="दस्तावेजों या संदेशों में कंपनी, पद या वेतन की जानकारी में विरोधाभास पाया गया है।",
                detection_method="cross_document_consistency",
                reason_it_matters="Conflicting company names, roles, or salaries across offer letters and job posts are strong signs of a fabricated template.",
                suggested_action="Clarify the discrepancy directly through the employer's official HR contact.",
            )
        )


def _recommended_actions_for(risk_level: RiskLevel) -> Tuple[List[str], List[str]]:
    en = (
        [
            "Do not pay any registration fee, security deposit, training fee, or task recharge.",
            "Do not open unverified career links or install AnyDesk / TeamViewer.",
            "Never share OTPs, UPI PINs, ATM PINs, CVV, or banking passwords with any recruiter.",
            "If you already transferred money in India, dial 1930 immediately and report on cybercrime.gov.in.",
        ]
        if risk_level == RiskLevel.HIGH
        else [
            "Independently look up the company's official website and career portal to verify the vacancy.",
            "Ask the recruiter to communicate from a verified corporate email address.",
            "Never pay upfront fees or share Aadhaar/PAN/banking details before verifying the employer.",
        ]
        if risk_level == RiskLevel.MEDIUM
        else [
            "Even with low detected risk, confirm the role directly on the company's official career page.",
            "Treat any later demand for fees, deposits, or OTPs as an immediate red flag.",
        ]
    )
    hi = [
        "किसी भी रजिस्ट्रेशन फीस, सिक्योरिटी डिपॉजिट या प्रीपेड टास्क के लिए पैसे न दें।",
        "असत्यापित करियर लिंक न खोलें और न ही AnyDesk या TeamViewer इंस्टॉल करें।",
        "अपना ओटीपी, यूपीआई पिन या बैंक पासवर्ड किसी भी रिक्रूटर के साथ साझा न करें।",
        "वित्तीय धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत दर्ज करें।",
    ]
    return en, hi


async def build_verification_report(req: VerifyRequest) -> VerificationReport:
    """Execute all verification layers (A–H) concurrently and assemble the 7-category evidence report."""
    ts = _now_iso()
    raw_text = sanitize_plain_text(req.text)
    secondary_text = sanitize_plain_text(req.secondary_text or "")
    job_url = (req.job_url or "").strip() or None

    extracted = apply_user_field_edits(
        extract_structured_job_data(raw_text, job_url=job_url, language_hint=req.language_hint), req.edited_fields
    )
    redacted_preview, redaction_counts = redact_sensitive_info(raw_text) if req.redact_sensitive else (raw_text, {})
    indicators, has_disclaimer = run_rule_analysis(raw_text, extracted)

    all_urls = extract_urls_from_text(raw_text)
    if extracted.job_url.value and extracted.job_url.value not in all_urls:
        all_urls.insert(0, extracted.job_url.value)
    url_inspections = [inspect_url_structurally(u) for u in all_urls[:8]]

    employer_name = extracted.employer.value if extracted.employer.status == "extracted" else None
    registry_entry = lookup_employer_in_registry(employer_name)
    recruiter_info = analyze_recruiter_and_domain_alignment(extracted, registry_entry)
    conflicts = compare_document_consistency(raw_text, extracted, secondary_text)
    _enrich_indicators(indicators, url_inspections, recruiter_info, registry_entry, conflicts)

    gh_token = registry_entry.ats_slug if (registry_entry and registry_entry.ats_provider == "greenhouse" and req.run_external_checks) else None
    gleif_rec, gh_rec, lever_rec, mx_rec, rep_rec = await asyncio.gather(
        check_gleif_employer(employer_name if req.run_external_checks else None),
        check_greenhouse_vacancy(gh_token, extracted.role.value, extracted.requisition_id.value),
        check_lever_vacancy(None, extracted.role.value),
        check_cloudflare_mx(str(recruiter_info["email_domain"]) if (req.run_external_checks and recruiter_info["email_domain"]) else None),
        check_url_reputation(url_inspections[0].normalized_url if (req.run_external_checks and url_inspections) else None),
    )

    categories = [
        _build_employer_category(extracted, registry_entry, gleif_rec, ts),
        _build_vacancy_category(extracted, gh_rec, lever_rec, ts),
        _build_recruiter_category(extracted, indicators, ts),
        _build_email_category(extracted, registry_entry, recruiter_info, mx_rec, ts),
        _build_url_category(url_inspections, registry_entry, rep_rec if url_inspections else None, ts),
        _build_payment_category(indicators, has_disclaimer, ts),
        _build_consistency_category(extracted, conflicts, secondary_text, ts),
    ]

    ml_res = run_ml_classification(raw_text)
    risk_level, risk_index, risk_headline = _compute_risk_assessment(
        indicators, url_inspections, conflicts, has_disclaimer, registry_entry, ml_res.scam_probability_estimate
    )
    all_records = [r for cat in categories for r in cat.records]
    confirmed = sum(1 for r in all_records if r.status == EvidenceStatus.CONFIRMED_BY_SOURCE)
    unverified = sum(1 for r in all_records if r.status == EvidenceStatus.UNVERIFIED)
    unavailable = sum(1 for r in all_records if r.status == EvidenceStatus.CHECK_UNAVAILABLE)
    inconsistent = sum(1 for r in all_records if r.status == EvidenceStatus.INCONSISTENT)
    suspicious = sum(1 for r in all_records if r.status == EvidenceStatus.SUSPICIOUS_SIGNAL)
    coverage = int(round(((confirmed + inconsistent + suspicious) / max(1, len(all_records))) * 100))

    what_verified = [f"{c.category_name}: {r.check_name} — {r.observed_result}" for c in categories for r in c.records if r.status == EvidenceStatus.CONFIRMED_BY_SOURCE]
    what_not_verified = [f"{c.category_name}: {r.check_name} ({r.status.value}) — {r.residual_uncertainty}" for c in categories for r in c.records if r.status in (EvidenceStatus.UNVERIFIED, EvidenceStatus.CHECK_UNAVAILABLE)]
    rec_en, rec_hi = _recommended_actions_for(risk_level)

    return VerificationReport(
        report_id=f"jg-{uuid.uuid4().hex[:10]}", timestamp=ts, is_demo=req.is_demo,
        detected_language=extracted.detected_language, interface_language=req.interface_language,
        risk_index=risk_index, risk_level=risk_level, risk_headline=risk_headline,
        risk_index_disclaimer="This 0–100 Risk Index is an explainable heuristic assessment derived from deterministic rules, domain/URL structure, and evidence consistency—NOT a mathematically calibrated probability of fraud.",
        evidence_coverage_percent=coverage,
        verification_confidence="Moderate-to-High (Multiple Checks Evaluated)" if (coverage >= 65 and unavailable <= 2) else "Partial (Local Checks Complete; External Checks Limited)" if coverage >= 35 else "Limited (Several Details Missing or Unverified)",
        suspicious_indicator_count=len(indicators), confirmed_check_count=confirmed,
        unverified_check_count=unverified, unavailable_check_count=unavailable, inconsistent_check_count=inconsistent,
        extracted_data=extracted, indicators=indicators, url_inspections=url_inspections, categories=categories,
        recommended_actions=rec_en, recommended_actions_hi=rec_hi,
        what_was_verified=what_verified, what_could_not_be_verified=what_not_verified,
        ml_assessment=ml_res,
        ai_explanation=generate_grounded_explanation(risk_level, risk_index, indicators, categories, what_not_verified, req.interface_language),
        redacted_input_preview=redacted_preview[:1500], redaction_counts=redaction_counts,
        limitations=[
            "Local verification never opens or fetches arbitrary user-submitted URLs.",
            "External ATS (Greenhouse/Lever), corporate (GLEIF/OpenCorporates), DNS MX, and reputation checks are optional and honestly marked 'Check Unavailable' when disabled or unreachable.",
            "An unknown company not present in the curated reference registry is marked 'Unverified', never automatically classified as fraudulent.",
        ],
    )
