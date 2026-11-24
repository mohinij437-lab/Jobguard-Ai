"""Optional AI Explanation Service — strictly grounded in verified report evidence."""
from __future__ import annotations

import os
from typing import List

from .schemas import AIExplanation, DetectionIndicator, EvidenceCategoryReport, EvidenceStatus, RiskLevel


def _build_risk_summary(
    risk_level: RiskLevel,
    risk_index: int,
    indicator_count: int,
    suspicious_cats: List[str],
    confirmed_cats: List[str],
    is_hi: bool,
) -> str:
    if risk_level == RiskLevel.HIGH:
        if is_hi:
            return f"उच्च जोखिम ({risk_index}/100): {indicator_count} गंभीर चेतावनी संकेत पाए गए हैं ({', '.join(suspicious_cats[:3]) or 'भर्ती धोखाधड़ी पैटर्न'})। किसी भी प्रकार का शुल्क या ओटीपी/पिन साझा न करें।"
        return f"High Risk ({risk_index}/100 heuristic index): JobGuard AI identified {indicator_count} serious warning signal(s) affecting {', '.join(suspicious_cats[:3]) or 'recruitment safety'}. Do not pay any fee, click unverified links, or share sensitive codes."
    if risk_level == RiskLevel.MEDIUM:
        if is_hi:
            return f"मध्यम जोखिम ({risk_index}/100): कुछ संदिग्ध संकेत या असत्यापित जानकारी मिली है। कंपनी की आधिकारिक वेबसाइट से स्वतंत्र पुष्टि किए बिना आगे न बढ़ें।"
        return f"Medium Risk ({risk_index}/100 heuristic index): This opportunity contains concerning signals or important unverified details. Independently verify the employer and vacancy before proceeding."
    if is_hi:
        return f"कम जोखिम ({risk_index}/100): कोई मजबूत धोखाधड़ी संकेत नहीं मिला, लेकिन स्वचालित जांच 100% वैधता की गारंटी नहीं देती।"
    confirmed_note = f"Confirmed checks: {', '.join(confirmed_cats)}. " if confirmed_cats else "However, key details remain unverified—absence of red flags is not proof of legitimacy."
    return f"Low Risk ({risk_index}/100 heuristic index): No strong recruitment-fraud signals were detected in the submitted material. {confirmed_note}"


def generate_grounded_explanation(
    risk_level: RiskLevel,
    risk_index: int,
    indicators: List[DetectionIndicator],
    categories: List[EvidenceCategoryReport],
    what_could_not_be_verified: List[str],
    interface_language: str = "en",
) -> AIExplanation:
    """Translate structured evidence into clear, plain-language advice without inventing facts."""
    llm_configured = bool(os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY"))
    suspicious_cats = [c.category_name for c in categories if c.overall_status in (EvidenceStatus.SUSPICIOUS_SIGNAL, EvidenceStatus.INCONSISTENT)]
    confirmed_cats = [c.category_name for c in categories if c.overall_status == EvidenceStatus.CONFIRMED_BY_SOURCE]

    summary = _build_risk_summary(risk_level, risk_index, len(indicators), suspicious_cats, confirmed_cats, interface_language == "hi")
    advice = [ind.suggested_action for ind in indicators[:3]] or [
        "Cross-check the job opening on the company's official career portal typed manually in your browser.",
        "Never pay registration, training, or security deposit fees at any stage of hiring.",
        "Confirm recruiter identity via an official corporate email address and LinkedIn presence.",
    ]
    uncertainty_note = (
        f"{len(what_could_not_be_verified)} verification area(s) could not be independently confirmed."
        if what_could_not_be_verified
        else "All available checks were evaluated; always verify offer letters directly with the employer."
    )
    return AIExplanation(
        provider=(
            "deterministic_evidence_explainer (external LLM key present; offline-safe local grounding used)"
            if llm_configured
            else "deterministic_evidence_explainer (local, zero external API required)"
        ),
        used_external_llm=False,
        summary=summary,
        plain_language_advice=list(dict.fromkeys(advice)),
        uncertainty_note=uncertainty_note,
    )
