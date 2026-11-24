"""Layer B & Pre-Analysis Extraction: 10-field structured job data extractor and PDF/DOCX/TXT parser.

All regular expressions are precompiled at module load for optimal runtime efficiency.
"""
from __future__ import annotations

import io
import re
from typing import Dict, List, Optional, Tuple

from .schemas import ExtractedField, ExtractedJobData
from .url_inspector import extract_urls_from_text

# Precompiled regex patterns for high-efficiency extraction
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PHONE_REGEX = re.compile(
    r"(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|\+\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{4}\b"
)
DEVANAGARI_REGEX = re.compile(r"[\u0900-\u097F]")
LATIN_REGEX = re.compile(r"[A-Za-z]")
HINGLISH_MARKERS = re.compile(
    r"\b(aapka|aapke|abhi|karo|karein|turant|bhejo|jama|paisa|paise|naukri|kaam|ghar\s+baithe|"
    r"bina\s+interview|mahina|roz|kamayein|kamao|fees|pehle|sampark|vetan|bharti)\b",
    re.IGNORECASE,
)

EMPLOYER_PATTERNS: Tuple[Tuple[re.Pattern, float], ...] = (
    (
        re.compile(
            r"(?i)(?:company|employer|organization|organisation|hiring\s+at|from)\s*[:\-]\s*"
            r"([A-Z][A-Za-z0-9&.,'()\- ]{1,60}?)(?=\s*(?:\n|\||,|;|\.|for\s+the|is\s+hiring|$))"
        ),
        0.90,
    ),
    (
        re.compile(
            r"(?i)(?:welcome\s+to|offer\s+(?:of\s+employment\s+)?(?:from|at)|selected\s+(?:at|by|for)|joining)\s+"
            r"([A-Z][A-Za-z0-9&.,\- ]{2,50}?)(?=\s*(?:\n|\.|,|as\s+a|for\s+the|!|$))"
        ),
        0.80,
    ),
    (
        re.compile(
            r"(?i)\b(Infosys|TCS|Tata Consultancy Services|Wipro|HCLTech|HCL Technologies|Accenture|"
            r"Cognizant|Capgemini|Tech Mahindra|Google|Microsoft|Amazon|Meta|Flipkart|Zoho|Deloitte|"
            r"PwC|KPMG|EY|IBM|Oracle|Razorpay|Swiggy|Zomato|Paytm|Reliance Jio|Jio)\b"
        ),
        0.82,
    ),
)
EMPLOYER_STOPWORDS_RE = re.compile(r"^(?:the|our|your|this|a|an|hr|team)$", re.I)

ROLE_PATTERNS: Tuple[Tuple[re.Pattern, float], ...] = (
    (
        re.compile(
            r"(?i)(?:job\s+title|role|position|designation|profile|post|vacancy)\s*[:\-]\s*"
            r"([A-Za-z0-9/()&,\- ]{2,70}?)(?=\s*(?:\n|\||;|\.|salary|location|ctc|experience|$))"
        ),
        0.90,
    ),
    (
        re.compile(
            r"(?i)(?:hiring\s+(?:for\s+)?(?:a\s+|an\s+)?|looking\s+for\s+(?:a\s+|an\s+)?|selected\s+as\s+(?:a\s+|an\s+)?)"
            r"([A-Z][A-Za-z0-9/\- ]{2,55}?(?:Engineer|Developer|Intern|Analyst|Manager|Executive|"
            r"Associate|Specialist|Designer|Coordinator|Representative|Assistant|Consultant|Trainee|Tester|Operator))"
        ),
        0.82,
    ),
    (
        re.compile(
            r"(?i)\b(Software\s+(?:Development\s+)?Engineer|Frontend\s+Developer|Backend\s+Developer|"
            r"Full[\s-]Stack\s+Developer|Data\s+(?:Analyst|Scientist|Entry\s+Operator)|Web\s+Developer|"
            r"Marketing\s+Intern|HR\s+Intern|Business\s+Development\s+Executive|Customer\s+Support\s+Executive)\b"
        ),
        0.78,
    ),
)

SALARY_PATTERNS: Tuple[Tuple[re.Pattern, float], ...] = (
    (
        re.compile(
            r"(?i)(?:salary|ctc|package|stipend|compensation|pay|earning|earn)\s*[:\-]?\s*"
            r"((?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*(?:\.\d+)?)?\s*"
            r"(?:LPA|lakh|lakhs|k|K|per\s+month|/month|pm|per\s+day|daily|/day|per\s+week|/week|per\s+annum|/year)?)"
        ),
        0.88,
    ),
    (
        re.compile(
            r"(?i)((?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*(?:\.\d+)?)?\s*"
            r"(?:LPA|lakhs?\s*(?:per\s+annum)?|per\s+month|/month|pm|per\s+day|daily|/day|per\s+week|/week))"
        ),
        0.82,
    ),
    (re.compile(r"(?i)\b(\d{1,2}(?:\.\d+)?(?:\s*(?:-|to|–)\s*\d{1,2}(?:\.\d+)?)?\s*LPA)\b"), 0.85),
)

LOCATION_PATTERNS: Tuple[Tuple[re.Pattern, float], ...] = (
    (
        re.compile(
            r"(?i)(?:location|work\s+location|job\s+location|city|place)\s*[:\-]\s*"
            r"([A-Za-z0-9,/\-() ]{2,60}?)(?=\s*(?:\n|\||;|salary|ctc|apply|$))"
        ),
        0.88,
    ),
    (
        re.compile(
            r"(?i)\b(Bengaluru|Bangalore|Hyderabad|Pune|Mumbai|Navi Mumbai|Gurugram|Gurgaon|Noida|"
            r"New Delhi|Delhi NCR|Chennai|Kolkata|Lucknow|Ahmedabad|Jaipur|Remote\s*\(India\)|"
            r"Work\s+From\s+Home\s*/\s*Remote|Remote)\b"
        ),
        0.72,
    ),
)

REQUISITION_RE = re.compile(
    r"(?i)(?:requisition\s*(?:id|no\.?|number|#)|req\s*(?:id|no\.?|#)|job\s*(?:id|code|ref(?:erence)?)|"
    r"vacancy\s*(?:id|code)|ref(?:erence)?\s*(?:id|no\.?))\s*[:\-#]?\s*([A-Z0-9][A-Z0-9\-_/]{2,24})"
)

PAYMENT_REQUEST_RE = re.compile(
    r"(?i)((?:pay|deposit|transfer|send|jama\s+karo|jama\s+karein|dena\s+hoga|दें|जमा\s+करें)[^.\n]{0,70}?"
    r"(?:registration\s+fee|security\s+deposit|refundable\s+(?:deposit|fee)|processing\s+fee|training\s+fee|"
    r"laptop\s+deposit|verification\s+fee|prepaid\s+task|recharge|fee\s+of\s+(?:₹|Rs\.?|INR|\$)?\s*\d+|(?:₹|Rs\.?|INR|\$)\s*\d[\d,]*)"
    r"|(?:₹|Rs\.?|INR|\$)\s*\d[\d,]*(?:\s+only)?\s*(?:refundable\s+)?(?:registration|security|processing|training|verification|joining|kit|laptop)\s*(?:fee|fees|deposit|charge)"
    r"|सिक्योरिटी\s+डिपॉजिट|रजिस्ट्रेशन\s+फीस|प्रोसेसिंग\s+फीस)"
)
PAYMENT_NEGATION_RE = re.compile(
    r"(?i)\b(?:never|do\s+not|don't|no|does\s+not|doesn't|zero|without|free\s+of)\b|कभी\s+नहीं|न\s+दें|नहीं\s+मांग"
)

DEADLINE_PATTERNS: Tuple[Tuple[re.Pattern, float], ...] = (
    (
        re.compile(
            r"(?i)(?:deadline|last\s+date(?:\s+to\s+apply)?|apply\s+(?:by|before)|respond\s+(?:by|within)|offer\s+expires?)\s*[:\-]?\s*"
            r"([A-Za-z0-9,:/\- ]{3,45}?)(?=\s*(?:\n|\.|;|!|$))"
        ),
        0.86,
    ),
    (
        re.compile(
            r"(?i)\b(within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)|today\s+(?:by|before|at)\s+[0-9:]+\s*(?:am|pm)?|"
            r"tonight\s+at\s+[0-9:]+\s*(?:am|pm)?)\b"
        ),
        0.80,
    ),
)

EMP_TYPE_RE = re.compile(r"(?i)\b(full[\s-]time|part[\s-]time|internship|contract|freelance|temporary)\b")
WORK_MODE_RE = re.compile(r"(?i)\b(work\s+from\s+home|wfh|remote|hybrid|on[\s-]site|work\s+from\s+office)\b")
QUAL_RE = re.compile(r"(?i)(?:qualification|eligibility|education|degree)\s*[:\-]\s*([^\n.;]{3,80})")
EXP_RE = re.compile(
    r"(?i)(?:experience\s*[:\-]\s*([^\n.;]{2,40})|\b(\d+\s*(?:\+|to|-)\s*\d*\s*years?\s+(?:of\s+)?experience|"
    r"freshers?\s+(?:welcome|can\s+apply)|no\s+experience\s+(?:required|needed))\b)"
)

EDITABLE_FIELDS = frozenset(
    {
        "employer", "role", "salary", "recruiter_email", "phone",
        "location", "job_url", "requisition_id", "payment_requests", "deadlines",
    }
)


def detect_message_language(text: str, hint: str = "auto") -> str:
    """Detect English ('en'), Hindi ('hi'), or Hinglish ('hinglish')."""
    if hint in ("en", "hi", "hinglish"):
        return hint
    if not text:
        return "en"
    devanagari = len(DEVANAGARI_REGEX.findall(text))
    latin = len(LATIN_REGEX.findall(text))
    if devanagari >= 5 and devanagari >= latin * 0.2:
        return "hi"
    if HINGLISH_MARKERS.search(text):
        return "hinglish"
    return "en"


def _snippet(text: str, start: int, end: int, pad: int = 35) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    raw = text[s:e].replace("\n", " ").strip()
    return ("..." if s > 0 else "") + raw + ("..." if e < len(text) else "")


def _missing(field_name: str) -> ExtractedField:
    return ExtractedField(
        field_name=field_name, value=None, status="missing", confidence=0.0, supporting_snippet=None
    )


def _extracted(field_name: str, value: str, confidence: float, snippet: str) -> ExtractedField:
    return ExtractedField(
        field_name=field_name,
        value=value.strip(),
        status="extracted",
        confidence=round(min(1.0, max(0.0, confidence)), 2),
        supporting_snippet=snippet,
    )


def _extract_employer(text: str) -> ExtractedField:
    for pat, conf in EMPLOYER_PATTERNS:
        m = pat.search(text)
        if m:
            val = m.group(1).strip(" .,-|:")
            if len(val) >= 2 and not EMPLOYER_STOPWORDS_RE.match(val):
                return _extracted("employer", val, conf, _snippet(text, m.start(), m.end()))
    return _missing("employer")


def _extract_role(text: str) -> ExtractedField:
    for pat, conf in ROLE_PATTERNS:
        m = pat.search(text)
        if m:
            val = m.group(1).strip(" .,-|:")
            if len(val) >= 3:
                return _extracted("role", val, conf, _snippet(text, m.start(), m.end()))
    return _missing("role")


def _extract_salary(text: str) -> ExtractedField:
    fee_terms = ("registration fee", "security deposit", "processing fee", "refundable deposit", "fee of", "deposit of")
    for pat, conf in SALARY_PATTERNS:
        m = pat.search(text)
        if m:
            ctx = text[max(0, m.start() - 35):min(len(text), m.end() + 25)].lower()
            if any(k in ctx for k in fee_terms):
                continue
            return _extracted("salary", m.group(1).strip(), conf, _snippet(text, m.start(), m.end()))
    return _missing("salary")


def _extract_location(text: str) -> ExtractedField:
    for pat, conf in LOCATION_PATTERNS:
        m = pat.search(text)
        if m:
            return _extracted("location", m.group(1).strip(" .,-|:"), conf, _snippet(text, m.start(), m.end()))
    return _missing("location")


def _extract_requisition_id(text: str) -> ExtractedField:
    m = REQUISITION_RE.search(text)
    if m:
        return _extracted("requisition_id", m.group(1).strip(), 0.90, _snippet(text, m.start(), m.end()))
    return _missing("requisition_id")


def _extract_payment_requests(text: str) -> ExtractedField:
    for m in PAYMENT_REQUEST_RE.finditer(text):
        prefix = text[max(0, m.start() - 45):m.start()]
        if PAYMENT_NEGATION_RE.search(prefix):
            continue
        return _extracted("payment_requests", m.group(0).strip(), 0.92, _snippet(text, m.start(), m.end()))
    return _missing("payment_requests")


def _extract_deadlines(text: str) -> ExtractedField:
    for pat, conf in DEADLINE_PATTERNS:
        m = pat.search(text)
        if m:
            return _extracted("deadlines", m.group(1).strip(" .,-"), conf, _snippet(text, m.start(), m.end()))
    return _missing("deadlines")


def extract_structured_job_data(
    text: str,
    job_url: Optional[str] = None,
    language_hint: str = "auto",
) -> ExtractedJobData:
    """Extract all 10 required structured job fields with confidence and exact supporting snippets."""
    combined = (text or "").strip()
    if job_url and job_url.strip() and job_url.strip() not in combined:
        search_text = f"{combined}\nJob URL: {job_url.strip()}".strip()
    else:
        search_text = combined

    lang = detect_message_language(combined or (job_url or ""), language_hint)

    emails = list(dict.fromkeys(EMAIL_REGEX.findall(search_text)))
    phones = list(dict.fromkeys(p.strip() for p in PHONE_REGEX.findall(search_text)))
    urls = extract_urls_from_text(search_text)
    if job_url and job_url.strip() and job_url.strip() not in urls:
        urls.insert(0, job_url.strip())

    if emails:
        m = EMAIL_REGEX.search(search_text)
        recruiter_email = _extracted(
            "recruiter_email",
            emails[0],
            0.95,
            _snippet(search_text, m.start(), m.end()) if m else emails[0],
        )
    else:
        recruiter_email = _missing("recruiter_email")

    if phones:
        m = PHONE_REGEX.search(search_text)
        phone_field = _extracted(
            "phone",
            phones[0],
            0.90,
            _snippet(search_text, m.start(), m.end()) if m else phones[0],
        )
    else:
        phone_field = _missing("phone")

    if urls:
        primary_url = job_url.strip() if (job_url and job_url.strip()) else urls[0]
        idx = search_text.find(primary_url)
        snip = _snippet(search_text, idx, idx + len(primary_url)) if idx >= 0 else primary_url
        url_field = _extracted("job_url", primary_url, 0.96, snip)
    else:
        url_field = _missing("job_url")

    emp_type_m = EMP_TYPE_RE.search(search_text)
    work_mode_m = WORK_MODE_RE.search(search_text)
    qual_m = QUAL_RE.search(search_text)
    exp_m = EXP_RE.search(search_text)

    return ExtractedJobData(
        employer=_extract_employer(search_text),
        role=_extract_role(search_text),
        salary=_extract_salary(search_text),
        recruiter_email=recruiter_email,
        phone=phone_field,
        location=_extract_location(search_text),
        job_url=url_field,
        requisition_id=_extract_requisition_id(search_text),
        payment_requests=_extract_payment_requests(search_text),
        deadlines=_extract_deadlines(search_text),
        additional_emails=emails[1:],
        additional_phones=phones[1:],
        additional_urls=[u for u in urls if u != (url_field.value or "")],
        employment_type=emp_type_m.group(1) if emp_type_m else None,
        work_mode=work_mode_m.group(1) if work_mode_m else None,
        qualifications=qual_m.group(1).strip() if qual_m else None,
        experience_required=(exp_m.group(1) or exp_m.group(2)).strip() if exp_m else None,
        detected_language=lang,
    )


def apply_user_field_edits(
    extracted: ExtractedJobData, edits: Optional[Dict[str, Optional[str]]]
) -> ExtractedJobData:
    """Apply user-reviewed corrections from Pre-Analysis Extraction Review."""
    if not edits:
        return extracted
    data = extracted.model_copy(deep=True) if hasattr(extracted, "model_copy") else extracted.copy(deep=True)
    for key, val in edits.items():
        if key not in EDITABLE_FIELDS:
            continue
        cleaned = (val or "").strip() if val is not None else ""
        if cleaned:
            setattr(
                data,
                key,
                ExtractedField(
                    field_name=key,
                    value=cleaned,
                    status="extracted",
                    confidence=1.0,
                    supporting_snippet="Confirmed/edited by user during Pre-Analysis Extraction Review.",
                ),
            )
        else:
            setattr(data, key, _missing(key))
    return data


def extract_text_from_document_bytes(
    filename: str, content: bytes
) -> Tuple[str, str, List[str]]:
    """Extract text from PDF, DOCX, or TXT with explicit warnings and errors."""
    lower = (filename or "").lower()
    warnings: List[str] = []

    if lower.endswith(".txt"):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1", errors="replace")
            warnings.append("File was not UTF-8 encoded; decoded using Latin-1 fallback.")
        if not text.strip():
            warnings.append("The uploaded TXT file appears to be empty.")
        return text.strip(), "txt", warnings

    if lower.endswith(".pdf"):
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(content))
            if reader.is_encrypted:
                raise ValueError("PDF is password-protected/encrypted and cannot be read.")
            pages_text: List[str] = []
            for idx, page in enumerate(reader.pages):
                page_txt = (page.extract_text() or "").strip()
                if page_txt:
                    pages_text.append(page_txt)
                else:
                    warnings.append(
                        f"Page {idx + 1} contained no selectable text (it may be a scanned image — use Screenshot OCR)."
                    )
            full_text = "\n\n".join(pages_text).strip()
            if not full_text:
                warnings.append(
                    "No selectable text could be extracted from this PDF. If it is a scanned offer letter, run Screenshot OCR."
                )
            return full_text, "pdf", warnings
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Failed to parse PDF document: {exc}") from exc

    if lower.endswith(".docx"):
        try:
            from docx import Document

            doc = Document(io.BytesIO(content))
            parts: List[str] = [p.text.strip() for p in doc.paragraphs if p.text and p.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    row_cells = [c.text.strip() for c in row.cells if c.text and c.text.strip()]
                    if row_cells:
                        parts.append(" | ".join(row_cells))
            full_text = "\n".join(parts).strip()
            if not full_text:
                warnings.append("DOCX document contained no readable paragraphs or table text.")
            return full_text, "docx", warnings
        except Exception as exc:
            raise ValueError(f"Failed to parse DOCX document: {exc}") from exc

    if lower.endswith(".json"):
        import json
        try:
            raw_text = content.decode("utf-8")
        except UnicodeDecodeError:
            raw_text = content.decode("latin-1", errors="replace")
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                if "report_id" in parsed and "extracted_data" in parsed:
                    ext = parsed["extracted_data"]
                    lines = [
                        f"Company: {ext.get('employer', {}).get('value') or ''}",
                        f"Role: {ext.get('role', {}).get('value') or ''}",
                        f"Salary: {ext.get('salary', {}).get('value') or ''}",
                        f"Location: {ext.get('location', {}).get('value') or ''}",
                        f"Email: {ext.get('recruiter_email', {}).get('value') or ''}",
                        f"URL: {ext.get('job_url', {}).get('value') or ''}",
                    ]
                    return "\n".join(l for l in lines if l.split(": ")[1]), "json", warnings
                lines = [f"{k}: {v}" for k, v in parsed.items() if isinstance(v, (str, int, float, bool))]
                return "\n".join(lines), "json", warnings
            elif isinstance(parsed, list):
                return "\n".join(str(x) for x in parsed), "json", warnings
            return raw_text.strip(), "json", warnings
        except json.JSONDecodeError as exc:
            warnings.append(f"JSON formatting note: {exc}")
            return raw_text.strip(), "json", warnings

    raise ValueError("Unsupported document type. Allowed formats: PDF, DOCX, TXT, JSON.")
