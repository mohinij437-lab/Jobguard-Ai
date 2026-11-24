"""Layers A, B, G & H: Multilingual & De-obfuscated Recruitment Fraud Rule Engine.

Covers all 12 major recruitment fraud typologies + English, Hindi, and Hinglish,
with text de-obfuscation (leetspeak & punctuation-splitting) and sentence-scoped
negation protection to minimize false positives on legitimate recruiter outreach.
"""
from __future__ import annotations

import re
from functools import lru_cache
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .extractor import extract_structured_job_data
from .schemas import DetectionIndicator, ExtractedJobData, Severity


@dataclass(frozen=True)
class FraudRule:
    rule_id: str
    category: str
    severity: Severity
    weight: int
    pattern: re.Pattern
    explanation: str
    explanation_hi: str
    reason_it_matters: str
    suggested_action: str
    respect_negation: bool = True


NEGATION_SENTENCE_RE = re.compile(
    r"(?i)\b(?:never|do\s+not|don't|does\s+not|doesn't|will\s+not|won't|"
    r"not\s+(?:ask(?:ed)?|charge|pay|share|require|need)|"
    r"no\s+(?:upfront\s+|preparation\s+)?(?:fees?|charges?|deposits?|binaries|downloads?)|"
    r"zero\s+(?:fee|cost)|covers\s+100%\s+of\s+the\s+cost|paid\s+(?:entirely\s+)?by\s+(?:the\s+)?employer|"
    r"beware\s+of)\b|कभी\s+नहीं|कोई\s+शुल्क\s+नहीं|न\s+दें|मत\s+देना|nahi\s+mangta"
)

SAFETY_DISCLAIMER_RE = re.compile(
    r"(?i)(?:never\s+(?:pay|send|share|be\s+asked\s+to\s+purchase)|"
    r"does\s+not\s+charge\s+(?:any\s+)?(?:fee|money|deposit)|"
    r"no\s+(?:preparation\s+)?fees?\s+(?:or\s+external\s+downloads?\s+)?(?:are\s+|is\s+)?(?:charged|needed)|"
    r"covers\s+100%\s+of\s+the\s+cost|"
    r"भर्ती\s+के\s+दौरान\s+कोई\s+शुल्क\s+नहीं\s+लिया\s+जाता)"
)


_DOT_SPLIT_RE = re.compile(r"(?:\b[A-Za-z₹$0-9]\.){3,}[A-Za-z0-9]?")
_DOT_JOIN_RE = re.compile(r"(?:[A-Za-z₹$0-9]\.){2,}[A-Za-z0-9]?")
_LEET_WORD_RE = re.compile(r"\b(?=[A-Za-z0-9@]*[A-Za-z])(?=[A-Za-z0-9@]*[013@])[A-Za-z0-9@]{2,}\b")
_CURRENCY_O_RE = re.compile(r"([₹$]\d+)O+")
_CLAUSE_SPLIT_RE = re.compile(r"[.!?\n;]")
_WHITESPACE_RE = re.compile(r"\s+")
_LEET_TRANS = str.maketrans({"0": "o", "1": "i", "3": "e", "@": "a"})


@lru_cache(maxsize=256)
def deobfuscate_text(text: str) -> Tuple[str, Optional[str]]:
    """Detect and normalize leetspeak and punctuation-split obfuscation (LRU-cached)."""
    if not text:
        return "", None

    # 1. Detect punctuation-splitting like "W.o.r.k  f.r.o.m  h.o.m.e"
    dot_split_hits = _DOT_SPLIT_RE.findall(text)
    if len(dot_split_hits) >= 2:
        cleaned = _DOT_JOIN_RE.sub(lambda m: m.group(0).replace(".", ""), text)
        return cleaned, "Punctuation-splitting obfuscation detected (e.g., 'W.o.r.k f.r.o.m h.o.m.e')"

    # 2. Detect leetspeak like "H3llo! W3 are h1ring ... E@rn $2OO d@ily ... Wh@tsApp"
    leet_words = _LEET_WORD_RE.findall(text)
    if len(leet_words) >= 3:
        norm = _CURRENCY_O_RE.sub(lambda m: m.group(1) + "0" * (len(m.group(0)) - len(m.group(1))), text)
        norm = _LEET_WORD_RE.sub(lambda m: m.group(0).translate(_LEET_TRANS), norm)
        return norm, f"Leetspeak character substitution detected ({', '.join(leet_words[:4])})"

    return text, None


def _is_negated_in_clause(text: str, match_start: int) -> bool:
    """Check negation ONLY within the same clause/sentence (stops at . ! ? ; or newline)."""
    window = text[max(0, match_start - 75):match_start]
    clause = _CLAUSE_SPLIT_RE.split(window)[-1]
    return bool(NEGATION_SENTENCE_RE.search(clause))


RULES: List[FraudRule] = [
    # Cat 1: Task / App Optimization / Click-to-Earn
    FraudRule(
        rule_id="task_click_optimization_scam",
        category="Task / App Optimization / Click-to-Earn Scam",
        severity=Severity.CRITICAL,
        weight=48,
        pattern=re.compile(
            r"(?i)\b(?:prepaid\s+(?:merchant\s+)?task|task\s+recharge|recharge\s+(?:wallet|account)|"
            r"vip\s+(?:telegram\s+)?task\s*(?:group|operator|payout)?|"
            r"(?:liking|like)\s+(?:youtube|instagram)\s+videos|subscribing\s+to\s+channels|"
            r"follow\s+instagram\s+accounts.{0,35}screenshots?|"
            r"(?:rating|rate)\s+(?:google\s+maps|hotels?|movies?)|(?:hotel|movie)[\s-]rating\s+tasks?|"
            r"(?:app|order)\s+optimization|product\s+booster|click\s+and\s+review\s+e-?commerce|"
            r"upgrading\s+your\s+workbench\s+balance|sets?\s+of\s+\d+\s+clicks|"
            r"daily\s+settlement.{0,25}(?:usdt|crypto)|settled\s+daily\s+via\s+crypto|"
            r"claim\s+your\s+\$?\d+\s+welcome\s+bonus|"
            r"(?:flipkart|amazon|meesho)\s+(?:packing|home\s+packing|review)\s+job)\b|"
            r"प्रीपेड\s+टास्क|वीडियो\s+लाइक\s+करके\s+कमाएं|टास्क\s+रिचार्ज",
        ),
        explanation="Matches an online task, app/order optimization, paid fake-review, or click-to-earn scam.",
        explanation_hi="वीडियो लाइक करने, रिव्यू देने, या ऐप/ऑर्डर ऑप्टिमाइज़ेशन टास्क स्कैम का पैटर्न मिला है।",
        reason_it_matters="Task scams lure victims with small initial payouts or bonuses before locking funds behind escalating 'workbench' or prepaid deposits.",
        suggested_action="Do not engage with task-boosting or paid-review offers; leave the chat group immediately.",
    ),
    # Cat 2: Upfront Fees, Deposits, Bonds, Training, Courier Insurance, Vendor Fees
    FraudRule(
        rule_id="upfront_fee_deposit_scam",
        category="Upfront Fee / Security Deposit / Paid Onboarding Scam",
        severity=Severity.CRITICAL,
        weight=46,
        pattern=re.compile(
            r"(?i)\b(?:(?:pay|deposit|submit|transfer|send|wire|cover)\s+(?:a\s+|an\s+|the\s+|just\s+|only\s+)?(?:fully\s+)?(?:refundable\s+)?(?:₹|Rs\.?|INR|\$|€|£)?\s*\d[\d,]*(?:\.\d+)?\s*(?:rs\.?|inr|rupees|rupaye|only)?\s*(?:as\s+|for\s+)?(?:a\s+)?(?:one[\s-]time\s+)?(?:refundable\s+)?(?:registration|application|processing|joining|onboarding|interview|document\s+verification|verification|hr\s+verification|file|id\s+card|uniform|gate[\s-]pass|portal\s+activation|international\s+payroll\s+activation|vendor[\s-]onboarding|administrative\s+bond|security\s+deposit|biometric\s+smart\s+card|software\s+setup|courier(?:\s+&\s+security)?|training\s+kit|starter\s+database|agreement\s+stamp[\s-]duty|visa[\s-]stamping|medical\s+&\s+embassy|certificate\s+of\s+sponsorship|cos\s+reservation|offshore\s+safety\s+clearance|mom\s+verification)\s*(?:fee|fees|charge|charges|deposit|bond|key)?|"
            r"(?:refundable\s+)?(?:₹|Rs\.?|INR|\$|€|£)\s*\d[\d,]*(?:\.\d+)?\s*(?:refundable\s+)?(?:registration|security|processing|joining|uniform\s+&\s+gate[\s-]pass|portal\s+activation|agreement\s+stamp[\s-]duty|courier\s+insurance|document\s+verification|vendor[\s-]onboarding|administrative|verification|visa[\s-]stamping|cos\s+reservation)\s*(?:fee|fees|charge|charges|deposit|bond|insurance)|"
            r"(?:registration|security|processing|joining|verification|payroll\s+activation|vendor[\s-]onboarding)\s*(?:fee|fees|deposit|charge)\s*(?:of\s+(?:₹|Rs\.?|\$|€|£)?\s*\d+|applies|required|jama\s+karo|bhejo|dena\s+hoga)|"
            r"complete\s+our\s+proprietary\s+compliance\s+course\s*\(\$\d+\)|"
            r"purchase\s+(?:your|our)\s+\$?\d+\s*(?:starter\s+database|home[\s-]billing\s+software|wellness\s+starter\s+kit|personal\s+coaching\s+license)|"
            r"to\s+unlock\s+your\s+joining\s+letter.{0,40}deposit|"
            r"wire\s+\$?\d[\d,]+\s+to\s+our\s+(?:verification\s+agency|travel\s+desk)|"
            r"verify\s+their\s+identity\s+with\s+a\s+\$?\d+\s+refundable\s+deposit|"
            r"nominal\s+\$?\d+(?:\.\d+)?\s+verification\s+charge|"
            r"pehle\s+(?:₹|Rs\.?)?\s*\d[\d,]+\s*(?:rs\.?|rupees|rupaye)?\s*(?:registration|joining|processing)?\s*(?:fee|fees)?\s*(?:jama\s+karo|bhejo|do)|"
            r"(?:pay|send|transfer)\s+(?:₹|Rs\.?|INR)?\s*\d[\d,]+\s*(?:rs\.?|rupees|rupaye)?\s*(?:via|on|through|to)\s+(?:upi|phonepe|gpay|google\s+pay|paytm))\b|"
            r"रजिस्ट्रेशन\s+फीस|सिक्योरिटी\s+डिपॉजिट|प्रोसेसिंग\s+फीस|जॉइनिंग\s+फीस|लैपटॉप\s+डिपॉजिट",
        ),
        explanation="Demands an upfront fee, refundable deposit, bond, paid compliance course, courier insurance, or vendor onboarding charge.",
        explanation_hi="नौकरी, लैपटॉप, ट्रेनिंग या दस्तावेज़ सत्यापन के नाम पर अग्रिम शुल्क या डिपॉजिट मांगा गया है।",
        reason_it_matters="Legitimate employers never charge candidates upfront fees, bonds, or deposits to apply, verify identity, or receive equipment.",
        suggested_action="Do not pay any upfront fee, deposit, or verification charge; discontinue contact immediately.",
    ),
    # Cat 3: Fake Check, Equipment Purchase & Mystery Shopper / Gift Cards
    FraudRule(
        rule_id="fake_check_equipment_scam",
        category="Fake Check / Equipment Purchase / Gift Card Scam",
        severity=Severity.CRITICAL,
        weight=48,
        pattern=re.compile(
            r"(?i)\b(?:(?:mailing|sending|issued|issue|emailing)\s+(?:you\s+)?a\s+(?:mobile\s+|company\s+|certified\s+|reimbursement\s+)?(?:e-?)?check\s+(?:for\s+\$?\d[\d,]*\s+)?(?:to\s+(?:purchase|buy)|for\s+your\s+(?:workstation|equipment|sign[\s-]on))|"
            r"(?:equipment|workstation)\s+(?:grant|check|stipend).{0,80}(?:e-?check|certified\s+check|zelle|cashapp|wire|gift\s+cards?|vendor|supplier|deposit\s+receipt)|"
            r"accidentally\s+issued\s+your.{0,30}check.{0,60}return\s+the\s+\$?\d[\d,]+\s+excess|"
            r"deposit\s+(?:it|the\s+check).{0,55}(?:wire|zelle|cashapp|bitcoin\s+atm|western\s+union|apple\s+gift\s+cards?|pay\s+the\s+(?:software\s+)?vendor|keep\s+\$?\d+)|"
            r"purchasing\s+(?:digital\s+|apple\s+)?gift\s+cards?\s+(?:for\s+client|or\s+send\s+an\s+instant\s+transfer)|"
            r"mystery\s+shopper.{0,80}(?:check|western\s+union|money[\s-]transfer))\b",
        ),
        explanation="Uses a fake check, e-check, overpayment refund, or gift-card purchase scheme disguised as equipment onboarding or mystery shopping.",
        explanation_hi="नकली चेक, उपकरण खरीद या गिफ्ट कार्ड खरीदने के नाम पर धोखाधड़ी का पैटर्न मिला है।",
        reason_it_matters="Fraudulent checks initially appear in your balance before bouncing days later, leaving you personally liable for all wired/Zelle/CashApp funds.",
        suggested_action="Never deposit a check from an unverified employer to pay a 'vendor', buy gift cards, or wire back excess money.",
    ),
    # Cat 5: Data Entry, Typing, Captcha & Accuracy Penalty Extortion
    FraudRule(
        rule_id="data_entry_typing_penalty_scam",
        category="Data Entry / Typing / Accuracy Penalty Scam",
        severity=Severity.HIGH,
        weight=38,
        pattern=re.compile(
            r"(?i)\b(?:convert\s+scanned\s+pdf\s+pages\s+into\s+ms\s+word|home[\s-]based\s+typing\s+job|"
            r"simple\s+captcha\s+entry|copy[\s-]paste\s+&\s+form\s+filling|online\s+ad[\s-]posting\s+&\s+form[\s-]filling|"
            r"handwriting\/notebook\s+writing\s+jobs?|"
            r"accuracy\s+penalty.{0,80}(?:legal\s+settlement|court\s+action|pay)|"
            r"scored\s+\d+%\s+accuracy.{0,80}(?:legal\s+settlement|pay|fee))\b",
        ),
        explanation="Matches a WFH typing, PDF-to-Word, captcha, handwriting, or fake accuracy-penalty extortion scam.",
        explanation_hi="घर बैठे टाइपिंग, कैप्चा, फॉर्म-फिलिंग या नकली 'एक्यूरेसी पेनल्टी' कानूनी धमकी का पैटर्न मिला है।",
        reason_it_matters="These schemes charge activation/stamp-duty fees upfront or intimidate victims with fake legal notices for 'low accuracy'.",
        suggested_action="Do not pay portal activation fees or legal settlement threats from unverified typing portals.",
    ),
    # Cat 6: Reshipping & Parcel Mule Scams
    FraudRule(
        rule_id="reshipping_parcel_mule_scam",
        category="Reshipping / Parcel Mule Scam",
        severity=Severity.CRITICAL,
        weight=48,
        pattern=re.compile(
            r"(?i)\b(?:receive\s+(?:electronics|luxury\s+packages?|online\s+orders?|domestic\s+shipments?|10-15\s+parcels?|the\s+package|and\s+re[\s-]label\s+parcels?)\s+(?:at\s+your\s+(?:home|residential\s+address|address)|from\s+home)|"
            r"(?:receiving\s+and\s+forwarding|receiving\s+domestic\s+shipments\s+at\s+your\s+residential\s+address)|"
            r"(?:remove\s+original\s+invoices?|discard\s+the\s+retail\s+receipt|re[\s-]label\s+parcels\s+from\s+home)|"
            r"package\s+forwarding\s+coordinator.{0,80}residence|"
            r"packages\s+are\s+sent\s+to\s+your\s+residence.{0,60}(?:ups|fedex|forward))\b",
        ),
        explanation="Recruits you to receive packages at your home address, remove receipts/invoices, and reship them—a parcel mule operation.",
        explanation_hi="घर के पते पर पार्सल मंगवाकर, रसीद हटाकर आगे भेजने (पार्सल म्यूल) की धोखाधड़ी का पैटर्न मिला है।",
        reason_it_matters="Parcel mule jobs launder merchandise bought with stolen credit cards and can expose you to criminal investigation.",
        suggested_action="Refuse any job that asks you to receive and forward retail packages from your residential address.",
    ),
    # Cat 7: Money Mule & Crypto-Transfer Scams
    FraudRule(
        rule_id="money_mule_laundering_scam",
        category="Money Mule / Bank Account Laundering Scam",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:receive\s+(?:client\s+payments?|zelle\/venmo\s+transfers?|verified\s+corporate\s+funds)\s+(?:into\s+your\s+bank\s+account|from\s+our\s+us\s+customers|,\s*execute\s+simple\s+wallet\s+transfers)|"
            r"deposit\s+(?:funds|checks?)\s+into\s+your\s+(?:personal\s+)?(?:bank|checking)?\s*account.{0,75}(?:purchase\s+bitcoin|wire\s+\d+%|crypto|western\s+union|keep\s+\d+%)|"
            r"accept\s+domestic\s+bank\s+wires.{0,50}remit\s+them\s+via\s+western\s+union|"
            r"renting\s+out\s+your\s+(?:unused\s+)?bank\s+account\s+or\s+upi\s+id|"
            r"localized\s+payment\s+settlement.{0,80}(?:processing\s+fee\s+per\s+settled\s+invoice|domestic\s+checking\s+account)|"
            r"convert\s+to\s+usdt.{0,45}corporate\s+wallet)\b",
        ),
        explanation="Asks you to use your personal bank account, UPI ID, or crypto wallet to receive and forward third-party funds for a commission.",
        explanation_hi="अपने निजी बैंक खाते, यूपीआई या क्रिप्टो वॉलेट से पैसे प्राप्त करके आगे भेजने (मनी म्यूल) की मांग की गई है।",
        reason_it_matters="Acting as a payment intermediary or renting out your bank/UPI account is illegal money laundering and leads to frozen accounts and prosecution.",
        suggested_action="Never allow anyone to route funds through your personal bank account, UPI ID, or crypto exchange account.",
    ),
    # Cat 8: Text-Only App Interviews & Instant-Hire PII Traps
    FraudRule(
        rule_id="text_only_interview_pii_trap",
        category="Text-Only App Interview / Instant-Hire PII Trap",
        severity=Severity.HIGH,
        weight=40,
        pattern=re.compile(
            r"(?i)\b(?:interviews?\s+(?:are\s+)?conducted\s+exclusively\s+via\s+text\s+chat|"
            r"(?:10|15)[\s-]minute\s+text\s+interview|asynchronous\s+written\s+screening\s+on\s+telegram|"
            r"no\s+phone\s+or\s+video\s+calls?\s+required.{0,60}(?:signal|telegram|whatsapp)|"
            r"complete\s+the\s+\d+[\s-]minute\s+text\s+interview\s+on\s+signal|"
            r"instant\s+chat\s+interview|"
            r"skip\s+the\s+panel\s+interview\s+by\s+sharing\s+your\s+aadhaar|"
            r"board\s+has\s+unanimously\s+approved\s+your\s+hiring.{0,80}(?:routing\s+number|maiden\s+name)|"
            r"send\s+your\s+(?:full\s+)?(?:ssn|social\s+security\s+number).{0,50}(?:whatsapp|google\s+form|direct\s+deposit)|"
            r"uploading\s+your\s+passport\s+and\s+debit\s+card\s+front\/back|"
            r"selfie\s+holding\s+your\s+passport\s+and\s+your\s+online\s+banking\s+credentials)\b",
        ),
        explanation="Conducts hiring exclusively via Telegram/Signal/WhatsApp text chat or demands sensitive identity/banking details immediately.",
        explanation_hi="केवल टेलीग्राम/सिग्नल/व्हाट्सएप चैट इंटरव्यू या तुरंत संवेदनशील पहचान/बैंकिंग विवरण मांगे गए हैं।",
        reason_it_matters="Scammers avoid live video/voice interviews and harvest SSN, Aadhaar, PAN, passport selfies, or banking credentials right after a fake chat.",
        suggested_action="Insist on a verified corporate email and live video/in-person interview before sharing any government ID or bank details.",
    ),
    # Cat 9: Fake Overseas Jobs & Visa Sponsorship Scams
    FraudRule(
        rule_id="overseas_visa_scam",
        category="Fake Overseas Job / Visa Sponsorship Scam",
        severity=Severity.CRITICAL,
        weight=45,
        pattern=re.compile(
            r"(?i)\b(?:guaranteed\s+(?:canada|uk|europe|australia|dubai|qatar|singapore)?\s*(?:work\s+permit|warehouse\s+&\s+packaging\s+jobs?)|"
            r"direct\s+company\s+visa\s+in\s+\d+\s+days|move\s+to\s+europe\s+in\s+\d+\s+days|"
            r"no\s+ielts\s+needed.{0,50}visa[\s-]stamping\s+fee|"
            r"(?:visa[\s-]stamping|medical\s+&\s+embassy|cos\s+reservation|offshore\s+safety\s+clearance|mom\s+verification\s+and\s+insurance\s+bond)\s*(?:fee|deposit)?|"
            r"release\s+your\s+sponsored\s+flight\s+ticket.{0,40}wire)\b",
        ),
        explanation="Promises guaranteed overseas work visas in days (or with no language test) in exchange for upfront visa, embassy, medical, or flight fees.",
        explanation_hi="विदेश में पक्की नौकरी और वीज़ा के नाम पर अग्रिम वीज़ा, मेडिकल, एम्बेसी या टिकट शुल्क मांगा गया है।",
        reason_it_matters="Official work permits are processed through government immigration portals and licensed employers—not personal UPI or wire transfers.",
        suggested_action="Verify overseas agencies against official government emigration registries and never pay upfront visa-stamping fees to private accounts.",
    ),
    # Cat 10: Identity Theft, Credential Phishing & Malware Lures
    FraudRule(
        rule_id="credential_phishing_malware_scam",
        category="Credential Phishing / Credit Check / Malware Lure",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:(?:share|send|provide|enter|give|bhejo|batao)\s+(?:your\s+|the\s+|apna\s+)?(?:6[\s-]digit\s+)?(?:google\s+voice\s*\/\s*)?(?:otp|upi\s+pin|atm\s+pin|cvv|netbanking\s+password|bank\s+password|mpin)|"
            r"(?:pull\s+your\s+credit\s+score|mandatory\s+(?:pre[\s-]employment\s+)?credit\s+(?:and\s+identity\s+)?check).{0,80}(?:credit\s+card|verification\s+charge|link)|"
            r"sign\s+in\s+with\s+your\s+google\s+or\s+microsoft\s+account\s+at|"
            r"(?:log\s+into|signing\s+into)\s+your\s+bank(?:\s+portal)?\s+through\s+our|"
            r"submit\s+your\s+full\s+social\s+security\s+number.{0,50}google\s+form|"
            r"(?:encrypted\s+job[\s-]offer\s+viewer\s*\(\.zip\/\.exe\)|disable\s+your\s+antivirus)|"
            r"create\s+a\s+verified\s+account\s+on.{0,40}share\s+the\s+login\s+credentials|"
            r"(?:install|download)\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk))\b|"
            r"(?:ओटीपी|यूपीआई\s+पिन|एटीएम\s+पिन)\s*(?:शेयर|साझा|भेजें|बताएं|डालें)",
        ),
        explanation="Attempts to steal banking/Google/Microsoft logins, OTP/Google Voice codes, credit card details, or install malware/remote-access tools.",
        explanation_hi="बैंक लॉगिन, ओटीपी, क्रेडिट कार्ड या मैलवेयर/रिमोट-एक्सेस ऐप के जरिए धोखाधड़ी का प्रयास है।",
        reason_it_matters="Legitimate employers never ask you to disable antivirus, run unknown `.exe`/`.zip` viewers, pay for a credit check link, or enter bank logins on an HR portal.",
        suggested_action="Do not click the link, run the file, or share any OTP/login credentials.",
    ),
    # Cat 11: Disguised MLM & Starter-Pack Schemes
    FraudRule(
        rule_id="mlm_starter_pack_scam",
        category="Disguised MLM / Pyramid / Starter-Pack Scheme",
        severity=Severity.HIGH,
        weight=38,
        pattern=re.compile(
            r"(?i)\b(?:6[\s-]figure\s+residual\s+income|mentorship\s+circle.{0,60}residual\s+income|"
            r"(?:wellness\s+starter\s+kit|starter\s+bundle|personal\s+coaching\s+license|initial\s+sample\s+inventory)|"
            r"(?:₹|Rs\.?|\$)\s*\d[\d,]+\s+joining\s+package\s+gives\s+you\s+lifetime\s+business\s+rights|"
            r"recruit\s+(?:just\s+)?\d+\s+members?.{0,40}(?:diamond\s+tier|passive\s+income)|"
            r"be\s+your\s+own\s+ceo.{0,60}(?:lifestyle\s+coach|invest\s+\$\d+)|"
            r"building\s+a\s+network\s+of\s+\d+\s+driven\s+partners)\b",
        ),
        explanation="Disguises a recruitment-based MLM/pyramid scheme or mandatory paid starter-kit pitch as a salaried job.",
        explanation_hi="नौकरी के नाम पर एमएलएम (MLM) या अनिवार्य स्टार्टर किट/जॉइनिंग पैकेज खरीदने का प्रस्ताव है।",
        reason_it_matters="Income depends on buying inventory/kits and recruiting others rather than genuine salaried employment.",
        suggested_action="Avoid opportunities requiring starter-kit purchases or recruitment tiers for pay.",
    ),
    # Cat 4 & 12: Brand Impersonation, Unrealistic Pay, No-Interview & Off-Platform Pivots
    FraudRule(
        rule_id="unrealistic_pay_or_no_interview",
        category="Unrealistic Compensation / No-Interview Direct Offer",
        severity=Severity.HIGH,
        weight=36,
        pattern=re.compile(
            r"(?i)\b(?:earn\s+(?:up\s+to\s+)?(?:₹|Rs\.?|INR|\$|€)\s*(?:[1-9]\d{2,4}|[1-9],\d{3})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR|\$|€)?\s*\d[\d,]*)?\s*(?:rs\.?|rupees)?\s*(?:per\s+day|daily|\/day)|"
            r"work\s+1-2\s+hours\/day,\s*earn\s+\$\d+|"
            r"(?:selected|hired|offer)\s+(?:you\s+)?(?:an\s+immediate\s+)?(?:full[\s-]time\s+remote\s+role.{0,40})?(?:no\s+interview\s+required|without\s+(?:any\s+)?interview)|"
            r"no\s+resume\s+needed.{0,40}onboarding|guaranteed\s+\$?\d+\/day|"
            r"zero\s+experience\s+needed.{0,40}telegram\s+(?:bot|group)|"
            r"ghar\s+baithe\s+(?:roz|daily)\s+(?:₹|Rs\.?)?\s*\d{3,5}|"
            r"bina\s+interview\s+(?:ke\s+)?(?:direct\s+)?(?:selection|naukri|job|joining))\b|"
            r"घर\s+बैठे\s+रोज़\s*₹?\s*\d[\d,]*\s*कमाएं|बिना\s+इंटरव्यू",
        ),
        explanation="Promises unusually high daily pay for 20–60 minutes of work or immediate hiring with no interview/resume.",
        explanation_hi="कम समय में अवास्तविक कमाई या बिना इंटरव्यू के सीधी नौकरी का वादा किया गया है।",
        reason_it_matters="Legitimate employers evaluate skills through interviews and pay market-aligned rates.",
        suggested_action="Verify the role and salary band directly on the company's official career portal.",
    ),
    FraudRule(
        rule_id="lookalike_domain_or_suspicious_channel",
        category="Lookalike Domain / Off-Platform Messaging Pivot",
        severity=Severity.HIGH,
        weight=36,
        pattern=re.compile(
            r"(?i)\b(?:-(?:recruitment-portal|hiring-desk|careers-verify|hr-portal)\.|"
            r"hiringmanager\.global@gmail\.com|"
            r"(?:add|contact|message)\s+(?:our\s+)?(?:director|recruiter|receptionist|manager|hr\s+bot)\s+on\s+(?:telegram|signal)|"
            r"reply\s+(?:yes|'yes'|'info')\s+(?:within\s+\d+\s+hours\s+)?(?:to\s+(?:get\s+started|claim\s+your\s+priority\s+slot|connect\s+with\s+our\s+tutor))|"
            r"got\s+your\s+number\s+from\s+a\s+recruiting\s+colleague.{0,80}whatsapp|"
            r"number\s+was\s+selected\s+from\s+our\s+hiring\s+database.{0,80}(?:registration|whatsapp)|"
            r"t\.me\/[a-z0-9_]+|wa\.me\/\d+)\b",
        ),
        explanation="Uses a lookalike HR domain, unsolicited database-selection claim, or off-platform Telegram/Signal/WhatsApp funnel.",
        explanation_hi="नकली एचआर डोमेन या अनचाहे व्हाट्सएप/टेलीग्राम/सिग्नल भर्ती चैनल का उपयोग किया गया है।",
        reason_it_matters="Scammers move targets off audited job platforms onto encrypted chat apps or lookalike domains.",
        suggested_action="Verify the recruiter via an official corporate email and never apply through unknown chat bots.",
    ),
    FraudRule(
        rule_id="subtle_fee_check_phishing_patterns",
        category="Subtle Fee / Fake Check / Phishing / Parcel / Off-Platform Pattern",
        severity=Severity.HIGH,
        weight=42,
        pattern=re.compile(
            r"(?i)(?:\b(?:paying|pay)\s+(?:the\s+|a\s+)?(?:₹|Rs\.?|\$|€|£)\s*\d[\d,]*\s*(?:document\s+verification|biometric\s+smart\s+card|software\s+setup|courier\s+insurance|training\s+kit|processing)\s*(?:fee|charge|deposit)?|"
            r"(?:₹|Rs\.?|\$|€|£)\s*\d[\d,]*\s+(?:courier\s+insurance|software\s+setup\s+fee|biometric\s+smart\s+card)|"
            r"compliance\s+course\s*\(\$\d+\)|"
            r"(?:mailing|sending|send)\s+(?:you\s+)?a\s+(?:certified\s+)?(?:\$\d[\d,]*\s+)?check|"
            r"pay\s+(?:₹|Rs\.?|\$|€|£)\s*\d[\d,]*\s+for\s+your\s+(?:biometric|smart\s+card|training\s+kit|id\s+card)|"
            r"purchase\s+(?:apple|digital)\s+gift\s+cards?|"
            r"deposit\s+checks?\s+into\s+your\s+personal\s+checking\s+account|"
            r"receive\s+\d+-\d+\s+parcels\s+weekly.{0,90}shipping\s+labels?|"
            r"social\s+security\s+number.{0,90}google\s+form|"
            r"\.zip\s*\/\s*\.exe|"
            r"create\s+a\s+verified\s+account.{0,90}share\s+the\s+login\s+credentials|"
            r"selected\s+from\s+our\s+hiring\s+database|"
            r"external\s+hr\s+bot\s+on\s+telegram|"
            r"got\s+your\s+number\s+from\s+a\s+recruiting\s+colleague.{0,120}whatsapp)"
        ),
        explanation="Matches subtle recruitment-fraud patterns including disguised fees, check-to-vendor/gift-card schemes, residential parcel forwarding, malware archives, or unsolicited off-platform pivots.",
        explanation_hi="छिपे हुए शुल्क, नकली चेक/गिफ्ट कार्ड, पार्सल म्यूल, मैलवेयर फ़ाइल या अनचाहे व्हाट्सएप/टेलीग्राम भर्ती का पैटर्न मिला है।",
        reason_it_matters="Modern recruitment scams use polite corporate language and low-dollar fees to bypass naive keyword filters.",
        suggested_action="Verify the opportunity independently through the company's official career website before replying or paying.",
    ),
]


def run_rule_analysis(text: str, extracted: ExtractedJobData) -> Tuple[List[DetectionIndicator], bool]:
    """Run de-obfuscation + 12-typology rule engine with sentence-scoped negation."""
    if not text:
        return [], False

    norm_text, obf_reason = deobfuscate_text(text)
    has_disclaimer = bool(SAFETY_DISCLAIMER_RE.search(norm_text))
    indicators: List[DetectionIndicator] = []
    seen_ids = set()

    if obf_reason:
        indicators.append(
            DetectionIndicator(
                id="obfuscation_evasion_1",
                category="Text Obfuscation / Filter Evasion",
                matched_text=text[:90],
                severity=Severity.HIGH,
                explanation=obf_reason,
                explanation_hi="फ़िल्टर से बचने के लिए शब्दों को जानबूझकर बदलकर (ओबफ़स्केशन) लिखा गया है।",
                detection_method="deobfuscation_preprocessor",
                reason_it_matters="Scammers use leetspeak or dot-splitting to evade spam filters; legitimate employers do not obfuscate job ads.",
                suggested_action="Treat obfuscated recruitment messages as high risk and do not respond.",
            )
        )

    for rule in RULES:
        for m in rule.pattern.finditer(norm_text):
            if rule.respect_negation and _is_negated_in_clause(norm_text, m.start()):
                continue
            matched = m.group(0).strip()
            dedup_key = (rule.rule_id, matched.lower())
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)
            indicators.append(
                DetectionIndicator(
                    id=f"{rule.rule_id}_{len(indicators) + 1}",
                    category=rule.category,
                    matched_text=matched,
                    severity=rule.severity,
                    explanation=rule.explanation,
                    explanation_hi=rule.explanation_hi,
                    detection_method="deterministic_rule_engine",
                    reason_it_matters=rule.reason_it_matters,
                    suggested_action=rule.suggested_action,
                )
            )
            break  # One match per rule category keeps scoring clean and non-inflated

    return indicators, has_disclaimer


def compare_document_consistency(
    primary_text: str,
    primary_extracted: ExtractedJobData,
    secondary_text: Optional[str],
) -> List[dict]:
    """Layer H: Compare primary job description against a secondary document."""
    if not secondary_text or not secondary_text.strip():
        return []

    secondary_extracted = extract_structured_job_data(secondary_text)
    conflicts: List[dict] = []

    fields_to_compare = [
        ("employer", "Employer Name"),
        ("role", "Job Title / Role"),
        ("salary", "Salary / Compensation"),
        ("location", "Job Location"),
        ("recruiter_email", "Recruiter Email"),
    ]

    for attr, label in fields_to_compare:
        f1 = getattr(primary_extracted, attr)
        f2 = getattr(secondary_extracted, attr)
        if f1.status == "extracted" and f2.status == "extracted" and f1.value and f2.value:
            v1_norm = _WHITESPACE_RE.sub(" ", f1.value.strip().lower())
            v2_norm = _WHITESPACE_RE.sub(" ", f2.value.strip().lower())
            if v1_norm != v2_norm and v1_norm not in v2_norm and v2_norm not in v1_norm:
                conflicts.append(
                    {
                        "field": label,
                        "primary_value": f1.value,
                        "secondary_value": f2.value,
                        "explanation": f"{label} differs between submitted materials ('{f1.value}' vs '{f2.value}').",
                    }
                )

    return conflicts
