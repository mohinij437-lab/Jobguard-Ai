/** Deterministic recruitment fraud rules and obfuscation normalizers. */

const DOT_SPLIT_RE = /(?:\b[A-Za-z₹$0-9]\.){3,}[A-Za-z0-9]?/g;
const DOT_JOIN_RE = /(?:[A-Za-z₹$0-9]\.){2,}[A-Za-z0-9]?/g;
const LEET_WORD_RE = /\b(?=[A-Za-z0-9@]*[A-Za-z])(?=[A-Za-z0-9@]*[013@])[A-Za-z0-9@]{2,}\b/g;
const CURRENCY_O_RE = /([₹$]\d+)O+/g;
const LEET_MAP = { "0": "o", "1": "i", "3": "e", "@": "a" };
const NEGATION_CLAUSE_RE = new RegExp(
  [
    "\\b(?:never|do\\s+not|don't|does\\s+not|doesn't|will\\s+never|won't|zero\\s+cost|",
    "covered\\s+by\\s+(?:company|employer)|covers\\s+100%|",
    "no\\s+(?:preparation\\s+fees?|external\\s+downloads?|binaries\\s+needed|",
    "check\\/reimbursement|charge|fee\\s+required))\\b|",
    "कभी\\s+नहीं|न\\s+दें|कोई\\s+शुल्क\\s+नहीं",
  ].join(""),
  "i"
);

export function deobfuscateText(text) {
  if (!text) return { cleaned: "", note: null };
  const dotHits = text.match(DOT_SPLIT_RE) || [];
  if (dotHits.length >= 2) {
    return {
      cleaned: text.replace(DOT_JOIN_RE, (m) => m.replace(/\./g, "")),
      note: "Punctuation-splitting obfuscation detected",
    };
  }
  const leetHits = text.match(LEET_WORD_RE) || [];
  if (leetHits.length >= 3) {
    let norm = text.replace(CURRENCY_O_RE, (m, g1) => g1 + "0".repeat(m.length - g1.length));
    norm = norm.replace(LEET_WORD_RE, (w) => w.replace(/[013@]/g, (c) => LEET_MAP[c] || c));
    return {
      cleaned: norm,
      note: `Leetspeak character substitution detected (${leetHits.slice(0, 4).join(", ")})`,
    };
  }
  return { cleaned: text, note: null };
}

export function isNegatedInClause(text, matchIndex) {
  const windowStr = text.slice(Math.max(0, matchIndex - 75), matchIndex);
  const parts = windowStr.split(/[.!?\n;]/);
  return NEGATION_CLAUSE_RE.test(parts[parts.length - 1] || "");
}

function compileRule(parts) {
  return new RegExp(parts.join(""), "gi");
}

export const LOCAL_RULES = [
  {
    id: "task_click_optimization_scam",
    category: "Task / App Optimization / Click-to-Earn Scam",
    severity: "critical",
    weight: 48,
    regex: compileRule([
      "\\b(?:prepaid\\s+(?:merchant\\s+)?task|task\\s+recharge|recharge\\s+(?:wallet|account)|vip\\s+(?:telegram\\s+)",
      "?task\\s*(?:group|operator|payout)?|(?:liking|like)\\s+(?:youtube|instagram)\\s+videos|",
      "subscribing\\s+to\\s+channels|follow\\s+instagram\\s+accounts.{0,35}screenshots?|(?:rating|",
      "rate)\\s+(?:google\\s+maps|hotels?|movies?)|(?:hotel|movie)[\\s-]rating\\s+tasks?|(?:app|",
      "order)\\s+optimization|product\\s+booster|click\\s+and\\s+review\\s+e-?commerce|upgrading\\s+your\\s+workbench\\s+balance|",
      "sets?\\s+of\\s+\\d+\\s+clicks|daily\\s+settlement.{0,25}(?:usdt|crypto)|settled\\s+daily\\s+via\\s+crypto|",
      "claim\\s+your\\s+\\$?\\d+\\s+welcome\\s+bonus|(?:flipkart|amazon|meesho)\\s+(?:packing|home\\s+packing|",
      "review)\\s+job)\\b|\u092a\u094d\u0930\u0940\u092a\u0947\u0921\\s+\u091f\u093e\u0938\u094d\u0915|\u0935\u0940\u0921\u093f\u092f\u094b\\s+\u0932\u093e\u0907\u0915\\s+\u0915\u0930\u0915\u0947\\s+\u0915\u092e\u093e\u090f\u0902|\u091f\u093e\u0938\u094d\u0915\\s+\u0930\u093f\u091a\u093e\u0930\u094d\u091c",
    ]),
    explanation: "Matches an online task, app/order optimization, paid fake-review, or click-to-earn scam.",
    reason: "Task scams lure victims with small initial payouts or bonuses before locking funds behind escalating 'workbench' or prepaid deposits.",
    action: "Do not engage with task-boosting or paid-review offers; leave the chat group immediately.",
  },
  {
    id: "upfront_fee_deposit_scam",
    category: "Upfront Fee / Security Deposit / Paid Onboarding Scam",
    severity: "critical",
    weight: 46,
    regex: compileRule([
      "\\b(?:(?:pay|deposit|submit|transfer|send|wire|cover)\\s+(?:a\\s+|an\\s+|the\\s+|just\\s+|",
      "only\\s+)?(?:fully\\s+)?(?:refundable\\s+)?(?:\u20b9|Rs\\.?|INR|\\$|\u20ac|\u00a3)?\\s*\\d[\\d,]*(?:\\.\\d+)?\\s*(?:rs\\.?|",
      "inr|rupees|rupaye|only)?\\s*(?:as\\s+|for\\s+)?(?:a\\s+)?(?:one[\\s-]time\\s+)?(?:refundable\\s+)",
      "?(?:registration|application|processing|joining|onboarding|interview|document\\s+verification|",
      "verification|hr\\s+verification|file|id\\s+card|uniform|gate[\\s-]pass|portal\\s+activation|",
      "international\\s+payroll\\s+activation|vendor[\\s-]onboarding|administrative\\s+bond|security\\s+deposit|",
      "biometric\\s+smart\\s+card|software\\s+setup|courier(?:\\s+&\\s+security)?|training\\s+kit|",
      "starter\\s+database|agreement\\s+stamp[\\s-]duty|visa[\\s-]stamping|medical\\s+&\\s+embassy|",
      "certificate\\s+of\\s+sponsorship|cos\\s+reservation|offshore\\s+safety\\s+clearance|mom\\s+verification)",
      "\\s*(?:fee|fees|charge|charges|deposit|bond|key)?|(?:refundable\\s+)?(?:\u20b9|Rs\\.?|INR|\\$|",
      "\u20ac|\u00a3)\\s*\\d[\\d,]*(?:\\.\\d+)?\\s*(?:refundable\\s+)?(?:registration|security|processing|joining|",
      "uniform\\s+&\\s+gate[\\s-]pass|portal\\s+activation|agreement\\s+stamp[\\s-]duty|courier\\s+insurance|",
      "document\\s+verification|vendor[\\s-]onboarding|administrative|verification|visa[\\s-]stamping|",
      "cos\\s+reservation)\\s*(?:fee|fees|charge|charges|deposit|bond|insurance)|(?:registration|",
      "security|processing|joining|verification|payroll\\s+activation|vendor[\\s-]onboarding)",
      "\\s*(?:fee|fees|deposit|charge)\\s*(?:of\\s+(?:\u20b9|Rs\\.?|\\$|\u20ac|\u00a3)?\\s*\\d+|applies|required|",
      "jama\\s+karo|bhejo|dena\\s+hoga)|complete\\s+our\\s+proprietary\\s+compliance\\s+course\\s*\\(\\$\\d+\\)|",
      "purchase\\s+(?:your|our)\\s+\\$?\\d+\\s*(?:starter\\s+database|home[\\s-]billing\\s+software|",
      "wellness\\s+starter\\s+kit|personal\\s+coaching\\s+license)|to\\s+unlock\\s+your\\s+joining\\s+letter.{0,",
      "40}deposit|wire\\s+\\$?\\d[\\d,]+\\s+to\\s+our\\s+(?:verification\\s+agency|travel\\s+desk)|verify\\s+their\\s+identity\\s+with\\s+a\\s+\\$?\\d+\\s+refundable\\s+deposit|",
      "nominal\\s+\\$?\\d+(?:\\.\\d+)?\\s+verification\\s+charge|pehle\\s+(?:\u20b9|Rs\\.?)?\\s*\\d[\\d,]+\\s*(?:rs\\.?|",
      "rupees|rupaye)?\\s*(?:registration|joining|processing)?\\s*(?:fee|fees)?\\s*(?:jama\\s+karo|",
      "bhejo|do)|(?:pay|send|transfer)\\s+(?:\u20b9|Rs\\.?|INR)?\\s*\\d[\\d,]+\\s*(?:rs\\.?|rupees|rupaye)",
      "?\\s*(?:via|on|through|to)\\s+(?:upi|phonepe|gpay|google\\s+pay|paytm))\\b|\u0930\u091c\u093f\u0938\u094d\u091f\u094d\u0930\u0947\u0936\u0928\\s+\u092b\u0940\u0938|",
      "\u0938\u093f\u0915\u094d\u092f\u094b\u0930\u093f\u091f\u0940\\s+\u0921\u093f\u092a\u0949\u091c\u093f\u091f|\u092a\u094d\u0930\u094b\u0938\u0947\u0938\u093f\u0902\u0917\\s+\u092b\u0940\u0938|\u091c\u0949\u0907\u0928\u093f\u0902\u0917\\s+\u092b\u0940\u0938|\u0932\u0948\u092a\u091f\u0949\u092a\\s+\u0921\u093f\u092a\u0949\u091c\u093f\u091f",
    ]),
    explanation: "Demands an upfront fee, refundable deposit, bond, paid compliance course, courier insurance, or vendor onboarding charge.",
    reason: "Legitimate employers never charge candidates upfront fees, bonds, or deposits to apply, verify identity, or receive equipment.",
    action: "Do not pay any upfront fee, deposit, or verification charge; discontinue contact immediately.",
  },
  {
    id: "fake_check_equipment_scam",
    category: "Fake Check / Equipment Purchase / Gift Card Scam",
    severity: "critical",
    weight: 48,
    regex: compileRule([
      "\\b(?:(?:mailing|sending|issued|issue|emailing)\\s+(?:you\\s+)?a\\s+(?:mobile\\s+|company\\s+|",
      "certified\\s+|reimbursement\\s+)?(?:e-?)?check\\s+(?:for\\s+\\$?\\d[\\d,]*\\s+)?(?:to\\s+(?:purchase|",
      "buy)|for\\s+your\\s+(?:workstation|equipment|sign[\\s-]on))|(?:equipment|workstation)\\s+(?:grant|",
      "check|stipend).{0,80}(?:e-?check|certified\\s+check|zelle|cashapp|wire|gift\\s+cards?|",
      "vendor|supplier|deposit\\s+receipt)|accidentally\\s+issued\\s+your.{0,30}check.{0,60}return\\s+the\\s+\\$?\\d[\\d,",
      "]+\\s+excess|deposit\\s+(?:it|the\\s+check).{0,55}(?:wire|zelle|cashapp|bitcoin\\s+atm|western\\s+union|",
      "apple\\s+gift\\s+cards?|pay\\s+the\\s+(?:software\\s+)?vendor|keep\\s+\\$?\\d+)|purchasing\\s+(?:digital\\s+|",
      "apple\\s+)?gift\\s+cards?\\s+(?:for\\s+client|or\\s+send\\s+an\\s+instant\\s+transfer)|mystery\\s+shopper.{0,",
      "80}(?:check|western\\s+union|money[\\s-]transfer))\\b",
    ]),
    explanation: "Uses a fake check, e-check, overpayment refund, or gift-card purchase scheme disguised as equipment onboarding or mystery shopping.",
    reason: "Fraudulent checks initially appear in your balance before bouncing days later, leaving you personally liable for all wired/Zelle/CashApp funds.",
    action: "Never deposit a check from an unverified employer to pay a 'vendor', buy gift cards, or wire back excess money.",
  },
  {
    id: "data_entry_typing_penalty_scam",
    category: "Data Entry / Typing / Accuracy Penalty Scam",
    severity: "high",
    weight: 38,
    regex: compileRule([
      "\\b(?:convert\\s+scanned\\s+pdf\\s+pages\\s+into\\s+ms\\s+word|home[\\s-]based\\s+typing\\s+job|",
      "simple\\s+captcha\\s+entry|copy[\\s-]paste\\s+&\\s+form\\s+filling|online\\s+ad[\\s-]posting\\s+&\\s+form[\\s-]filling|",
      "handwriting\\/notebook\\s+writing\\s+jobs?|accuracy\\s+penalty.{0,80}(?:legal\\s+settlement|",
      "court\\s+action|pay)|scored\\s+\\d+%\\s+accuracy.{0,80}(?:legal\\s+settlement|pay|fee))\\b",
    ]),
    explanation: "Matches a WFH typing, PDF-to-Word, captcha, handwriting, or fake accuracy-penalty extortion scam.",
    reason: "These schemes charge activation/stamp-duty fees upfront or intimidate victims with fake legal notices for 'low accuracy'.",
    action: "Do not pay portal activation fees or legal settlement threats from unverified typing portals.",
  },
  {
    id: "reshipping_parcel_mule_scam",
    category: "Reshipping / Parcel Mule Scam",
    severity: "critical",
    weight: 48,
    regex: compileRule([
      "\\b(?:receive\\s+(?:electronics|luxury\\s+packages?|online\\s+orders?|domestic\\s+shipments?|",
      "10-15\\s+parcels?|the\\s+package|and\\s+re[\\s-]label\\s+parcels?)\\s+(?:at\\s+your\\s+(?:home|",
      "residential\\s+address|address)|from\\s+home)|(?:receiving\\s+and\\s+forwarding|receiving\\s+domestic\\s+shipments\\s+at\\s+your\\s+residential\\s+address)",
      "|(?:remove\\s+original\\s+invoices?|discard\\s+the\\s+retail\\s+receipt|re[\\s-]label\\s+parcels\\s+from\\s+home)",
      "|package\\s+forwarding\\s+coordinator.{0,80}residence|packages\\s+are\\s+sent\\s+to\\s+your\\s+residence.{0,",
      "60}(?:ups|fedex|forward))\\b",
    ]),
    explanation: "Recruits you to receive packages at your home address, remove receipts/invoices, and reship them\u2014a parcel mule operation.",
    reason: "Parcel mule jobs launder merchandise bought with stolen credit cards and can expose you to criminal investigation.",
    action: "Refuse any job that asks you to receive and forward retail packages from your residential address.",
  },
  {
    id: "money_mule_laundering_scam",
    category: "Money Mule / Bank Account Laundering Scam",
    severity: "critical",
    weight: 50,
    regex: compileRule([
      "\\b(?:receive\\s+(?:client\\s+payments?|zelle\\/venmo\\s+transfers?|verified\\s+corporate\\s+funds)",
      "\\s+(?:into\\s+your\\s+bank\\s+account|from\\s+our\\s+us\\s+customers|,\\s*execute\\s+simple\\s+wallet\\s+transfers)",
      "|deposit\\s+(?:funds|checks?)\\s+into\\s+your\\s+(?:personal\\s+)?(?:bank|checking)?\\s*account.{0,",
      "75}(?:purchase\\s+bitcoin|wire\\s+\\d+%|crypto|western\\s+union|keep\\s+\\d+%)|accept\\s+domestic\\s+bank\\s+wires.{0,",
      "50}remit\\s+them\\s+via\\s+western\\s+union|renting\\s+out\\s+your\\s+(?:unused\\s+)?bank\\s+account\\s+or\\s+upi\\s+id|",
      "localized\\s+payment\\s+settlement.{0,80}(?:processing\\s+fee\\s+per\\s+settled\\s+invoice|",
      "domestic\\s+checking\\s+account)|convert\\s+to\\s+usdt.{0,45}corporate\\s+wallet)\\b",
    ]),
    explanation: "Asks you to use your personal bank account, UPI ID, or crypto wallet to receive and forward third-party funds for a commission.",
    reason: "Acting as a payment intermediary or renting out your bank/UPI account is illegal money laundering and leads to frozen accounts and prosecution.",
    action: "Never allow anyone to route funds through your personal bank account, UPI ID, or crypto exchange account.",
  },
  {
    id: "text_only_interview_pii_trap",
    category: "Text-Only App Interview / Instant-Hire PII Trap",
    severity: "high",
    weight: 40,
    regex: compileRule([
      "\\b(?:interviews?\\s+(?:are\\s+)?conducted\\s+exclusively\\s+via\\s+text\\s+chat|(?:10|15)[\\s-]minute\\s+text\\s+interview|",
      "asynchronous\\s+written\\s+screening\\s+on\\s+telegram|no\\s+phone\\s+or\\s+video\\s+calls?\\s+required.{0,",
      "60}(?:signal|telegram|whatsapp)|complete\\s+the\\s+\\d+[\\s-]minute\\s+text\\s+interview\\s+on\\s+signal|",
      "instant\\s+chat\\s+interview|skip\\s+the\\s+panel\\s+interview\\s+by\\s+sharing\\s+your\\s+aadhaar|",
      "board\\s+has\\s+unanimously\\s+approved\\s+your\\s+hiring.{0,80}(?:routing\\s+number|maiden\\s+name)",
      "|send\\s+your\\s+(?:full\\s+)?(?:ssn|social\\s+security\\s+number).{0,50}(?:whatsapp|google\\s+form|",
      "direct\\s+deposit)|uploading\\s+your\\s+passport\\s+and\\s+debit\\s+card\\s+front\\/back|selfie\\s+holding\\s+your\\s+passport\\s+and\\s+your\\s+online\\s+banking\\s+credentials)",
      "\\b",
    ]),
    explanation: "Conducts hiring exclusively via Telegram/Signal/WhatsApp text chat or demands sensitive identity/banking details immediately.",
    reason: "Scammers avoid live video/voice interviews and harvest SSN, Aadhaar, PAN, passport selfies, or banking credentials right after a fake chat.",
    action: "Insist on a verified corporate email and live video/in-person interview before sharing any government ID or bank details.",
  },
  {
    id: "overseas_visa_scam",
    category: "Fake Overseas Job / Visa Sponsorship Scam",
    severity: "critical",
    weight: 45,
    regex: compileRule([
      "\\b(?:guaranteed\\s+(?:canada|uk|europe|australia|dubai|qatar|singapore)?\\s*(?:work\\s+permit|",
      "warehouse\\s+&\\s+packaging\\s+jobs?)|direct\\s+company\\s+visa\\s+in\\s+\\d+\\s+days|move\\s+to\\s+europe\\s+in\\s+\\d+\\s+days|",
      "no\\s+ielts\\s+needed.{0,50}visa[\\s-]stamping\\s+fee|(?:visa[\\s-]stamping|medical\\s+&\\s+embassy|",
      "cos\\s+reservation|offshore\\s+safety\\s+clearance|mom\\s+verification\\s+and\\s+insurance\\s+bond)",
      "\\s*(?:fee|deposit)?|release\\s+your\\s+sponsored\\s+flight\\s+ticket.{0,40}wire)\\b",
    ]),
    explanation: "Promises guaranteed overseas work visas in days (or with no language test) in exchange for upfront visa, embassy, medical, or flight fees.",
    reason: "Official work permits are processed through government immigration portals and licensed employers\u2014not personal UPI or wire transfers.",
    action: "Verify overseas agencies against official government emigration registries and never pay upfront visa-stamping fees to private accounts.",
  },
  {
    id: "credential_phishing_malware_scam",
    category: "Credential Phishing / Credit Check / Malware Lure",
    severity: "critical",
    weight: 50,
    regex: compileRule([
      "\\b(?:(?:share|send|provide|enter|give|bhejo|batao)\\s+(?:your\\s+|the\\s+|apna\\s+)?(?:6[\\s-]digit\\s+)",
      "?(?:google\\s+voice\\s*\\/\\s*)?(?:otp|upi\\s+pin|atm\\s+pin|cvv|netbanking\\s+password|bank\\s+password|",
      "mpin)|(?:pull\\s+your\\s+credit\\s+score|mandatory\\s+(?:pre[\\s-]employment\\s+)?credit\\s+(?:and\\s+identity\\s+)",
      "?check).{0,80}(?:credit\\s+card|verification\\s+charge|link)|sign\\s+in\\s+with\\s+your\\s+google\\s+or\\s+microsoft\\s+account\\s+at|",
      "(?:log\\s+into|signing\\s+into)\\s+your\\s+bank(?:\\s+portal)?\\s+through\\s+our|submit\\s+your\\s+full\\s+social\\s+security\\s+number.{0,",
      "50}google\\s+form|(?:encrypted\\s+job[\\s-]offer\\s+viewer\\s*\\(\\.zip\\/\\.exe\\)|disable\\s+your\\s+antivirus)",
      "|create\\s+a\\s+verified\\s+account\\s+on.{0,40}share\\s+the\\s+login\\s+credentials|(?:install|",
      "download)\\s+(?:the\\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk))\\b|(?:\u0913\u091f\u0940\u092a\u0940|\u092f\u0942\u092a\u0940\u0906\u0908\\s+\u092a\u093f\u0928|",
      "\u090f\u091f\u0940\u090f\u092e\\s+\u092a\u093f\u0928)\\s*(?:\u0936\u0947\u092f\u0930|\u0938\u093e\u091d\u093e|\u092d\u0947\u091c\u0947\u0902|\u092c\u0924\u093e\u090f\u0902|\u0921\u093e\u0932\u0947\u0902)",
    ]),
    explanation: "Attempts to steal banking/Google/Microsoft logins, OTP/Google Voice codes, credit card details, or install malware/remote-access tools.",
    reason: "Legitimate employers never ask you to disable antivirus, run unknown `.exe`/`.zip` viewers, pay for a credit check link, or enter bank logins on an HR portal.",
    action: "Do not click the link, run the file, or share any OTP/login credentials.",
  },
  {
    id: "mlm_starter_pack_scam",
    category: "Disguised MLM / Pyramid / Starter-Pack Scheme",
    severity: "high",
    weight: 38,
    regex: compileRule([
      "\\b(?:6[\\s-]figure\\s+residual\\s+income|mentorship\\s+circle.{0,60}residual\\s+income|(?:wellness\\s+starter\\s+kit|",
      "starter\\s+bundle|personal\\s+coaching\\s+license|initial\\s+sample\\s+inventory)|(?:\u20b9|Rs\\.?|",
      "\\$)\\s*\\d[\\d,]+\\s+joining\\s+package\\s+gives\\s+you\\s+lifetime\\s+business\\s+rights|recruit\\s+(?:just\\s+)",
      "?\\d+\\s+members?.{0,40}(?:diamond\\s+tier|passive\\s+income)|be\\s+your\\s+own\\s+ceo.{0,60}(?:lifestyle\\s+coach|",
      "invest\\s+\\$\\d+)|building\\s+a\\s+network\\s+of\\s+\\d+\\s+driven\\s+partners)\\b",
    ]),
    explanation: "Disguises a recruitment-based MLM/pyramid scheme or mandatory paid starter-kit pitch as a salaried job.",
    reason: "Income depends on buying inventory/kits and recruiting others rather than genuine salaried employment.",
    action: "Avoid opportunities requiring starter-kit purchases or recruitment tiers for pay.",
  },
  {
    id: "unrealistic_pay_or_no_interview",
    category: "Unrealistic Compensation / No-Interview Direct Offer",
    severity: "high",
    weight: 36,
    regex: compileRule([
      "\\b(?:earn\\s+(?:up\\s+to\\s+)?(?:\u20b9|Rs\\.?|INR|\\$|\u20ac)\\s*(?:[1-9]\\d{2,4}|[1-9],\\d{3})(?:\\s*(?:-|",
      "to|\u2013)\\s*(?:\u20b9|Rs\\.?|INR|\\$|\u20ac)?\\s*\\d[\\d,]*)?\\s*(?:rs\\.?|rupees)?\\s*(?:per\\s+day|daily|",
      "\\/day)|work\\s+1-2\\s+hours\\/day,\\s*earn\\s+\\$\\d+|(?:selected|hired|offer)\\s+(?:you\\s+)",
      "?(?:an\\s+immediate\\s+)?(?:full[\\s-]time\\s+remote\\s+role.{0,40})?(?:no\\s+interview\\s+required|",
      "without\\s+(?:any\\s+)?interview)|no\\s+resume\\s+needed.{0,40}onboarding|guaranteed\\s+\\$?\\d+\\/day|",
      "zero\\s+experience\\s+needed.{0,40}telegram\\s+(?:bot|group)|ghar\\s+baithe\\s+(?:roz|daily)",
      "\\s+(?:\u20b9|Rs\\.?)?\\s*\\d{3,5}|bina\\s+interview\\s+(?:ke\\s+)?(?:direct\\s+)?(?:selection|naukri|",
      "job|joining))\\b|\u0918\u0930\\s+\u092c\u0948\u0920\u0947\\s+\u0930\u094b\u091c\u093c\\s*\u20b9?\\s*\\d[\\d,]*\\s*\u0915\u092e\u093e\u090f\u0902|\u092c\u093f\u0928\u093e\\s+\u0907\u0902\u091f\u0930\u0935\u094d\u092f\u0942",
    ]),
    explanation: "Promises unusually high daily pay for 20\u201360 minutes of work or immediate hiring with no interview/resume.",
    reason: "Legitimate employers evaluate skills through interviews and pay market-aligned rates.",
    action: "Verify the role and salary band directly on the company's official career portal.",
  },
  {
    id: "lookalike_domain_or_suspicious_channel",
    category: "Lookalike Domain / Off-Platform Messaging Pivot",
    severity: "high",
    weight: 36,
    regex: compileRule([
      "\\b(?:-(?:recruitment-portal|hiring-desk|careers-verify|hr-portal)\\.|hiringmanager\\.global@gmail\\.com|",
      "(?:add|contact|message)\\s+(?:our\\s+)?(?:director|recruiter|receptionist|manager|hr\\s+bot)",
      "\\s+on\\s+(?:telegram|signal)|reply\\s+(?:yes|'yes'|'info')\\s+(?:within\\s+\\d+\\s+hours\\s+)",
      "?(?:to\\s+(?:get\\s+started|claim\\s+your\\s+priority\\s+slot|connect\\s+with\\s+our\\s+tutor)",
      ")|got\\s+your\\s+number\\s+from\\s+a\\s+recruiting\\s+colleague.{0,80}whatsapp|number\\s+was\\s+selected\\s+from\\s+our\\s+hiring\\s+database.{0,",
      "80}(?:registration|whatsapp)|t\\.me\\/[a-z0-9_]+|wa\\.me\\/\\d+)\\b",
    ]),
    explanation: "Uses a lookalike HR domain, unsolicited database-selection claim, or off-platform Telegram/Signal/WhatsApp funnel.",
    reason: "Scammers move targets off audited job platforms onto encrypted chat apps or lookalike domains.",
    action: "Verify the recruiter via an official corporate email and never apply through unknown chat bots.",
  },
  {
    id: "subtle_fee_check_phishing_patterns",
    category: "Subtle Fee / Fake Check / Phishing / Parcel / Off-Platform Pattern",
    severity: "high",
    weight: 42,
    regex: compileRule([
      "(?:\\b(?:paying|pay)\\s+(?:the\\s+|a\\s+)?(?:\u20b9|Rs\\.?|\\$|\u20ac|\u00a3)\\s*\\d[\\d,]*\\s*(?:document\\s+verification|",
      "biometric\\s+smart\\s+card|software\\s+setup|courier\\s+insurance|training\\s+kit|processing)",
      "\\s*(?:fee|charge|deposit)?|(?:\u20b9|Rs\\.?|\\$|\u20ac|\u00a3)\\s*\\d[\\d,]*\\s+(?:courier\\s+insurance|software\\s+setup\\s+fee|",
      "biometric\\s+smart\\s+card)|compliance\\s+course\\s*\\(\\$\\d+\\)|(?:mailing|sending|send)\\s+(?:you\\s+)",
      "?a\\s+(?:certified\\s+)?(?:\\$\\d[\\d,]*\\s+)?check|pay\\s+(?:\u20b9|Rs\\.?|\\$|\u20ac|\u00a3)\\s*\\d[\\d,]*\\s+for\\s+your\\s+(?:biometric|",
      "smart\\s+card|training\\s+kit|id\\s+card)|purchase\\s+(?:apple|digital)\\s+gift\\s+cards?|",
      "deposit\\s+checks?\\s+into\\s+your\\s+personal\\s+checking\\s+account|receive\\s+\\d+-\\d+\\s+parcels\\s+weekly.{0,",
      "90}shipping\\s+labels?|social\\s+security\\s+number.{0,90}google\\s+form|\\.zip\\s*\\/\\s*\\.exe|",
      "create\\s+a\\s+verified\\s+account.{0,90}share\\s+the\\s+login\\s+credentials|selected\\s+from\\s+our\\s+hiring\\s+database|",
      "external\\s+hr\\s+bot\\s+on\\s+telegram|got\\s+your\\s+number\\s+from\\s+a\\s+recruiting\\s+colleague.{0,",
      "120}whatsapp)",
    ]),
    explanation: "Matches subtle recruitment-fraud patterns including disguised fees, check-to-vendor/gift-card schemes, residential parcel forwarding, malware archives, or unsolicited off-platform pivots.",
    reason: "Modern recruitment scams use polite corporate language and low-dollar fees to bypass naive keyword filters.",
    action: "Verify the opportunity independently through the company's official career website before replying or paying.",
  },
];
