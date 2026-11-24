import { LOCAL_RULES, deobfuscateText, isNegatedInClause } from "./scamRules.mjs";

const MAX_LOCAL_CACHE = 64;
const _urlCache = new Map();
const _extractCache = new Map();

function _lruGet(cache, key) {
  if (!cache.has(key)) return undefined;
  const val = cache.get(key);
  cache.delete(key);
  cache.set(key, val);
  return val;
}

function _lruSet(cache, key, val) {
  if (cache.has(key)) cache.delete(key);
  else if (cache.size >= MAX_LOCAL_CACHE) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, val);
  return val;
}

/**
 * JobGuard AI — Local Client-Side Verification Engine (ES Module)
 * Mirrors the FastAPI backend's deterministic rules, 10-field extraction,
 * zero-visit URL inspection, PII redaction, 7-category evidence report, and exporters.
 * Enables 100% offline/local-first operation AND direct Node.js automated testing.
 */

export const MULTI_PART_TLDS = new Set([
  "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
  "co.uk", "org.uk", "com.au", "co.jp", "com.sg",
]);

export const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
  "buzz", "icu", "vip", "monster", "shop", "live", "online", "site", "club", "win",
]);

export const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly",
  "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "lnkd.in", "wa.me",
]);

export const PROTECTED_EMPLOYERS = {
  infosys: { canonical: "Infosys Limited", domains: ["infosys.com"], portal: "https://www.infosys.com/careers/" },
  tcs: { canonical: "Tata Consultancy Services (TCS)", domains: ["tcs.com"], portal: "https://www.tcs.com/careers" },
  wipro: { canonical: "Wipro Limited", domains: ["wipro.com"], portal: "https://careers.wipro.com" },
  hcl: { canonical: "HCLTech", domains: ["hcltech.com", "hcl.com"], portal: "https://www.hcltech.com/careers" },
  accenture: { canonical: "Accenture", domains: ["accenture.com"], portal: "https://www.accenture.com/in-en/careers" },
  cognizant: { canonical: "Cognizant Technology Solutions", domains: ["cognizant.com"], portal: "https://careers.cognizant.com" },
  google: { canonical: "Google LLC", domains: ["google.com"], portal: "https://www.google.com/about/careers/" },
  microsoft: { canonical: "Microsoft Corporation", domains: ["microsoft.com"], portal: "https://careers.microsoft.com" },
  amazon: { canonical: "Amazon", domains: ["amazon.com", "amazon.jobs", "amazon.in"], portal: "https://www.amazon.jobs" },
  flipkart: { canonical: "Flipkart", domains: ["flipkart.com", "flipkartcareers.com"], portal: "https://www.flipkartcareers.com" },
  zoho: { canonical: "Zoho Corporation", domains: ["zohocorp.com", "zoho.com"], portal: "https://www.zoho.com/careers/" },
  razorpay: { canonical: "Razorpay", domains: ["razorpay.com"], portal: "https://razorpay.com/jobs/" },
};

export const PERSONAL_EMAIL_PROVIDERS = new Set([
  "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
  "live.com", "rediffmail.com", "protonmail.com", "proton.me", "icloud.com",
]);

export function redactSensitiveInfo(text) {
  if (!text) return { redacted: "", counts: {} };
  const patterns = [
    ["aadhaar", /(?<!\d)(?:[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}|[2-9]\d{11})(?!\d)/g, "[REDACTED_AADHAAR]"],
    ["pan", /\b[A-Z]{5}\d{4}[A-Z]\b/g, "[REDACTED_PAN]"],
    ["ifsc", /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, "[REDACTED_IFSC]"],
    ["card_number", /(?<!\d)(?:\d{4}[\s-]){3}\d{4}(?!\d)/g, "[REDACTED_CARD]"],
    ["bank_account", /((?:a\/c|acct|account)\s*(?:no\.?|number|#)?\s*[:=-]?\s*)\d{9,18}\b/gi, "$1[REDACTED_BANK_ACCOUNT]"],
    ["otp_pin_cvv", /((?:otp|upi\s*pin|atm\s*pin|mpin|cvv|cvc|pin\s*(?:code|is|:))\s*(?:is|code|:|=|-)?\s*)\d{3,8}\b/gi, "$1[REDACTED_SECRET_CODE]"],
    ["password", /((?:password|passcode|pwd)\s*(?:is|:|=)\s*)\S{3,40}/gi, "$1[REDACTED_PASSWORD]"],
  ];
  let redacted = text;
  const counts = {};
  for (const [label, regex, replacement] of patterns) {
    let n = 0;
    redacted = redacted.replace(regex, (...args) => {
      n += 1;
      return typeof replacement === "string" && replacement.includes("$1")
        ? replacement.replace("$1", args[1] || "")
        : replacement;
    });
    if (n > 0) counts[label] = n;
  }
  return { redacted, counts };
}

export function detectLanguage(text, hint = "auto") {
  if (["en", "hi", "hinglish"].includes(hint)) return hint;
  if (!text) return "en";
  const devanagari = (text.match(/[\u0900-\u097F]/g) || []).length;
  const latin = (text.match(/[a-zA-Z]/g) || []).length;
  if (devanagari >= 5 && devanagari >= latin * 0.2) return "hi";
  if (/\b(aapka|aapke|abhi|karo|karein|turant|bhejo|jama|paisa|naukri|ghar\s+baithe|bina\s+interview|roz|kamayein|fees|pehle)\b/i.test(text)) {
    return "hinglish";
  }
  return "en";
}

export function extractRegistrableDomain(hostname) {
  const host = (hostname || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!host) return { regDomain: "", subdomains: [] };
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return { regDomain: host, subdomains: [] };
  const parts = host.split(".");
  if (parts.length < 2) return { regDomain: host, subdomains: [] };
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return { regDomain: parts.slice(-3).join("."), subdomains: parts.slice(0, -3) };
  }
  return { regDomain: lastTwo, subdomains: parts.slice(0, -2) };
}

export function extractUrlsFromText(text) {
  if (!text) return [];
  const regex = /(?:https?:\/\/|www\.)[^\s<>"'\)\]]+|\b(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|io|co|xyz|top|click|icu|vip|online|site|live|shop|info|jobs|co\.in|gov\.in|ly|at|gy|cc|me)(?:\/[^\s<>"'\)\]]*)?/gi;
  const out = [];
  const seen = new Set();
  let m;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > 0 && text[m.index - 1] === "@") continue;
    const clean = m[0].replace(/[.,;:!?'\")\]}]+$/, "");
    if (clean && !seen.has(clean.toLowerCase())) {
      seen.add(clean.toLowerCase());
      out.push(clean);
    }
  }
  return out.slice(0, 8);
}

export function inspectUrlStructurally(rawUrl) {
  const _cacheKey = String(rawUrl || '').trim();
  const _cached = _lruGet(_urlCache, _cacheKey);
  if (_cached) return _cached;
  return _lruSet(_urlCache, _cacheKey, _inspectUrlStructurallyUncached(rawUrl));
}

function _inspectUrlStructurallyUncached(rawUrl) {
  const submitted = (rawUrl || "").trim();
  const lower = submitted.toLowerCase();
  if (/^(javascript|data|vbscript|file):/.test(lower)) {
    return {
      submitted_url: submitted,
      normalized_url: submitted,
      hostname: "",
      registrable_domain: "",
      subdomains: [],
      scheme: lower.split(":")[0],
      is_https: false,
      is_ip_address: false,
      is_shortened: false,
      has_punycode_or_idn: false,
      subdomain_count: 0,
      impersonated_brand: null,
      official_domains: [],
      risk_level: "HIGH RISK",
      risk_index: 95,
      summary: "Executable or unsafe URI scheme detected. Never open this link.",
      signals: [{ signal: "dangerous_uri_scheme", severity: "critical", explanation: "Non-web executable URI scheme." }],
      reputation_status: "Check Unavailable",
      reputation_provider: "none (local zero-visit structural inspection)",
      recommended_actions: ["Do not click or paste this address into your browser."],
      limitations: ["Zero-visit structural inspection; URL was never opened."],
    };
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(submitted) ? submitted : "http://" + submitted;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    return {
      submitted_url: submitted,
      normalized_url: withScheme,
      hostname: "",
      registrable_domain: "",
      subdomains: [],
      scheme: "invalid",
      is_https: false,
      is_ip_address: false,
      is_shortened: false,
      has_punycode_or_idn: false,
      subdomain_count: 0,
      impersonated_brand: null,
      official_domains: [],
      risk_level: "HIGH RISK",
      risk_index: 80,
      summary: "Malformed recruitment URL.",
      signals: [{ signal: "malformed_url", severity: "high", explanation: "Not a valid standard URL." }],
      reputation_status: "Check Unavailable",
      reputation_provider: "none (local zero-visit structural inspection)",
      recommended_actions: ["Do not open malformed links."],
      limitations: ["Zero-visit structural inspection."],
    };
  }
  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const isHttps = scheme === "https";
  const host = (parsed.hostname || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const hasIdn = host.includes("xn--") || /[^\x00-\x7F]/.test(host);
  const { regDomain, subdomains } = extractRegistrableDomain(host);
  const isShortened = KNOWN_SHORTENERS.has(regDomain);
  const signals = [];
  let points = 0;

  if (parsed.username || parsed.password || submitted.includes("@")) {
    points += 42;
    signals.push({ signal: "embedded_credentials_in_url", severity: "high", explanation: "Contains '@' in URL authority." });
  }
  if (isIp) {
    points += 45;
    signals.push({ signal: "raw_ip_address", severity: "high", explanation: "Uses raw numeric IP address." });
  }
  if (hasIdn) {
    points += 38;
    signals.push({ signal: "punycode_or_idn_homograph", severity: "high", explanation: "Contains Punycode/IDN characters." });
  }
  if (!isHttps) {
    points += 14;
    signals.push({ signal: "unencrypted_http", severity: "medium", explanation: "Uses unencrypted HTTP." });
  }
  if (host.length > 40) {
    points += 20;
    signals.push({ signal: "excessively_long_hostname", severity: "medium", explanation: `Long hostname (${host.length} chars).` });
  }
  if (subdomains.length >= 3) {
    points += 22;
    signals.push({ signal: "excessive_subdomains", severity: "medium", explanation: `Contains ${subdomains.length} subdomains.` });
  }
  const tld = regDomain.split(".").pop() || "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    points += 26;
    signals.push({ signal: "suspicious_tld", severity: "medium", explanation: `Uses high-abuse TLD '.${tld}'.` });
  }
  if (isShortened) {
    points += 24;
    signals.push({ signal: "url_shortener", severity: "medium", explanation: `Uses URL shortener '${regDomain}'.` });
  }

  let impersonatedBrand = null;
  let officialDomains = [];
  const fullLower = (host + parsed.pathname).toLowerCase();
  const tokens = new Set(fullLower.split(/[^a-z0-9]+/).filter(Boolean));
  for (const [key, info] of Object.entries(PROTECTED_EMPLOYERS)) {
    const hit = key.length <= 3 ? tokens.has(key) : fullLower.includes(key);
    if (hit && !info.domains.includes(regDomain)) {
      impersonatedBrand = key.toUpperCase();
      officialDomains = info.domains;
      points += 52;
      signals.push({
        signal: "employer_brand_impersonation",
        severity: "critical",
        explanation: `References '${key.toUpperCase()}' in the URL, but actual domain is '${regDomain}' instead of official (${info.domains.join(", ")}).`,
      });
      break;
    }
  }

  if (parsed.search && /(redirect|url=|next=|token=|otp=|session=)/i.test(parsed.search)) {
    points += 18;
    signals.push({ signal: "suspicious_redirect_parameters", severity: "medium", explanation: "Contains redirect/session query parameters." });
  }

  const riskIndex = Math.min(98, Math.max(5, points));
  const riskLevel = riskIndex >= 60 || impersonatedBrand ? "HIGH RISK" : riskIndex >= 25 ? "MEDIUM RISK" : "LOW RISK";
  return {
    submitted_url: submitted,
    normalized_url: parsed.href,
    hostname: host,
    registrable_domain: regDomain,
    subdomains,
    scheme,
    is_https: isHttps,
    is_ip_address: isIp,
    is_shortened: isShortened,
    has_punycode_or_idn: hasIdn,
    subdomain_count: subdomains.length,
    impersonated_brand: impersonatedBrand,
    official_domains: officialDomains,
    risk_level: riskLevel,
    risk_index: riskIndex,
    summary:
      riskLevel === "HIGH RISK"
        ? `High-risk structural signals on '${regDomain}'. Do not open this link.`
        : riskLevel === "MEDIUM RISK"
        ? `Structural warning signs on '${regDomain}'. Verify independently.`
        : `No strong structural phishing signals on '${regDomain}' (structural check alone cannot guarantee legitimacy).`,
    signals,
    reputation_status: "Check Unavailable",
    reputation_provider: "none (local zero-visit structural inspection)",
    recommended_actions:
      riskLevel === "HIGH RISK"
        ? [`Do not open '${regDomain}'.`, "Visit the employer's official career website manually."]
        : ["Confirm the domain matches the employer's official website before applying."],
    limitations: ["Zero-visit structural inspection: URL is never automatically opened."],
  };
}

export function extractStructuredJobData(text, jobUrl = "") {
  const combined = (text || "").trim();
  const search = jobUrl && !combined.includes(jobUrl) ? `${combined}\nJob URL: ${jobUrl}`.trim() : combined;
  const lang = detectLanguage(search);

  const missing = (name) => ({ field_name: name, value: null, status: "missing", confidence: 0, supporting_snippet: null });
  const found = (name, val, conf, snip) => ({ field_name: name, value: val.trim(), status: "extracted", confidence: conf, supporting_snippet: snip });

  const empM = search.match(/(?:company|employer|organization|कंपनी)\s*[:\-]\s*([^\n,;.|]+)/i)
    || search.match(/\b(Infosys|TCS|Tata Consultancy Services|Wipro|HCLTech|Accenture|Cognizant|Google|Microsoft|Amazon|Flipkart|Zoho|Razorpay)\b/i);
  const roleM = search.match(/(?:job\s+title|role|position|designation|पद)\s*[:\-]\s*([^\n;.|]+)/i)
    || search.match(/\b(Software\s+Engineer|Backend\s+Software\s+Engineer|Frontend\s+Developer|Data\s+Entry\s+Operator|Web\s+Development\s+Intern|Systems\s+Engineer|Specialist\s+Programmer|Graduate\s+Engineer\s+Trainee)\b/i);
  const salM = search.match(/(?:salary|ctc|stipend|स्टाइपेंड|earn|package)\s*[:\-]?\s*((?:₹|Rs\.?|INR|\$)\s*\d[\d,]*(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*)?\s*(?:LPA|per\s+month|\/month|pm|per\s+day|daily|\/day)?|\d+(?:\.\d+)?(?:\s*(?:-|to|–)\s*\d+(?:\.\d+)?)?\s*LPA)/i);
  const emails = [...new Set(search.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [])];
  const phones = [...new Set(search.match(/(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g) || [])];
  const locM = search.match(/(?:location|city)\s*[:\-]\s*([^\n;.|]+)/i)
    || search.match(/\b(Bengaluru|Bangalore|Hyderabad|Pune|Mumbai|Noida|Gurugram|Delhi|Chennai|Lucknow|Remote)\b/i);
  const reqM = search.match(/(?:requisition\s*(?:id|no\.?)|req\s*id|job\s*id)\s*[:\-#]?\s*([A-Z0-9\-_]{3,24})/i);
  const deadM = search.match(/(?:deadline|before|within)\s*[:\-]?\s*(\d+\s*(?:hours?|hrs?|minutes?|days?)|[0-9:]+\s*(?:am|pm)\s*today)/i);

  const urls = extractUrlsFromText(search);
  if (jobUrl && !urls.includes(jobUrl)) urls.unshift(jobUrl);

  let payField = missing("payment_requests");
  const payRegex = /((?:pay|deposit|transfer|jama\s+karo|दें)[^.\n]{0,65}?(?:registration\s+fee|security\s+deposit|refundable\s+deposit|processing\s+fee|prepaid\s+task|recharge|₹\s*\d[\d,]*)|सिक्योरिटी\s+डिपॉजिट|रजिस्ट्रेशन\s+फीस)/gi;
  let pm;
  while ((pm = payRegex.exec(search)) !== null) {
    const pref = search.slice(Math.max(0, pm.index - 45), pm.index).toLowerCase();
    if (/(never|do\s+not|don't|no\s+|does\s+not|zero|कभी\s+नहीं|न\s+दें)/.test(pref)) continue;
    payField = found("payment_requests", pm[0], 0.92, pm[0]);
    break;
  }

  return {
    employer: empM ? found("employer", empM[1] || empM[0], 0.88, empM[0]) : missing("employer"),
    role: roleM ? found("role", roleM[1] || roleM[0], 0.86, roleM[0]) : missing("role"),
    salary: salM ? found("salary", salM[1] || salM[0], 0.85, salM[0]) : missing("salary"),
    recruiter_email: emails[0] ? found("recruiter_email", emails[0], 0.95, emails[0]) : missing("recruiter_email"),
    phone: phones[0] ? found("phone", phones[0], 0.9, phones[0]) : missing("phone"),
    location: locM ? found("location", locM[1] || locM[0], 0.82, locM[0]) : missing("location"),
    job_url: urls[0] ? found("job_url", urls[0], 0.96, urls[0]) : missing("job_url"),
    requisition_id: reqM ? found("requisition_id", reqM[1], 0.9, reqM[0]) : missing("requisition_id"),
    payment_requests: payField,
    deadlines: deadM ? found("deadlines", deadM[1] || deadM[0], 0.8, deadM[0]) : missing("deadlines"),
    additional_emails: emails.slice(1),
    additional_phones: phones.slice(1),
    additional_urls: urls.slice(1),
    detected_language: lang,
  };
}


export function runLocalVerification({
  text = "",
  secondaryText = "",
  jobUrl = "",
  editedFields = null,
  interfaceLanguage = "en",
  isDemo = false,
  redactSensitive = true,
}) {
  const ts = new Date().toISOString();
  const extracted = extractStructuredJobData(text, jobUrl);
  if (editedFields) {
    for (const [k, v] of Object.entries(editedFields)) {
      if (extracted[k]) {
        extracted[k] = v && String(v).trim()
          ? { field_name: k, value: String(v).trim(), status: "extracted", confidence: 1, supporting_snippet: "User reviewed" }
          : { field_name: k, value: null, status: "missing", confidence: 0, supporting_snippet: null };
      }
    }
  }

  const { redacted, counts } = redactSensitive ? redactSensitiveInfo(text) : { redacted: text, counts: {} };
  const hasDisclaimer = /(never\s+pay\s+(?:any\s+)?(?:registration\s+fee|security\s+deposit)|does\s+not\s+charge\s+(?:any\s+)?fee|भर्ती\s+के\s+दौरान\s+कोई\s+शुल्क\s+नहीं)/i.test(text);
  const indicators = [];

  const { cleaned: normalizedText, note: obfNote } = deobfuscateText(text);
  if (obfNote) {
    indicators.push({
      id: `obfuscation_${indicators.length + 1}`,
      category: "Character Obfuscation / Filter Evasion",
      matched_text: obfNote,
      severity: "high",
      explanation: obfNote,
      explanation_hi: obfNote,
      detection_method: "deobfuscation_analyzer",
      reason_it_matters: "Scammers use leetspeak or dot-splitting to evade basic keyword filters.",
      suggested_action: "Treat obfuscated recruitment messages as high-risk spam.",
    });
  }

  for (const rule of LOCAL_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(normalizedText)) !== null) {
      if (isNegatedInClause(normalizedText, m.index)) {
        continue;
      }
      indicators.push({
        id: `${rule.id}_${indicators.length + 1}`,
        category: rule.category,
        matched_text: m[0].trim(),
        severity: rule.severity,
        explanation: rule.explanation,
        explanation_hi: rule.explanation,
        detection_method: "deterministic_rule_engine",
        reason_it_matters: rule.reason,
        suggested_action: rule.action,
      });
      break;
    }
  }

  const urls = extractUrlsFromText(text);
  if (extracted.job_url.value && !urls.includes(extracted.job_url.value)) urls.unshift(extracted.job_url.value);
  const urlInspections = urls.map((u) => inspectUrlStructurally(u));

  for (const u of urlInspections) {
    if (u.risk_level === "HIGH RISK" || u.risk_level === "MEDIUM RISK") {
      indicators.push({
        id: `url_${indicators.length + 1}`,
        category: u.impersonated_brand ? "Fake Career Portal / Brand Impersonation" : "Suspicious Recruitment Link",
        matched_text: u.submitted_url,
        severity: u.impersonated_brand ? "critical" : u.risk_level === "HIGH RISK" ? "high" : "medium",
        explanation: u.summary,
        explanation_hi: u.summary,
        detection_method: "zero_visit_url_inspector",
        reason_it_matters: "Lookalike portals mimic real employers to steal fees or identity data.",
        suggested_action: u.recommended_actions[0] || "Do not open this link.",
      });
    }
  }

  const empName = extracted.employer.value;
  let regEntry = null;
  if (empName) {
    const lowerEmp = empName.toLowerCase();
    for (const [k, info] of Object.entries(PROTECTED_EMPLOYERS)) {
      if (lowerEmp.includes(k) || info.canonical.toLowerCase().includes(lowerEmp)) {
        regEntry = info;
        break;
      }
    }
  }

  const email = extracted.recruiter_email.value;
  const emailDom = email && email.includes("@") ? email.split("@").pop().toLowerCase() : null;
  let emailStatus = "Unverified";
  let emailNote = "No recruiter email supplied.";
  if (emailDom) {
    if (regEntry && regEntry.domains.includes(emailDom)) {
      emailStatus = "Confirmed by Source";
      emailNote = `Email domain '@${emailDom}' matches ${regEntry.canonical}'s official domain.`;
    } else if (regEntry && PERSONAL_EMAIL_PROVIDERS.has(emailDom)) {
      emailStatus = "Suspicious Signal";
      emailNote = `Personal email '@${emailDom}' used while claiming corporate employer '${regEntry.canonical}'.`;
      indicators.push({
        id: `personal_email_${indicators.length + 1}`,
        category: "Personal Email Claiming Major Corporate Employer",
        matched_text: email,
        severity: "medium",
        explanation: emailNote,
        explanation_hi: emailNote,
        detection_method: "email_domain_alignment",
        reason_it_matters: "Large corporations rarely send official hiring offers from personal Gmail/Yahoo accounts.",
        suggested_action: "Ask for confirmation from an official corporate email.",
      });
    } else if (regEntry) {
      emailStatus = "Inconsistent";
      emailNote = `Email domain '@${emailDom}' does not match ${regEntry.canonical}'s official domains (${regEntry.domains.join(", ")}).`;
    } else {
      emailStatus = "Unverified";
      emailNote = `Domain '@${emailDom}' is not in the local reference registry.`;
    }
  }

  // Cross-document consistency
  const conflicts = [];
  if (secondaryText && secondaryText.trim()) {
    const sec = extractStructuredJobData(secondaryText);
    for (const f of ["employer", "role", "salary", "location"]) {
      if (extracted[f].value && sec[f].value && extracted[f].value.toLowerCase() !== sec[f].value.toLowerCase()) {
        conflicts.push(`${f}: '${extracted[f].value}' vs '${sec[f].value}'`);
      }
    }
  }

  const categories = [
    {
      category_number: 1,
      category_id: "employer_identity",
      category_name: "Employer Identity",
      overall_status: regEntry ? "Confirmed by Source" : "Unverified",
      summary: regEntry ? `Matched '${regEntry.canonical}' (${regEntry.portal}).` : (empName ? `Employer '${empName}' is not in the local registry (unverified, not automatically fraudulent).` : "No employer name provided."),
      records: [
        {
          check_name: "Curated Employer Reference Registry",
          source_examined: "Local Employer Reference Registry",
          source_type: "curated_registry",
          observed_result: regEntry ? `Matched ${regEntry.canonical}` : "Not in local registry",
          supporting_quotation: extracted.employer.supporting_snippet,
          status: regEntry ? "Confirmed by Source" : "Unverified",
          timestamp: ts,
          explanation: regEntry ? `Official domains: ${regEntry.domains.join(", ")}.` : "Unknown companies are marked Unverified rather than fraudulent.",
          residual_uncertainty: "Confirm live corporate registration via MCA/GLEIF independently.",
        },
      ],
    },
    {
      category_number: 2,
      category_id: "vacancy_verification",
      category_name: "Vacancy and Requisition Verification",
      overall_status: "Check Unavailable",
      summary: "Live Greenhouse/Lever ATS check requires backend external provider opt-in.",
      records: [
        {
          check_name: "Greenhouse & Lever Public ATS Check",
          source_examined: "Allowlisted ATS APIs",
          source_type: "external_verification",
          observed_result: "External ATS check unavailable in local-only mode.",
          supporting_quotation: extracted.requisition_id.supporting_snippet,
          status: "Check Unavailable",
          timestamp: ts,
          explanation: "Optional live ATS verification is not active locally.",
          residual_uncertainty: "Verify the role directly on the company's official career portal.",
        },
      ],
    },
    {
      category_number: 3,
      category_id: "recruiter_contact",
      category_name: "Recruiter Contact Verification",
      overall_status: /whatsapp|telegram|t\.me\/|wa\.me\//i.test(text) ? "Suspicious Signal" : "Unverified",
      summary: extracted.phone.value ? `Phone extracted: ${extracted.phone.value}` : "No phone number extracted.",
      records: [
        {
          check_name: "Recruiter Contact Channel",
          source_examined: "User-submitted text",
          source_type: "local_heuristic",
          observed_result: /whatsapp|telegram/i.test(text) ? "References WhatsApp/Telegram recruitment channel." : "Standard contact details or none supplied.",
          supporting_quotation: extracted.phone.supporting_snippet,
          status: /whatsapp|telegram/i.test(text) ? "Suspicious Signal" : "Unverified",
          timestamp: ts,
          explanation: "WhatsApp/Telegram-only hiring funnels lack corporate auditability.",
          residual_uncertainty: "Verify recruiter identity via official corporate email and LinkedIn.",
        },
      ],
    },
    {
      category_number: 4,
      category_id: "email_domain_alignment",
      category_name: "Email and Domain Alignment",
      overall_status: emailStatus,
      summary: emailNote,
      records: [
        {
          check_name: "Email vs. Employer Domain Alignment",
          source_examined: "Extracted Email & Registry",
          source_type: "local_heuristic",
          observed_result: emailNote,
          supporting_quotation: extracted.recruiter_email.supporting_snippet,
          status: emailStatus,
          timestamp: ts,
          explanation: emailNote,
          residual_uncertainty: "Pasted text cannot validate SPF/DKIM email headers.",
        },
      ],
    },
    {
      category_number: 5,
      category_id: "link_domain_safety",
      category_name: "Link and Domain Safety",
      overall_status: urlInspections.some((u) => u.risk_level !== "LOW RISK") ? "Suspicious Signal" : (urlInspections.length ? "Unverified" : "Unverified"),
      summary: urlInspections[0] ? urlInspections[0].summary : "No URLs found in submission.",
      records: [
        {
          check_name: "Zero-Visit URL Structural Inspection",
          source_examined: urlInspections[0] ? urlInspections[0].submitted_url : "None",
          source_type: "local_heuristic",
          observed_result: urlInspections[0] ? urlInspections[0].summary : "No job URLs detected.",
          supporting_quotation: urlInspections[0] ? urlInspections[0].submitted_url : null,
          status: urlInspections.some((u) => u.risk_level !== "LOW RISK") ? "Suspicious Signal" : "Unverified",
          timestamp: ts,
          explanation: "Links are inspected structurally without ever opening them.",
          residual_uncertainty: "External reputation feeds (Safe Browsing/VirusTotal) are not queried locally.",
        },
      ],
    },
    {
      category_number: 6,
      category_id: "payment_sensitive_info",
      category_name: "Payment and Sensitive Information Requests",
      overall_status: indicators.some((i) => i.severity === "critical") ? "Suspicious Signal" : (hasDisclaimer ? "Confirmed by Source" : "Unverified"),
      summary: indicators.some((i) => i.severity === "critical")
        ? "Detected payment, deposit, OTP/UPI PIN, or remote-access software demands."
        : (hasDisclaimer ? "Contains explicit anti-fraud safety disclaimer." : "No upfront payment or credential requests detected."),
      records: [
        {
          check_name: "Payment & Sensitive Credential Check",
          source_examined: "User-submitted text",
          source_type: "local_heuristic",
          observed_result: hasDisclaimer ? "Protective anti-fraud disclaimer detected." : "Evaluated for fees, deposits, OTP/PIN, and AnyDesk.",
          supporting_quotation: extracted.payment_requests.supporting_snippet,
          status: indicators.some((i) => i.severity === "critical") ? "Suspicious Signal" : (hasDisclaimer ? "Confirmed by Source" : "Unverified"),
          timestamp: ts,
          explanation: "Legitimate employers never ask for upfront fees, OTPs, UPI PINs, or remote-access tools.",
          residual_uncertainty: "Remain cautious if payment is requested later in the hiring process.",
        },
      ],
    },
    {
      category_number: 7,
      category_id: "document_consistency",
      category_name: "Document and Message Consistency",
      overall_status: conflicts.length ? "Inconsistent" : (secondaryText ? "Confirmed by Source" : "Unverified"),
      summary: conflicts.length ? `Conflicting fields found: ${conflicts.join("; ")}` : (secondaryText ? "No contradictions across submitted materials." : "Single document submitted."),
      records: [
        {
          check_name: "Document & Message Cross-Check",
          source_examined: secondaryText ? "Primary & Secondary Materials" : "Primary Material Only",
          source_type: "local_heuristic",
          observed_result: conflicts.length ? conflicts.join("; ") : "No internal contradictions detected.",
          supporting_quotation: null,
          status: conflicts.length ? "Inconsistent" : (secondaryText ? "Confirmed by Source" : "Unverified"),
          timestamp: ts,
          explanation: conflicts.length ? "Contradictory company, role, or salary details indicate a likely fabricated template." : "Add an offer letter or recruiter email to compare cross-document consistency.",
          residual_uncertainty: "Manual review of full offer terms is always recommended.",
        },
      ],
    },
  ];

  const crit = indicators.filter((i) => i.severity === "critical").length;
  const high = indicators.filter((i) => i.severity === "high").length;
  const med = indicators.filter((i) => i.severity === "medium").length;
  let score = crit * 42 + high * 30 + med * 18 + conflicts.length * 28;
  if (hasDisclaimer && crit === 0 && high === 0) score = Math.min(score, 12);
  const missingCore = ["employer", "role", "recruiter_email", "job_url"].filter((k) => extracted[k].status === "missing").length;
  if (score === 0 && missingCore >= 3) score = 26;
  const riskIndex = Math.max(4, Math.min(98, score));
  const riskLevel = riskIndex >= 60 || crit >= 1 || high >= 2 ? "HIGH RISK" : (riskIndex >= 25 || high >= 1 || med >= 1 || conflicts.length ? "MEDIUM RISK" : "LOW RISK");

  const allRecs = categories.flatMap((c) => c.records);
  const confirmed = allRecs.filter((r) => r.status === "Confirmed by Source").length;
  const unverified = allRecs.filter((r) => r.status === "Unverified").length;
  const unavailable = allRecs.filter((r) => r.status === "Check Unavailable").length;
  const inconsistent = allRecs.filter((r) => r.status === "Inconsistent").length;
  const suspicious = allRecs.filter((r) => r.status === "Suspicious Signal").length;
  const coverage = Math.round(((confirmed + inconsistent + suspicious) / Math.max(1, allRecs.length)) * 100);

  return {
    report_id: "jg-local-" + Math.random().toString(36).slice(2, 10),
    timestamp: ts,
    is_demo: isDemo,
    detected_language: extracted.detected_language,
    interface_language: interfaceLanguage,
    risk_index: riskIndex,
    risk_level: riskLevel,
    risk_headline:
      riskLevel === "HIGH RISK"
        ? "HIGH RISK — Multiple serious fraud indicators or strong contradictory evidence."
        : riskLevel === "MEDIUM RISK"
        ? "MEDIUM RISK — Concerning indicators or important unverified information."
        : "LOW RISK — No strong suspicious indicators identified (verify unconfirmed details).",
    risk_index_disclaimer: "Heuristic Risk Index (0–100) reflects explainable local rules and structural evidence—not a calibrated probability of fraud.",
    evidence_coverage_percent: coverage,
    verification_confidence: coverage >= 60 ? "Moderate (Local Checks Evaluated)" : "Partial (External Checks Unavailable Locally)",
    suspicious_indicator_count: indicators.length,
    confirmed_check_count: confirmed,
    unverified_check_count: unverified,
    unavailable_check_count: unavailable,
    inconsistent_check_count: inconsistent,
    extracted_data: extracted,
    indicators,
    url_inspections: urlInspections,
    categories,
    recommended_actions:
      riskLevel === "HIGH RISK"
        ? ["Do not pay any registration fee, security deposit, or task recharge.", "Do not open unverified links or install AnyDesk/TeamViewer.", "Dial 1930 immediately if money was transferred in India (cybercrime.gov.in)."]
        : ["Verify the vacancy directly on the company's official career website.", "Never share OTPs, UPI PINs, or upfront fees at any stage of hiring."],
    recommended_actions_hi: [
      "किसी भी रजिस्ट्रेशन फीस या सिक्योरिटी डिपॉजिट का भुगतान न करें।",
      "असत्यापित लिंक न खोलें और वित्तीय धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें।",
    ],
    what_was_verified: categories.filter((c) => c.overall_status === "Confirmed by Source").map((c) => `${c.category_name}: ${c.summary}`),
    what_could_not_be_verified: categories.filter((c) => ["Unverified", "Check Unavailable"].includes(c.overall_status)).map((c) => `${c.category_name}: ${c.summary}`),
    ml_assessment: {
      available: false,
      model_type: "Server-side TF-IDF + Logistic Regression (connect FastAPI backend for ML signal)",
      predicted_label: "Unavailable in offline browser mode",
      scam_probability_estimate: 0.5,
      top_contributing_terms: [],
      dataset_disclosure: "Connect to the FastAPI backend to include the secondary TF-IDF + Logistic Regression assessment.",
      evaluation_metrics: {},
    },
    ai_explanation: {
      provider: "local_deterministic_explainer",
      used_external_llm: false,
      summary: `${riskLevel} (${riskIndex}/100): ${indicators.length} indicator(s) identified across 7 verification categories.`,
      plain_language_advice: ["Verify the employer independently before sharing documents or paying any fee."],
      uncertainty_note: "External ATS and corporate registries are unavailable in browser-only offline mode.",
    },
    redacted_input_preview: redacted.slice(0, 1500),
    redaction_counts: counts,
    limitations: ["Local offline engine: external ATS/GLEIF/DNS providers require the FastAPI backend."],
  };
}

export function exportReportToMarkdown(report) {
  const lines = [
    `# JobGuard AI — Evidence-Based Verification Report`,
    ``,
    `- **Report ID:** ${report.report_id}`,
    `- **Timestamp:** ${report.timestamp}`,
    `- **Risk Classification:** ${report.risk_level} (${report.risk_index}/100 heuristic index)`,
    `- **Evidence Coverage:** ${report.evidence_coverage_percent}%`,
    `- **Verification Confidence:** ${report.verification_confidence}`,
    `- **Detected Language:** ${report.detected_language}`,
    ``,
    `> ${report.risk_index_disclaimer}`,
    ``,
    `## 7-Category Evidence Breakdown`,
    ...report.categories.map(
      (c) => `### ${c.category_number}. ${c.category_name} — [${c.overall_status}]\n${c.summary}`
    ),
    ``,
    `## Detected Red Flags (${report.indicators.length})`,
    ...(report.indicators.length
      ? report.indicators.map((i) => `- **${i.category}** (${i.severity}): "${i.matched_text}" — ${i.explanation}`)
      : ["- None detected."]),
    ``,
    `## Recommended Actions`,
    ...report.recommended_actions.map((a, idx) => `${idx + 1}. ${a}`),
  ];
  return lines.join("\n");
}
