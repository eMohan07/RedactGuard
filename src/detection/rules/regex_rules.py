import re
import uuid
from typing import List, Dict, Any, Tuple
from src.detection.schemas import DetectedSpan
from src.detection.validators import (
    validate_verhoeff_checksum,
    validate_pan_format,
    validate_gstin_format,
    validate_ifsc_format,
    validate_uan_format,
    validate_phone_digits,
    is_likely_non_pii,
    NON_NAME_PHRASES,
    ORGANIZATION_INDICATORS
)

CATEGORY_MAP = {
    "PERSON": "NAME",
    "NAME": "NAME",
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "ADDRESS": "ADDRESS",
    "SSN": "ID",
    "CREDIT_CARD": "ID",
    "IPV4": "ID",
    "GOV_ID": "ID",
    "STUDENT_ID": "ID",
    "ID": "ID"
}

def normalize_category(cat: str) -> str:
    return CATEGORY_MAP.get(cat.upper(), "ID")

DISALLOWED_NAME_TOKENS = {
    "name", "names", "title", "role", "position", "designation",
    "email", "phone", "mobile", "tel", "fax", "id", "code", "number", "no", 
    "ref", "date", "address", "profile", "itinerary", "advice", "intake", 
    "log", "summary", "report", "ticket", "review", "status", "department", 
    "success", "registration", "notes", "minutes", "agreement", "letter", 
    "notice", "clinical", "support", "desk", "call", "speaker", "passenger",
    "customer", "patient", "employee", "candidate", "doctor", "meeting", "strategy",
    "escalations", "pilot", "regarding", "feedback", "query", "issue", "delivery",
    "committee", "board", "council", "commission", "division", "team", "organization",
    "architect", "engineer", "specialist", "officer", "manager", "lead", "developer",
    "attending", "physician", "executive", "director", "president", "advisor",
    "passport", "license", "licence", "dl", "pan", "ssn", "aadhaar", "epic", "voter",
    "invoice", "inv", "amount", "due", "balance", "total", "subtotal", "tax",
    "points", "findings", "results", "overview", "action", "items", "account",
    "savings", "transaction", "registered", "landline", "deposit", "premises",
    "operations", "host", "mitigation", "access", "key", "advanced", "learning",
    "official", "direct", "site", "reliability", "case", "frequent", "flyer", "technology"
}

ORGANIZATION_KEYWORDS = {
    "committee", "board", "council", "commission", "department", "division", 
    "team", "organization", "agency", "association", "service", "system"
}

STREET_SUFFIXES = {
    "ave", "avenue", "street", "st", "road", "rd", "lane", "ln", 
    "drive", "dr", "way", "court", "ct", "boulevard", "blvd", 
    "place", "pl", "terrace", "circle", "highway", "hwy", "square", "sq",
    "cross", "main", "layout", "sector", "phase", "stage", "block"
}

COMMON_STOPWORDS = {
    "the", "this", "that", "these", "those", "yesterday", "today", "tomorrow",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "please", "kindly", "dear",
    "regarding", "after", "before", "during", "while", "when", "where", "what",
    "which", "who", "whom", "whose", "why", "how", "with", "without", "within",
    "between", "among", "through", "about", "above", "below", "under", "over",
    "into", "onto", "upon", "from", "towards", "against", "because", "since",
    "although", "though", "even", "unless", "until", "however", "therefore",
    "furthermore", "moreover", "meanwhile", "instead", "besides", "additionally",
    "similarly", "likewise", "accordingly", "consequently", "hence", "thus",
    "overall", "first", "second", "third", "finally", "lastly", "next", "then",
    "soon", "later", "earlier", "already", "still", "yet", "just", "now", "always",
    "never", "often", "sometimes", "usually", "rarely", "almost", "nearly",
    "quite", "rather", "very", "too", "extremely", "well", "new", "old", "high",
    "low", "great", "long", "short", "own", "other", "another", "such", "same",
    "different", "similar", "certain", "clear", "simple", "free", "ready",
    "united", "states", "north", "south", "east", "west", "central", "national",
    "international", "global", "public", "private", "general", "special",
    "medical", "clinical", "technical", "financial", "legal", "corporate",
    "meeting", "notes", "agreement", "contract", "policy", "project", "quarterly",
    "discussion", "findings", "results", "social", "security", "permanent"
}

def is_valid_name(name_str: str, allow_lowercase: bool = False) -> bool:
    clean = name_str.strip().rstrip(".,;:")
    if len(clean) < 2:
        return False
    lower_clean = clean.lower()
    
    # 1. Reject known non-name corporate, tech & heading phrases
    if lower_clean in NON_NAME_PHRASES:
        return False

    tokens = [t.lower().strip(".,") for t in re.split(r"[\s,]+", clean) if t.strip(".,")]
    if not tokens:
        return False

    # 2. Reject if ends with an address/street suffix (e.g. Dr. Strange Ave, Elm Street)
    if tokens[-1] in STREET_SUFFIXES:
        return False

    # 3. Filter out organizations, corporate indicators, and committees
    if any(t in ORGANIZATION_INDICATORS for t in tokens) or any(t in ORGANIZATION_KEYWORDS for t in tokens):
        return False

    # 4. Filter out phrases where all tokens are disallowed words
    if all(t in DISALLOWED_NAME_TOKENS for t in tokens):
        return False
    if len(tokens) == 1 and tokens[0] in DISALLOWED_NAME_TOKENS:
        return False

    # 5. Casing check
    if not allow_lowercase:
        # Must have at least one capitalized token
        if not any(t[0].isupper() for t in clean.split() if t):
            return False

    # 6. Reject if all tokens are generic stopwords/nouns (e.g., "Machine Learning", "Action Items")
    if len(tokens) >= 2 and all(t in COMMON_STOPWORDS or t in DISALLOWED_NAME_TOKENS for t in tokens):
        return False

    return True

class PresidioStyleRecognizer:
    def __init__(
        self, 
        name: str, 
        category: str, 
        patterns: List[Dict[str, Any]], 
        context_words: List[str] | None = None, 
        validator_fn = None
    ):
        self.name = name
        self.category = category
        self.patterns = patterns
        self.context_words = [w.lower() for w in (context_words or [])]
        self.validator_fn = validator_fn

    def analyze(self, text: str, page_num: int = 1) -> List[DetectedSpan]:
        spans = []
        lower_text = text.lower()

        for pat_cfg in self.patterns:
            regex = pat_cfg["regex"]
            base_score = pat_cfg.get("score", 0.85)
            target_group = pat_cfg.get("group", 0)
            allow_lower = pat_cfg.get("allow_lowercase", False)

            for match in re.finditer(regex, text):
                if target_group > 0 and len(match.groups()) >= target_group:
                    val = match.group(target_group).strip()
                    start_char = match.start(target_group)
                    end_char = match.end(target_group)
                else:
                    val = match.group(0).strip()
                    start_char = match.start()
                    end_char = match.end()

                # Clean trailing punctuation
                val = val.rstrip(".,;:")
                if not val or len(val) < 2:
                    continue

                if self.category == "NAME" and not is_valid_name(val, allow_lowercase=allow_lower):
                    continue

                # Surrounding context window
                ctx_start = max(0, start_char - 60)
                ctx_end = min(len(text), end_char + 60)
                surrounding = lower_text[ctx_start:ctx_end]

                # False positive check (except for address recognizers which have valid city/street words)
                if self.category != "ADDRESS" and is_likely_non_pii(val, surrounding):
                    continue

                # Context-aware Aadhaar check
                if self.name == "AadhaarRecognizer":
                    has_ctx = any(cw in surrounding for cw in self.context_words)
                    if not (validate_verhoeff_checksum(val) or has_ctx):
                        continue
                elif self.name == "PhoneRecognizer":
                    # Pass surrounding context to prevent capturing account/bank numbers
                    if not validate_phone_digits(val, surrounding):
                        continue
                elif self.validator_fn:
                    if not self.validator_fn(val):
                        continue

                # Context score boost
                score = base_score
                if any(cw in surrounding for cw in self.context_words):
                    score = min(0.99, score + 0.08)

                spans.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=val,
                    category=self.category,
                    start_char=start_char,
                    end_char=start_char + len(val),
                    page_num=page_num,
                    source=f"rule:{self.name}",
                    confidence=score,
                    accepted=True
                ))
        return spans

RECOGNIZERS = [
    # 1. Emails: Standard, Obfuscated, Spaces around @, and Unicode
    PresidioStyleRecognizer(
        name="EmailRecognizer",
        category="EMAIL",
        patterns=[
            # Standard RFC email
            {"regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b", "score": 0.96},
            # Emails with whitespace around @ or domain dot (e.g. user @ domain.com, user@ domain.com)
            {"regex": r"(?i:\b[A-Za-z0-9._%+\-\u00A0-\uFFFF]+\s*@\s*[A-Za-z0-9.\-\u00A0-\uFFFF]+\s*\.\s*[A-Za-z]{2,7}\b)", "score": 0.95},
            # Obfuscated emails with bracketed at: user [at] example.com, user (at) domain dot com
            {"regex": r"(?i:\b[A-Za-z0-9._%+-]+(?:\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*[A-Za-z0-9._%+-]+)*\s*(?:\[at\]|\(at\))\s*[A-Za-z0-9.-]+\s*(?:\[dot\]|\(dot\)|\bdot\b|\.)\s*[A-Za-z]{2,7}\b)", "score": 0.95},
            # Obfuscated emails with word 'at' and 'dot': john.doe at example dot com, user dot name at domain dot com
            {"regex": r"(?i:\b[A-Za-z0-9._%+-]+(?:\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*[A-Za-z0-9._%+-]+)*\s*\bat\b\s*[A-Za-z0-9.-]+\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*[A-Za-z]{2,7}\b)", "score": 0.94}
        ],
        context_words=["email", "e-mail", "mail", "contact", "to", "from"]
    ),

    # 2. Phones: Landlines, Mobiles & International E.164 (+91, +44, +1, STD, 10-digit)
    PresidioStyleRecognizer(
        name="PhoneRecognizer",
        category="PHONE",
        patterns=[
            # International format with country code (e.g. +44 20 7946 0958, +44-20-7946-0958)
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)\+\d{1,3}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?)?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", "score": 0.94},
            # +91 mobiles: +91 98230 11223, +91-94220-54321
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)(?:\+91[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}\b", "score": 0.93},
            # STD Landlines: 020-25678901, 022-24123456, 020-66778899
            {"regex": r"\b0\d{2,4}[-.\s]?\d{6,8}\b", "score": 0.91},
            # Standard 10-digit mobile: 9876543210
            {"regex": r"\b[6-9]\d{9}\b", "score": 0.89},
            # International / US formats: +1-555-0199, (555) 234-5678
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s])?\d{3,4}[-.\s]\d{4}\b", "score": 0.89}
        ],
        context_words=["phone", "mobile", "cell", "tel", "contact", "call", "landline", "direct", "registered"],
        validator_fn=validate_phone_digits
    ),

    # 3. Aadhaar Number (4-4-4 format with Verhoeff Checksum or Context Anchor)
    PresidioStyleRecognizer(
        name="AadhaarRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b", "score": 0.98}
        ],
        context_words=["aadhaar", "uidai", "national id", "identification"]
    ),

    # 4. Indian PAN Card Number
    PresidioStyleRecognizer(
        name="PanCardRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "score": 0.98}
        ],
        context_words=["pan", "permanent account number", "tax id"],
        validator_fn=validate_pan_format
    ),

    # 5. GSTIN (Goods and Services Tax Identification Number - 15 chars)
    PresidioStyleRecognizer(
        name="GstinRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b", "score": 0.98}
        ],
        context_words=["gst", "gstin", "tax", "invoice", "vendor", "bill"],
        validator_fn=validate_gstin_format
    ),

    # 6. IFSC (Indian Financial System Code - 11 chars: 4 alpha + '0' + 6 alphanumeric)
    PresidioStyleRecognizer(
        name="IfscRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "score": 0.97}
        ],
        context_words=["ifsc", "bank", "branch", "neft", "rtgs", "imps", "account"],
        validator_fn=validate_ifsc_format
    ),

    # 7. UAN (Universal Account Number for EPFO - 12 digits)
    PresidioStyleRecognizer(
        name="UanRecognizer",
        category="ID",
        patterns=[
            {"regex": r"(?i:\b(?:UAN|Universal\s+Account\s+Number)\b[:\s#-]+)([1-9]\d{11})\b", "score": 0.98, "group": 1},
            {"regex": r"\b[1-9]\d{11}\b", "score": 0.93}
        ],
        context_words=["uan", "epfo", "provident", "pf number", "pension"],
        validator_fn=validate_uan_format
    ),

    # 8. Generic ID Recognizer: Label followed by ID-shaped token & Bank Account Numbers
    PresidioStyleRecognizer(
        name="GenericIDRecognizer",
        category="ID",
        patterns=[
            # Generic label followed by ID (e.g. Employee ID: 10234, Staff ID: S-99812, Customer ID: CUST-77881, Emp. No. 4471)
            {
                "regex": (
                    r"(?i:\b(?:Employee\s*ID|Staff\s*ID|Customer\s*ID|Cust\s*ID|Emp\.?\s*(?:No\.?|ID|Code|Num)|"
                    r"Member\s*ID|Patient\s*ID|User\s*ID|Student\s*ID|Registration\s*(?:No\.?|Number)|"
                    r"Reg\.?\s*No\.?|Citizen\s*ID|National\s*ID|Voter\s*ID|Voter\s*Card|Policy\s*(?:No\.?|Number)|"
                    r"Claim\s*(?:No\.?|Number)|Beneficiary\s*ID|Client\s*ID)(?:[:\s#–—-]+))"
                    r"([A-Za-z0-9][A-Za-z0-9\-_/]{1,24}[A-Za-z0-9]|[A-Za-z0-9]{2,24})\b"
                ),
                "score": 0.97,
                "group": 1
            },
            # Bank Account numbers (spaced or unspaced 8-24 characters: Acct No 9876 5432 1098)
            {
                "regex": (
                    r"(?i:\b(?:Account(?:\s+Number|\s+No\.?|\s+No)?|Acct\.?(?:\s+Number|\s+No\.?|\s+No)?|"
                    r"A/C(?:\s+Number|\s+No\.?|\s+No)?|Savings\s+Account|Current\s+Account)\b[:\s#-]+)"
                    r"([0-9][0-9 \t\-]{7,24}[0-9]|[0-9]{8,24})\b"
                ),
                "score": 0.97,
                "group": 1
            },
            # US SSN
            {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "score": 0.96},
            # Passport Numbers
            {"regex": r"(?i:\b(?:Passport(?:\s+No|\s+Number)?)\b[:\s]+)([A-Za-z0-9]{6,10})\b", "score": 0.96, "group": 1},
            {"regex": r"\b[A-PR-WYa-pr-wy][0-9]{7}\b", "score": 0.90},
            # Driving Licences
            {"regex": r"(?i:\b(?:DL|Driving\s+Licence|Driver's\s+License|License\s+No|DL\s+No)\b[:\s]+)([A-Za-z0-9 -]{8,18})\b", "score": 0.96, "group": 1},
            {"regex": r"\b[A-Z]{2}[0-9]{2}[ -]?(?:19|20)[0-9]{2}[0-9]{7}\b", "score": 0.94},
            # Known Prefix ID codes (EMP-9421, MRN-4412, etc.)
            {"regex": r"\b(?:EMP|EID|FF|MRN|STU|STUID|SID)[-_:]?\s*\d{4,8}\b", "score": 0.95},
            # Student ID & Roll Number
            {"regex": r"(?i:\b(?:Student\s+ID|Roll\s+No\.?|Roll\s+Number|Enrollment\s+No\.?|SID)\b[:\s]+)([A-Za-z0-9-]+)\b", "score": 0.95, "group": 1},
            # Voter ID / EPIC
            {"regex": r"\b[A-Z]{3}[0-9]{7}\b", "score": 0.92},
            # IPv4 Address
            {"regex": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "score": 0.92}
        ],
        context_words=["employee", "code", "account", "savings", "member", "ssn", "student", "roll", "ip", "voter", "passport", "license", "licence", "acct"]
    ),

    # 9. PIN-Code & Postal-Code Anchored Physical Addresses
    PresidioStyleRecognizer(
        name="PinCodeAnchoredAddressRecognizer",
        category="ADDRESS",
        patterns=[
            # Addresses anchored by a 6-digit Indian PIN code (No. 12, 4th Cross, Indiranagar, Bengaluru 560038)
            {
                "regex": (
                    r"\b(?:No\.?\s*\d+[A-Za-z]?|Plot\s*(?:No\.?)?\s*\d+|Sector\s*\d+|Flat\s*(?:No\.?)?\s*\d+|"
                    r"House\s*(?:No\.?)?\s*\d+|\d{1,5}[A-Za-z]?(?:/[A-Za-z0-9]+)?)"
                    r"[,\s]+[A-Za-z0-9\s,.'/-]+?\b(?:\d{6}|[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}|\d{5}(?:-\d{4})?)\b"
                ),
                "score": 0.95
            },
            # Street pattern format (supports "221B Baker Street, London NW1 6XE" and "14, MG Road, Bengaluru 560001")
            {
                "regex": (
                    r"\b\d{1,5}[A-Za-z]?(?:/[A-Za-z0-9]+)?(?:[^\S\r\n]*,[^\S\r\n]*|[^\S\r\n]+)"
                    r"(?:[A-Za-z0-9.'-]+[^\S\r\n]*){1,4}\b"
                    r"(?:Street|St|Avenue|Ave|Road|Rd|Park|Marg|Lane|Ln|Drive|Dr|Terrace|Way|Court|Ct|Colony|Nagar|Point|Sector|Complex|Place|Pl|Boulevard|Blvd|Cross|Main)\b"
                    r"(?:[^\r\n,]+,)*[^\r\n]+?\b(?:\d{6}|[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}|\d{5})\b"
                ),
                "score": 0.94
            }
        ],
        context_words=["address", "residence", "office", "road", "street", "cross", "sector", "nagar", "bengaluru", "noida", "mumbai", "london", "pune"]
    ),

    # 10. Explicit Prefix & Structural Addresses
    PresidioStyleRecognizer(
        name="AddressPrefixRecognizer",
        category="ADDRESS",
        patterns=[
            {"regex": r"(?:\b(?:Address|Branch|Meeting held at|Leased Premises|Residence|Office|Location|residing at|located at|locked workstation located at)[:\s]+)([^;\r\n\)]+?)(?=\s*(?:\)|and\s+[A-Z]|\bcontact\b|\bphone\b|\bemail\b|[;\r\n]|$))", "score": 0.93, "group": 1}
        ],
        context_words=["address", "residence", "office", "branch", "premises", "road", "park", "nagar", "located", "residing"]
    ),
    PresidioStyleRecognizer(
        name="AddressPatternRecognizer",
        category="ADDRESS",
        patterns=[
            # Flat format: Flat 101, Palm Court, Mumbai, MH 400050
            {"regex": r"\bFlat\s+\d+[A-Za-z0-9\s,-]*?\b(?:Street|St|Avenue|Ave|Road|Rd|Park|Marg|Lane|Ln|Drive|Dr|Terrace|\bWay\b|Court|Ct|Colony|Nagar|Point|Sector|Complex)\b(?:[^\S\r\n]*,[^\S\r\n]*[A-Za-z\s]+)*(?:[^\S\r\n]*,[^\S\r\n]*[A-Z]{2}[^\S\r\n]+\d{5,6})?", "score": 0.90},
            # Landmark / Tech Park format: Tech Park 4, Bellandur, Bangalore 560103
            {"regex": r"\b(?:Tech Park|IT Park|Cyber City|Prestige Tech|EON Free Zone|Manyata)[^\r\n,]+,[^\r\n,]+,[^\r\n,]+\d{5,6}\b", "score": 0.91}
        ],
        context_words=["address", "road", "street", "pune", "mumbai", "bangalore", "delhi", "bengaluru", "london"]
    ),

    # 11. Person Names (Headers, Attendee Lists, Signatures, Initials, ALL-CAPS, Lowercase)
    PresidioStyleRecognizer(
        name="NameHeaderRecognizer",
        category="NAME",
        patterns=[
            # Standard Title-case header names (supports names split across line breaks e.g. Consultant: Sneha\nDeshmukh)
            {
                "regex": (
                    r"(?i:\b(?:Patient Name|Primary Patient|Emergency Contact|Attn|Attending Doctor|"
                    r"Attending Physician|Doctor|Candidate|Officer|Caller Name|"
                    r"Caller|User Name|User|Submitted by|Consultant|Reviewer|Manager|Employee Name|"
                    r"Employee(?:\s+[A-Z])?|Witness|Landlord|Tenant|Passenger|Author|Lead|Contact Person|"
                    r"Contact|Account Holder|Speaker|Chairman|Chief Financial Officer|Corporate Secretary|"
                    r"Reported By|Legal Counsel|Managing Director|Chief Legal Officer|CISO Contact|"
                    r"Consultant|Advisor|Auditor|Officer|Doctor|Attending|Reviewer|Witness|Tenant|Passenger|"
                    r"Assigned to|From|To|Dear|Customer|Client|Patient|Name)\b[:\s]+)"
                    r"((?:(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Mr|Mrs|Ms|Dr|Prof)[ \t]+)?"
                    r"(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)"
                    r"(?:(?:[ \t]+|[ \t]*\r?\n[ \t]*(?![^\r\n]{0,40}:))(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)){0,3})"
                ),
                "score": 0.94,
                "group": 1
            },
            # ALL-CAPS names in official headers (e.g. Employee: RAJIV SHARMA, Attending: DR. ARVIND PATEL)
            {
                "regex": (
                    r"(?i:\b(?:Patient Name|Primary Patient|Employee Name|Employee|Candidate|Officer|Caller|User Name|"
                    r"Doctor|Attending|Consultant|Reviewer|Manager|Witness|Tenant|Passenger|"
                    r"Contact Person|Reported By|Attendee|Name|From|To)\b[:\s]+)"
                    r"((?:(?:MR\.|MRS\.|MS\.|DR\.|PROF\.)[ \t]+)?[A-Z]{2,}(?:(?:[ \t]+|[ \t]*\r?\n[ \t]*(?![^\r\n]{0,40}:))[A-Z]{2,}){1,2})\b"
                ),
                "score": 0.93,
                "group": 1
            },
            # Lowercase names preceded by strong personal name headers (e.g. Patient Name: john doe)
            {
                "regex": (
                    r"(?i:\b(?:Patient Name|Primary Patient|Emergency Contact|Employee Name|Candidate|Contact Person|Name)\b[:\s]+)"
                    r"([a-z]{2,}(?:(?:[ \t]+|[ \t]*\r?\n[ \t]*(?![^\r\n]{0,40}:))[a-z]{2,}){1,2})\b"
                ),
                "score": 0.92,
                "group": 1,
                "allow_lowercase": True
            },
            # Signature block names
            {
                "regex": r"(?:\b(?:Sincerely|Respectfully|Sincerely and Respectfully|Regards|Best regards|Warm regards|Yours sincerely|Yours faithfully)\b[^\r\n]*\r?\n+)([A-Za-z]+(?:[^\S\r\n]+[A-Za-z]+){1,2})",
                "score": 0.92,
                "group": 1
            },
            # Initial variants: R. Sharma, R Sharma, S. K. Rao, Sneha R. Deshmukh
            {
                "regex": r"\b(?:[A-Z][a-z]+[^\S\r\n]+)?[A-Z]\.?(?:\s*[A-Z]\.?)*[^\S\r\n]+[A-Z][a-z]+\b",
                "score": 0.92
            },
            # Standalone Honorific names: Mr. O'Connor, Dr. Kenneth O'Connor, Dr. Arvind Patel, Dr Arvind Patel, Dr. R Sharma, Dr R Sharma
            {
                "regex": r"\b(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)[^\S\r\n]+((?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.?)(?:[^\S\r\n]+(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.?)){0,2})\b",
                "score": 0.94,
                "group": 0
            }
        ],
        context_words=["name", "patient", "doctor", "attendee", "employee", "director", "manager"]
    )
]

def chunk_text(text: str, chunk_size: int = 400, overlap: int = 50) -> List[Tuple[str, int]]:
    """Chunks text into word windows with overlap to ensure fast inference on laptops."""
    words = text.split()
    if len(words) <= chunk_size:
        return [(text, 0)]
    
    chunks = []
    start_word = 0
    while start_word < len(words):
        end_word = min(len(words), start_word + chunk_size)
        sub_words = words[start_word:end_word]
        chunk_str = " ".join(sub_words)
        char_offset = text.find(chunk_str)
        if char_offset == -1:
            char_offset = 0
        chunks.append((chunk_str, char_offset))
        start_word += (chunk_size - overlap)
        if end_word >= len(words):
            break
            
    return chunks

def detect_by_rules(text: str, page_num: int = 1) -> List[DetectedSpan]:
    """Runs all registered Presidio-style pattern recognizers with coreference propagation."""
    detected: List[DetectedSpan] = []
    for recognizer in RECOGNIZERS:
        detected.extend(recognizer.analyze(text, page_num=page_num))

    # Parse attendee/board-member lists
    list_header_pat = re.compile(r"(?:\b(?:Attendees|Board Members Present)[:\s]+)([^\r\n]+)", re.IGNORECASE)
    for m in list_header_pat.finditer(text):
        line = m.group(1)
        line_start = m.start(1)
        for part in re.split(r"[,;]|\band\b", line):
            part_clean = re.sub(r"\(.*?\)", "", part).strip()
            if part_clean and len(part_clean) > 2 and is_valid_name(part_clean):
                sub_match = re.search(r"\b" + re.escape(part_clean) + r"\b", line)
                if sub_match:
                    detected.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        text=part_clean,
                        category="NAME",
                        start_char=line_start + sub_match.start(),
                        end_char=line_start + sub_match.end(),
                        page_num=page_num,
                        source="rule:AttendeeNameRecognizer",
                        confidence=0.92,
                        accepted=True
                    ))

    # Running-text Proper Name Detection (supports Title-case words across horizontal space OR single newline)
    word_pat = re.compile(r"\b(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.?)\b")
    cap_words = [(m.group(0), m.start(), m.end()) for m in word_pat.finditer(text)]

    # Check 3-word names (e.g. "Sneha R. Deshmukh", "Vikram Singh Rathore")
    for i in range(len(cap_words) - 2):
        w1, s1, e1 = cap_words[i]
        w2, s2, e2 = cap_words[i + 1]
        w3, s3, e3 = cap_words[i + 2]
        gap1 = text[e1:s2]
        gap2 = text[e2:s3]
        if gap1 == ' ' and gap2 == ' ':
            w1_l, w2_l, w3_l = w1.lower().rstrip('.'), w2.lower().rstrip('.'), w3.lower().rstrip('.')
            if (w1_l not in COMMON_STOPWORDS and w3_l not in COMMON_STOPWORDS and
                w1_l not in DISALLOWED_NAME_TOKENS and w3_l not in DISALLOWED_NAME_TOKENS and
                w3_l not in STREET_SUFFIXES):
                full_cand = f"{w1} {w2} {w3}"
                ctx_start = max(0, s1 - 40)
                ctx_end = min(len(text), e3 + 40)
                if is_valid_name(full_cand) and not is_likely_non_pii(full_cand, text[ctx_start:ctx_end]):
                    detected.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        text=text[s1:e3],
                        category="NAME",
                        start_char=s1,
                        end_char=e3,
                        page_num=page_num,
                        source="rule:RunningTextName",
                        confidence=0.74,
                        accepted=False
                    ))

    # Check 2-word names (rule-only capitalized bigrams default to low confidence for user review or GLiNER confirmation)
    for i in range(len(cap_words) - 1):
        w1, s1, e1 = cap_words[i]
        w2, s2, e2 = cap_words[i + 1]
        gap = text[e1:s2]
        if gap == ' ':
            w1_l = w1.lower().rstrip('.')
            w2_l = w2.lower().rstrip('.')
            if (w1_l not in COMMON_STOPWORDS and w2_l not in COMMON_STOPWORDS and
                w1_l not in DISALLOWED_NAME_TOKENS and w2_l not in DISALLOWED_NAME_TOKENS and
                w2_l not in STREET_SUFFIXES):
                full_cand = f"{w1} {w2}"
                ctx_start = max(0, s1 - 40)
                ctx_end = min(len(text), e2 + 40)
                if is_valid_name(full_cand) and not is_likely_non_pii(full_cand, text[ctx_start:ctx_end]):
                    detected.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        text=text[s1:e2],
                        category="NAME",
                        start_char=s1,
                        end_char=e2,
                        page_num=page_num,
                        source="rule:RunningTextName",
                        confidence=0.68,
                        accepted=False
                    ))

    # Coreference Name Propagation:
    # 1. Propagate detected full names across the document
    discovered_names = [s.text.strip() for s in detected if s.category == "NAME" and len(s.text.split()) >= 2]
    unique_names = list(set(discovered_names))
    for full_name in unique_names:
        for m in re.finditer(r"\b" + re.escape(full_name) + r"\b", text):
            detected.append(DetectedSpan(
                id=str(uuid.uuid4())[:8],
                text=m.group(0),
                category="NAME",
                start_char=m.start(),
                end_char=m.end(),
                page_num=page_num,
                source="rule:NamePropagation",
                confidence=0.90,
                accepted=True
            ))

    # 2. Propagate constituent bare first/last names and initial variants for headline name linking
    # Handles: "Priya Nair ... Later, Priya said Nair would call" and "Later Sharma said Richa was right"
    constituent_tokens = set()
    for full_name in unique_names:
        clean_name = re.sub(r"^(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+", "", full_name, flags=re.IGNORECASE)
        parts = [p.strip(".,") for p in clean_name.split() if p.strip(".,")]
        if len(parts) >= 2:
            first_tok = parts[0]
            last_tok = parts[-1]
            if len(first_tok) >= 3 and first_tok.lower() not in COMMON_STOPWORDS and first_tok.lower() not in DISALLOWED_NAME_TOKENS:
                constituent_tokens.add(first_tok)
            if len(last_tok) >= 3 and last_tok.lower() not in COMMON_STOPWORDS and last_tok.lower() not in DISALLOWED_NAME_TOKENS and last_tok.lower() not in STREET_SUFFIXES:
                constituent_tokens.add(last_tok)

            # Initial variants without or with dot (e.g. "R Sharma", "R. Sharma", "Dr R Sharma", "Dr. R Sharma")
            init_char = first_tok[0].upper()
            init_variants = [
                rf"\b{init_char}\.?\s+{re.escape(last_tok)}\b",
                rf"\b(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+{init_char}\.?\s+{re.escape(last_tok)}\b",
                rf"\b(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+{re.escape(last_tok)}\b"
            ]
            for iv_pat in init_variants:
                for m in re.finditer(iv_pat, text, flags=re.IGNORECASE):
                    val = m.group(0)
                    detected.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        text=val,
                        category="NAME",
                        start_char=m.start(),
                        end_char=m.end(),
                        page_num=page_num,
                        source="rule:NamePropagation:InitialVariant",
                        confidence=0.91,
                        accepted=True
                    ))

    for tok in constituent_tokens:
        for m in re.finditer(r"\b" + re.escape(tok) + r"\b", text):
            start, end = m.start(), m.end()
            # Do not emit bare token if it's already part of an existing full name span
            if not any(s.category == "NAME" and len(s.text.split()) >= 2 and s.start_char <= start and end <= s.end_char for s in detected):
                detected.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=m.group(0),
                    category="NAME",
                    start_char=start,
                    end_char=end,
                    page_num=page_num,
                    source="rule:NamePropagation:BareToken",
                    confidence=0.72,
                    accepted=False
                ))

    # Clean address prefix captures to strip any trailing metadata keywords
    for s in detected:
        if s.category == "ADDRESS":
            for kw in ["and Phone", "Phone:", "Email:", "Contact:", "Date:", "Ref:"]:
                if kw in s.text:
                    s.text = s.text.split(kw)[0].strip()
                    s.end_char = s.start_char + len(s.text)

    return detected
