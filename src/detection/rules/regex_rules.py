import re
import uuid
from typing import List, Dict, Any, Tuple
from src.detection.schemas import DetectedSpan
from src.detection.validators import (
    validate_verhoeff_checksum,
    validate_pan_format,
    validate_phone_digits,
    is_likely_non_pii
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
    "email", "phone", "mobile", "tel", "fax", "id", "code", "number", "no", 
    "ref", "date", "address", "profile", "itinerary", "advice", "intake", 
    "log", "summary", "report", "ticket", "review", "status", "department", 
    "success", "registration", "notes", "minutes", "agreement", "letter", 
    "notice", "clinical", "support", "desk", "call", "speaker", "passenger",
    "customer", "patient", "employee", "candidate", "doctor", "meeting", "strategy",
    "escalations", "pilot", "regarding", "feedback", "query", "issue", "delivery",
    "committee", "board", "council", "commission", "division", "team", "organization",
    "architect", "engineer", "specialist", "officer", "manager", "lead", "developer",
    "passport", "license", "licence", "dl", "pan", "ssn", "aadhaar", "epic", "voter"
}

ORGANIZATION_KEYWORDS = {
    "committee", "board", "council", "commission", "department", "division", 
    "team", "organization", "agency", "association", "service", "system"
}

STREET_SUFFIXES = {
    "ave", "avenue", "street", "st", "road", "rd", "lane", "ln", 
    "drive", "dr", "way", "court", "ct", "boulevard", "blvd", 
    "place", "pl", "terrace", "circle", "highway", "hwy", "square", "sq"
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
    "meeting", "notes", "agreement", "contract", "policy", "project"
}

def is_valid_name(name_str: str) -> bool:
    clean = name_str.strip().rstrip(".,;:")
    if len(clean) < 2:
        return False
    tokens = [t.lower().strip(".,") for t in clean.split() if t.strip(".,")]
    if not tokens:
        return False
    # Reject if ends with or begins with a street/address suffix (e.g. Dr. Strange Ave)
    if tokens[-1] in STREET_SUFFIXES or tokens[0] in STREET_SUFFIXES:
        return False
    # Filter out organizations / committees
    if any(t in ORGANIZATION_KEYWORDS for t in tokens):
        return False
    if all(t in DISALLOWED_NAME_TOKENS for t in tokens):
        return False
    if len(tokens) == 1 and tokens[0] in DISALLOWED_NAME_TOKENS:
        return False
    if not any(t[0].isupper() for t in clean.split() if t):
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

                if self.category == "NAME" and not is_valid_name(val):
                    continue

                # Surrounding context window
                ctx_start = max(0, start_char - 60)
                ctx_end = min(len(text), end_char + 60)
                surrounding = lower_text[ctx_start:ctx_end]

                # False positive check
                if is_likely_non_pii(val, surrounding):
                    continue

                # Context-aware Aadhaar check
                if self.name == "AadhaarRecognizer":
                    has_ctx = any(cw in surrounding for cw in self.context_words)
                    if not (validate_verhoeff_checksum(val) or has_ctx):
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
    # 1. Emails: Standard and Obfuscated
    PresidioStyleRecognizer(
        name="EmailRecognizer",
        category="EMAIL",
        patterns=[
            # Standard email
            {"regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b", "score": 0.95},
            # Obfuscated emails with bracketed at: user [at] example.com, user (at) domain dot com
            {"regex": r"(?i:\b[A-Za-z0-9._%+-]+(?:\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*[A-Za-z0-9._%+-]+)*\s*(?:\[at\]|\(at\))\s*[A-Za-z0-9.-]+\s*(?:\[dot\]|\(dot\)|\bdot\b|\.)\s*[A-Za-z]{2,7}\b)", "score": 0.94},
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
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)\+\d{1,3}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?)?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", "score": 0.93},
            # +91 mobiles: +91 98230 11223, +91-94220-54321
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)(?:\+91[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}\b", "score": 0.92},
            # STD Landlines: 020-25678901, 022-24123456, 020-66778899
            {"regex": r"\b0\d{2,4}[-.\s]?\d{6,8}\b", "score": 0.90},
            # Standard 10-digit mobile: 9876543210
            {"regex": r"\b[6-9]\d{9}\b", "score": 0.88},
            # International / US formats: +1-555-0199, (555) 234-5678
            {"regex": r"(?:(?<=\s)|(?<=\b)|^)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s])?\d{3,4}[-.\s]\d{4}\b", "score": 0.88}
        ],
        context_words=["phone", "mobile", "cell", "tel", "contact", "call", "landline", "direct", "registered"],
        validator_fn=validate_phone_digits
    ),

    # 3. Aadhaar Number (4-4-4 format with Verhoeff Checksum or Context Anchor)
    PresidioStyleRecognizer(
        name="AadhaarRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b", "score": 0.96}
        ],
        context_words=["aadhaar", "uidai", "national id", "identification"]
    ),

    # 4. Indian PAN Card Number
    PresidioStyleRecognizer(
        name="PanCardRecognizer",
        category="ID",
        patterns=[
            {"regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "score": 0.96}
        ],
        context_words=["pan", "permanent account number", "tax id"],
        validator_fn=validate_pan_format
    ),

    # 5. Government, Passports, Driving Licences, Student, Employee IDs & Bank Accounts
    PresidioStyleRecognizer(
        name="EmployeeAndAccountRecognizer",
        category="ID",
        patterns=[
            # US SSN
            {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "score": 0.95},
            # Passport Numbers (Indian: 1 letter + 7 digits; Keyword: Passport No XXXXXX)
            {"regex": r"(?i:\b(?:Passport(?:\s+No|\s+Number)?)\b[:\s]+)([A-Za-z0-9]{6,10})\b", "score": 0.95, "group": 1},
            {"regex": r"\b[A-PR-WYa-pr-wy][0-9]{7}\b", "score": 0.90},
            # Driving Licences (Indian DL, US/UK format, or Driving Licence keyword)
            {"regex": r"(?i:\b(?:DL|Driving\s+Licence|Driver's\s+License|License\s+No|DL\s+No)\b[:\s]+)([A-Za-z0-9 -]{8,18})\b", "score": 0.95, "group": 1},
            {"regex": r"\b[A-Z]{2}[0-9]{2}[ -]?(?:19|20)[0-9]{2}[0-9]{7}\b", "score": 0.94},
            # Employee / Medical / Student / Frequent Flyer Codes
            {"regex": r"\b(?:EMP|EID|FF|MRN|STU|STUID|SID)[-_:]?\s*\d{4,8}\b", "score": 0.94},
            # Student ID & Roll Number patterns
            {"regex": r"\b(?:Student\s+ID|Roll\s+No|Roll\s+Number|Enrollment\s+No|SID)[:\s]+([A-Za-z0-9-]+)\b", "score": 0.94, "group": 1},
            # Indian Voter ID / EPIC
            {"regex": r"\b[A-Z]{3}[0-9]{7}\b", "score": 0.92},
            # Bank Account numbers (11-16 digits when near account keywords)
            {"regex": r"(?:Account|Account Number|Savings Account|A/C|Acct)[:\s]{1,4}(\d{11,16})\b", "score": 0.94, "group": 1},
            # IPv4 Address
            {"regex": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "score": 0.92}
        ],
        context_words=["employee", "code", "account", "savings", "member", "ssn", "student", "roll", "ip", "voter", "passport", "license", "licence"]
    ),

    # 6. Physical & Postal Addresses (Prefix-driven, Comma-delimited and Street Pattern)
    PresidioStyleRecognizer(
        name="AddressPrefixRecognizer",
        category="ADDRESS",
        patterns=[
            {"regex": r"(?:\b(?:Address|Branch|Meeting held at|Leased Premises|Residence|Office|Location|residing at|located at|locked workstation located at)[:\s]+)([^;\r\n\)]+?)(?=\s*(?:\)|and\s+[A-Z]|\bcontact\b|\bphone\b|\bemail\b|[;\r\n]|$))", "score": 0.92, "group": 1}
        ],
        context_words=["address", "residence", "office", "branch", "premises", "road", "park", "nagar", "located", "residing"]
    ),
    PresidioStyleRecognizer(
        name="AddressPatternRecognizer",
        category="ADDRESS",
        patterns=[
            # Flat format: Flat 101, Palm Court, Mumbai, MH 400050
            {"regex": r"\bFlat\s+\d+[A-Za-z0-9\s,-]*?\b(?:Street|St|Avenue|Ave|Road|Rd|Park|Marg|Lane|Ln|Drive|Dr|Terrace|\bWay\b|Court|Ct|Colony|Nagar|Point|Sector|Complex)\b(?:[^\S\r\n]*,[^\S\r\n]*[A-Za-z\s]+)*(?:[^\S\r\n]*,[^\S\r\n]*[A-Z]{2}[^\S\r\n]+\d{5,6})?", "score": 0.88},
            # Street number format (supports 14, MG Road, Bengaluru 560001 and 22/B Baker Street, London NW1 6XE)
            {"regex": r"\b\d{1,5}(?:/[A-Za-z0-9]+)?(?:[^\S\r\n]*,[^\S\r\n]*|[^\S\r\n]+)(?:[A-Z][a-zA-Z0-9.'-]+[^\S\r\n]*){1,4}\b(?:Street|St|Avenue|Ave|Road|Rd|Park|Marg|Lane|Ln|Drive|Dr|Terrace|\bWay\b|Court|Ct|Colony|Nagar|Point|Sector|Complex|Place|Pl|Boulevard|Blvd)\b(?:[^\S\r\n]*,[^\S\r\n]*(?:Suite|Apt|Floor|Unit|Flat)[^\S\r\n]+[A-Za-z0-9-]+)?(?:[^\S\r\n]*,[^\S\r\n]*[A-Za-z]+)*(?:[^\S\r\n]*,?[^\S\r\n]*(?:[A-Z]{2}[^\S\r\n]+)?(?:\d{5,6}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?[^\S\r\n]+\d[A-Z]{2}))?", "score": 0.90},
            # Landmark / Tech Park format: Tech Park 4, Bellandur, Bangalore 560103
            {"regex": r"\b(?:Tech Park|IT Park|Cyber City|Prestige Tech|EON Free Zone|Manyata)[^\r\n,]+,[^\r\n,]+,[^\r\n,]+\d{5,6}\b", "score": 0.90}
        ],
        context_words=["address", "road", "street", "pune", "mumbai", "bangalore", "delhi", "bengaluru", "london"]
    ),

    # 7. Person Names (Headers, Attendee Lists, Signatures, Initials, Honorifics)
    PresidioStyleRecognizer(
        name="NameHeaderRecognizer",
        category="NAME",
        patterns=[
            # Single name prefixes (supports honorifics, apostrophes, hyphens e.g. Dear Mr. O'Connor, Candidate: Mary-Jane Smith-Jones)
            {
                "regex": (
                    r"(?i:\b(?:Patient Name|Primary Patient|Emergency Contact|Attn|Attending Doctor|"
                    r"Attending Physician|Doctor|Candidate|Officer|Caller Name|"
                    r"Caller|User Name|User|Submitted by|Consultant|Reviewer|Manager|Employee Name|"
                    r"Employee(?:\s+[A-Z])?|Witness|Landlord|Tenant|Passenger|Author|Lead|Contact Person|"
                    r"Contact|Account Holder|Speaker|Chairman|Chief Financial Officer|Corporate Secretary|"
                    r"Reported By|Legal Counsel|Managing Director|Chief Legal Officer|CISO Contact|"
                    r"Compromised Account|Assigned to|From|To|Dear|customer|Client|Patient|Name)\b[:\s]+)"
                    r"((?:(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Mr|Mrs|Ms|Dr|Prof)[^\S\r\n]+)?"
                    r"(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)"
                    r"(?:[^\S\r\n]+(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)){0,3})"
                ),
                "score": 0.93,
                "group": 1
            },
            # Signature block names
            {
                "regex": r"(?:\b(?:Sincerely|Respectfully|Sincerely and Respectfully|Regards|Best regards|Warm regards|Yours sincerely|Yours faithfully)\b[^\r\n]*\r?\n+)([A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+){1,2})",
                "score": 0.92,
                "group": 1
            },
            # Initial variants: R. Sharma, S. K. Rao, Sneha R. Deshmukh
            {
                "regex": r"\b(?:[A-Z][a-z]+[^\S\r\n]+)?[A-Z]\.(?:\s*[A-Z]\.)*[^\S\r\n]+[A-Z][a-z]+\b",
                "score": 0.90
            },
            # Standalone Honorific names: Mr. O'Connor, Dr. Kenneth O'Connor, Dr. Arvind Patel
            {
                "regex": r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.|Prof\.)\s+((?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)(?:\s+(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]\.)){0,2})\b",
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

    # Running-text Proper Name Detection (e.g. "Yesterday Priya Nair met Amit Verma...")
    word_pat = re.compile(r"\b(?:(?:O'|D'|Mc|Mac|Al-)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?)\b")
    cap_words = [(m.group(0), m.start(), m.end()) for m in word_pat.finditer(text)]
    for i in range(len(cap_words) - 1):
        w1, s1, e1 = cap_words[i]
        w2, s2, e2 = cap_words[i + 1]
        # Only horizontal whitespace between words (never across newlines)
        if s2 == e1 + 1 and text[e1:s2] == ' ':
            w1_l = w1.lower()
            w2_l = w2.lower()
            if (w1_l not in COMMON_STOPWORDS and w2_l not in COMMON_STOPWORDS and
                w1_l not in DISALLOWED_NAME_TOKENS and w2_l not in DISALLOWED_NAME_TOKENS and
                w1_l not in STREET_SUFFIXES and w2_l not in STREET_SUFFIXES):
                detected.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=f"{w1} {w2}",
                    category="NAME",
                    start_char=s1,
                    end_char=e2,
                    page_num=page_num,
                    source="rule:RunningTextName",
                    confidence=0.88,
                    accepted=True
                ))

    # Coreference Name Propagation:
    # Propagate detected full names across the document
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

    # Clean address prefix captures to strip any trailing metadata keywords
    for s in detected:
        if s.category == "ADDRESS":
            clean_addr = re.split(r"\b(?:Vitals|Phone|Tel|Mobile|Email|Contact|Resolution|Ref)[:\s]", s.text, flags=re.IGNORECASE)[0].strip()
            clean_addr = clean_addr.rstrip(".,;")
            if len(clean_addr) < len(s.text):
                s.text = clean_addr
                s.end_char = s.start_char + len(clean_addr)

    # Priority overlap resolution: longer span, higher confidence
    detected.sort(key=lambda s: (-(s.end_char - s.start_char), -s.confidence))
    filtered: List[DetectedSpan] = []
    for s in detected:
        overlap = False
        for ex in filtered:
            if not (s.end_char <= ex.start_char or s.start_char >= ex.end_char):
                overlap = True
                break
        if not overlap:
            filtered.append(s)

    filtered.sort(key=lambda s: s.start_char)
    return filtered
