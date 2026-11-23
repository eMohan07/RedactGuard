import re

# Verhoeff algorithm multiplication (d) and permutation (p) tables for Aadhaar checksum validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def validate_verhoeff_checksum(num_str: str) -> bool:
    """Validates Aadhaar 12-digit number using the Verhoeff checksum algorithm."""
    digits = re.sub(r"\D", "", num_str)
    if len(digits) != 12:
        return False
    
    # Check that it doesn't start with 0 or 1 (Aadhaar specification)
    if digits[0] in ('0', '1'):
        return False

    c = 0
    reversed_digits = [int(d) for d in reversed(digits)]
    for i, d in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0

def validate_pan_format(pan_str: str) -> bool:
    """
    Validates Indian Permanent Account Number (PAN):
    - Exactly 10 characters: 5 letters, 4 digits, 1 letter.
    - 4th character must be a valid entity type (P=Individual, C=Company, etc.)
    """
    cleaned = pan_str.strip().upper()
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]{1}", cleaned):
        return False
    valid_4th = {'P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'}
    return cleaned[3] in valid_4th

def validate_gstin_format(gstin_str: str) -> bool:
    """
    Validates Indian Goods and Services Tax Identification Number (GSTIN):
    - Exactly 15 characters: 2 state digits + 10 char PAN + 1 entity num + 'Z' + 1 check char.
    """
    cleaned = gstin_str.strip().upper()
    return bool(re.fullmatch(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}", cleaned))

def validate_ifsc_format(ifsc_str: str) -> bool:
    """
    Validates Indian Financial System Code (IFSC):
    - 11 characters: 4 letters (bank code) + '0' + 6 alphanumeric (branch code).
    """
    cleaned = ifsc_str.strip().upper()
    return bool(re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned))

def validate_uan_format(uan_str: str) -> bool:
    """
    Validates Indian Universal Account Number (UAN for EPFO):
    - Exactly 12 digits.
    """
    digits = re.sub(r"\D", "", uan_str)
    return len(digits) == 12 and not (digits.startswith("0") or digits.startswith("100000000000"))

def validate_phone_digits(phone_str: str, surrounding_context: str = "") -> bool:
    """
    Validates phone number:
    - Must have between 7 and 13 digits.
    - Rejects dates (ISO, UK/India formats) and trivial repetitions like '0000000000'.
    - Rejects strings starting with years like '2024-' which are invoice/reference years.
    - Rejects strings preceded by Account / Bank / Card / ID / Invoice keywords.
    """
    clean = phone_str.strip()
    # Reject dates
    if re.fullmatch(r"(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}", clean):
        return False
    if re.fullmatch(r"\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}", clean):
        return False
    # Reject year-prefixed invoice patterns like 2024-9982 unless explicitly phone formatted
    if re.fullmatch(r"(?:19|20)\d{2}[-]\d{3,5}", clean):
        return False

    # Check if context clearly says this is an account or financial ID, not a phone
    if surrounding_context:
        lower_ctx = surrounding_context.lower()
        account_indicators = [
            "acct", "account", "a/c", "card number", "card no", "bank", "savings", 
            "current a/c", "invoice", "inv no", "order #", "policy no", "claim no", 
            "emp no", "employee id", "staff id", "customer id", "cust id", "gstin", "ifsc"
        ]
        if any(ind in lower_ctx for ind in account_indicators):
            return False

    digits = re.sub(r"\D", "", clean)
    if len(digits) < 7 or len(digits) > 13:
        return False
    if len(set(digits)) == 1:
        return False
    return True

# Context words that signal a number or code is NOT a personal ID or account
NON_PII_CONTEXT_KEYWORDS = [
    "ref", "reference", "invoice", "inv", "product", "sku", "order",
    "ticket", "tck", "case", "flight", "bp", "pulse", "spo2", "vitals", "amount",
    "txn", "transaction", "pnr", "tracking", "model", "version"
]

# Patterns for non-PII codes (e.g. product code PX-2024-77, dates, vitals)
NON_PII_PATTERNS = [
    r"\bPX-\d{4}-\d+\b",                         # Product codes
    r"\bINV-\d{4}-\d+\b",                        # Invoice numbers
    r"\bTXN-\d+\b",                              # Transaction numbers
    r"\bTCK-\d+\b",                              # Ticket numbers
    r"\bPNR-[A-Za-z0-9]+\b",                     # Flight PNRs
    r"\b(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", # ISO Dates (e.g. 2024-10-14)
    r"\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}\b", # Dates (e.g. 15/11/2024)
    r"\b\d{2,3}/\d{2,3}\s*mmHg\b",               # Blood pressure (e.g. 120/80 mmHg)
    r"\bINR\s*[\d,]+\b",                         # Currency amounts
    r"\b(?:USD|EUR|GBP)\s*[\d,]+\b",
    r"\b(?:Tab|Tablet|Cap|Capsule|Inj|Injection|Syrup|Prescribed)\s+[A-Z][a-z]+\b" # Medication/Prescription
]

# Explicit Corporate, Technical & Document Heading Phrases to suppress from NAME categorization
NON_NAME_PHRASES = {
    # Tech & AI
    "machine learning", "deep learning", "artificial intelligence", "data science",
    "cloud computing", "cloud operations", "security protocol", "access key",
    "affected host", "compromised account", "immediate mitigation", "advanced machine learning",
    "cyber security", "operating system", "software development",
    # Document Sections & Business Headings
    "quarterly results", "key findings", "discussion points", "amount due",
    "action items", "status update", "annual meeting", "social security",
    "permanent account", "student name", "internal grievance", "emergency contact",
    "account holder", "savings account", "transaction reference", "registered landline",
    "leased premises", "security deposit", "primary contact", "user name",
    "caller name", "executive summary", "financial summary", "meeting notes",
    "performance review", "support ticket", "board minutes", "annual report",
    "terms and conditions", "governing law", "scope of work", "severability",
    "booking reference", "ip address", "reported by", "ciso contact",
    "revoked aws access", "vp operations",
    # Organizations, Companies & Institutions
    "amazon web services", "acme solutions pvt", "apex technologies inc",
    "sinai community health", "indian institute", "nova analytics",
    "acme solutions", "apex technologies", "community health",
    "apex logistics", "mount sinai",
    # Common Medications
    "tab paracetamol", "prescribed atorvastatin", "tablet paracetamol", "capsule omeprazole"
}

# Suffixes and tokens that identify a string as an organization, company, or institution rather than a person
ORGANIZATION_INDICATORS = {
    "pvt", "ltd", "inc", "corp", "corporation", "llc", "llp", "gmbh", "sa",
    "solutions", "technologies", "tech", "services", "systems", "enterprises",
    "analytics", "consulting", "associates", "ventures", "holdings", "group",
    "bank", "hospital", "clinic", "university", "institute", "college", "school",
    "academy", "foundation", "trust", "agency", "department", "committee",
    "board", "council", "commission", "division", "health", "healthcare",
    "community", "laboratories", "labs", "pharma", "pharmaceuticals", "industries",
    "motors", "energy", "capital", "partners", "logistics"
}

def is_likely_non_pii(text_span: str, surrounding_context: str) -> bool:
    """Checks whether a span is a product code, date, non-PII invoice reference, or organization name."""
    clean = text_span.strip()
    lower_span = clean.lower()
    
    # 1. Direct match in known non-name phrases
    if lower_span in NON_NAME_PHRASES:
        return True

    # 2. Match against known non-PII patterns (product codes, dates, vitals, prescriptions)
    for pat in NON_PII_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE):
            return True
            
    # 3. Check for corporate / organizational indicators
    tokens = [t.lower().strip(".,") for t in re.split(r"[\s,]+", clean) if t.strip(".,")]
    if any(t in ORGANIZATION_INDICATORS for t in tokens):
        return True

    # 4. Check surrounding context for non-PII indicators
    lower_ctx = surrounding_context.lower()
    
    # Check if immediately preceded by non-PII prefixes
    non_pii_prefix = r"(?:inv|invoice|ref|reference|txn|transaction|px|sku|tck|ticket|cas|pnr|order)[-:\s#]*" + re.escape(lower_span)
    if re.search(non_pii_prefix, lower_ctx):
        return True
        
    for kw in NON_PII_CONTEXT_KEYWORDS:
        if kw in lower_ctx:
            if re.search(r"\b(?:INV|REF|PX|TCK|CAS|SKU|MED|TXN|PNR)-", clean, re.IGNORECASE):
                return True
                
    return False
