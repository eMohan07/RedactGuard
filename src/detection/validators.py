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

def validate_phone_digits(phone_str: str) -> bool:
    """
    Validates phone number:
    - Must have between 7 and 13 digits.
    - Rejects dates (ISO, UK/India formats) and trivial repetitions like '0000000000'.
    - Rejects strings starting with years like '2024-' which are invoice/reference years.
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
    "txn", "transaction", "pnr"
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
    r"\b(?:USD|EUR|GBP)\s*[\d,]+\b"
]

def is_likely_non_pii(text_span: str, surrounding_context: str) -> bool:
    """Checks whether a span is a product code, date, or non-PII invoice/transaction reference."""
    clean = text_span.strip()
    
    # 1. Match against known non-PII patterns
    for pat in NON_PII_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE):
            return True
            
    # 2. Check surrounding context for non-PII indicators
    lower_ctx = surrounding_context.lower()
    lower_span = clean.lower()
    
    # Check if immediately preceded by non-PII prefixes
    non_pii_prefix = r"(?:inv|invoice|ref|reference|txn|transaction|px|sku|tck|ticket|cas|pnr|order)[-:\s#]*" + re.escape(lower_span)
    if re.search(non_pii_prefix, lower_ctx):
        return True
        
    for kw in NON_PII_CONTEXT_KEYWORDS:
        if kw in lower_ctx:
            if re.search(r"\b(?:INV|REF|PX|TCK|CAS|SKU|MED|TXN|PNR)-", clean, re.IGNORECASE):
                return True
                
    return False
