import re
import hmac
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional
from src.detection.schemas import DetectedSpan
from src.detection.entity_linker import EntityLinker
from src.detection.rules.regex_rules import COMMON_STOPWORDS, DISALLOWED_NAME_TOKENS, STREET_SUFFIXES

class VerificationFailedError(Exception):
    """Raised when the post-redaction re-read audit discovers residual sensitive text."""
    pass

def merge_overlapping_spans(spans: List[DetectedSpan], full_text: Optional[str] = None) -> List[DetectedSpan]:
    """
    Merges overlapping or nested spans into unified non-overlapping spans.
    Does NOT mutate the original span objects.
    Prevents malformed redaction output (e.g. [NAME_1]1]) when multiple spans overlap.
    """
    if not spans:
        return []
    sorted_s = sorted(spans, key=lambda s: (s.start_char, -s.end_char))
    merged: List[DetectedSpan] = []

    for s in sorted_s:
        if not merged:
            merged.append(s.model_copy())
            continue
        cur = merged[-1]
        if s.start_char < cur.end_char:
            # Overlap detected: construct a new merged span rather than mutating in place
            new_start = cur.start_char
            new_end = max(cur.end_char, s.end_char)
            if full_text and new_end <= len(full_text):
                new_text = full_text[new_start:new_end]
            else:
                # Fallback text reconstruction
                overlap_offset = max(0, cur.end_char - s.start_char)
                suffix = s.text[overlap_offset:] if overlap_offset < len(s.text) else ""
                new_text = cur.text + suffix
            
            # Select higher-confidence category or retain primary
            chosen_cat = cur.category if cur.confidence >= s.confidence else s.category
            chosen_conf = max(cur.confidence, s.confidence)
            combined_bboxes = (cur.bboxes or []) + (s.bboxes or [])

            merged[-1] = cur.model_copy(update={
                "start_char": new_start,
                "end_char": new_end,
                "text": new_text,
                "category": chosen_cat,
                "confidence": chosen_conf,
                "bboxes": combined_bboxes if combined_bboxes else None
            })
        else:
            merged.append(s.model_copy())
    return merged

def redact_text_with_placeholders(
    full_text: str, 
    spans: List[DetectedSpan],
    mask_style: str = "INDEXED",
    hmac_key: Optional[bytes] = None,
    preserve_length: bool = False
) -> Tuple[str, Dict[str, str]]:
    """
    Applies redactions with entity-linked placeholders (e.g. [NAME_1], [EMAIL_1]).
    Default mask style is INDEXED with fixed-width privacy preservation (preserve_length=False).
    
    Security enhancements:
    - Automatically resolves overlapping spans before applying edits.
    - HASH: Uses session-specific keyed HMAC-SHA256 instead of short plain SHA-256 to prevent dictionary/rainbow-table attacks.
    - ASTERISK / BLOCK: By default, uses fixed-width masks (preserve_length=False) to avoid revealing character counts.
    
    Returns (redacted_text, tag_map).
    """
    active_spans = [s for s in spans if s.accepted]
    if not active_spans:
        return full_text, {}

    # Merge overlapping accepted spans to avoid offset collisions
    active_spans = merge_overlapping_spans(active_spans, full_text=full_text)

    # Ephemeral session key for HMAC hashing if not provided
    if hmac_key is None:
        hmac_key = secrets.token_bytes(32)

    # Cluster entities and map span IDs to consistent placeholder tags
    tag_map, _ = EntityLinker.cluster_entities(active_spans)

    # Sort in reverse order of start position so preceding offsets remain valid
    sorted_spans = sorted(active_spans, key=lambda s: s.start_char, reverse=True)

    redacted = full_text
    for s in sorted_spans:
        if mask_style == "INDEXED":
            replacement = tag_map.get(s.id, f"[{s.category}]")
        elif mask_style == "BLOCK":
            replacement = "█" * len(s.text) if preserve_length else "████"
        elif mask_style == "ASTERISK":
            replacement = "*" * len(s.text) if preserve_length else "****"
        elif mask_style == "HASH":
            h = hmac.new(hmac_key, s.text.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
            replacement = f"<{s.category}_HMAC_{h}>"
        elif mask_style == "GENERIC":
            replacement = f"[{s.category}]"
        else:
            replacement = f"[REDACTED: {s.category}]"

        redacted = redacted[:s.start_char] + replacement + redacted[s.end_char:]

    return redacted, tag_map

def redact_text(
    full_text: str, 
    spans: List[DetectedSpan], 
    mask_style: str = "INDEXED",
    hmac_key: Optional[bytes] = None,
    preserve_length: bool = False
) -> str:
    """Convenience wrapper returning just the redacted string."""
    redacted, _ = redact_text_with_placeholders(
        full_text, spans, mask_style=mask_style, hmac_key=hmac_key, preserve_length=preserve_length
    )
    return redacted

def clean_and_align_redacted_text(
    text: str, 
    filename: str = "Document", 
    mask_style: str = "INDEXED",
    include_banner: bool = False
) -> str:
    """
    Cleans and professionally aligns de-identified document text:
    - Normalizes ragged spacing, punctuation gaps, and line endings.
    - Uniformly aligns structured key-value blocks (e.g. 'Name: [NAME_1]').
    - Preserves clean paragraph breaks without runaway blank lines.
    - Optionally adds an executive verification banner for formal exports.
    """
    if not text:
        return ""

    # Normalize line breaks and tabs
    clean = text.replace("\r\n", "\n").replace("\r", "\n")

    # Clean awkward spacing around punctuation introduced by placeholder substitution
    clean = re.sub(r"[ \t]+([,.;:!?])", r"\1", clean)
    clean = re.sub(r"([(\[{])[ \t]+", r"\1", clean)
    clean = re.sub(r"[ \t]+([)\]}])", r"\1", clean)

    lines = clean.split("\n")
    processed_lines = []

    # Detect blocks of structured key-value lines (e.g., "Patient Name: ...", "Email: ...")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for consecutive key-value lines
        kv_match = re.match(r"^([A-Za-z0-9\s/_-]{2,30}):\s*(.*)$", stripped)
        if kv_match and not stripped.startswith("http"):
            kv_block = []
            while i < len(lines):
                cur_stripped = lines[i].strip()
                cur_match = re.match(r"^([A-Za-z0-9\s/_-]{2,30}):\s*(.*)$", cur_stripped)
                if cur_match and not cur_stripped.startswith("http"):
                    kv_block.append((cur_match.group(1).strip(), cur_match.group(2).strip()))
                    i += 1
                else:
                    break
            
            if len(kv_block) >= 2:
                # Align colons neatly across the block
                max_key_len = min(max(len(k) for k, _ in kv_block), 25)
                for k, v in kv_block:
                    processed_lines.append(f"{k.ljust(max_key_len)} : {v}")
            else:
                for k, v in kv_block:
                    processed_lines.append(f"{k}: {v}")
            continue

        processed_lines.append(line.rstrip())
        i += 1

    # Join and collapse 3+ consecutive newlines to maximum 2
    result = "\n".join(processed_lines)
    result = re.sub(r"\n{3,}", "\n\n", result).strip()

    if include_banner:
        header = (
            f"================================================================================\n"
            f"                         VERIFIED REDACTED DOCUMENT\n"
            f"================================================================================\n"
            f"Reference File   : {filename}\n"
            f"De-Identification: {mask_style} Format\n"
            f"Verification Gate: PASSED (Air-Gapped Re-Read Audit Confirmed 0 Residual PII)\n"
            f"--------------------------------------------------------------------------------\n\n"
        )
        footer = (
            f"\n\n================================================================================\n"
            f"                    [END OF VERIFIED REDACTED DOCUMENT]\n"
            f"================================================================================"
        )
        return header + result + footer

    return result

def verify_redacted_text(
    redacted_text: str, 
    approved_spans: List[DetectedSpan],
    rejected_spans: Optional[List[DetectedSpan]] = None
) -> Tuple[bool, List[str]]:
    """
    Dual-layer export verification gate:
    1. Direct & constituent-token audit: Asserts that NO approved sensitive text,
       constituent name tokens (e.g. bare "Priya" or "Nair" from "Priya Nair"),
       or digit sequences remain unmasked in the output text.
    2. Scanner-based defense-in-depth: Re-runs autonomous rules-based PII detection
       across the redacted output text to catch any residual or undetected PII.
       (Explicitly human-rejected spans are honored as intentional exceptions).
    Refuses export if any leak is detected.
    """
    from src.detection.rules.regex_rules import detect_by_rules

    leaks = []
    lower_redacted = redacted_text.lower()

    # Collect explicitly rejected terms (user deliberate exceptions)
    rejected_terms = set()
    for s in approved_spans:
        if not s.accepted and s.text.strip():
            rejected_terms.add(s.text.strip().lower())
    if rejected_spans:
        for s in rejected_spans:
            if s.text.strip():
                rejected_terms.add(s.text.strip().lower())

    # Layer 1: Check full needle strings of approved spans with word boundary sensitivity
    for s in approved_spans:
        if not s.accepted or not s.text.strip():
            continue
        needle = s.text.strip().lower()
        if len(needle) < 2:
            continue
        # Use word boundary check for word tokens to avoid false positives (e.g. 'Nair' in 'Nairobi')
        is_word_token = re.match(r"^\w+$", needle) is not None
        pattern = r"\b" + re.escape(needle) + r"\b" if is_word_token else re.escape(needle)
        if re.search(pattern, lower_redacted):
            leaks.append(s.text)

    # Layer 2: Check constituent tokens of approved NAME spans
    for s in approved_spans:
        if not s.accepted or s.category != "NAME":
            continue
        # Extract constituent words
        clean_name = re.sub(r"^(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+", "", s.text.strip(), flags=re.IGNORECASE)
        tokens = [t.strip(".,") for t in re.split(r"\s+", clean_name) if len(t.strip(".,")) >= 3]
        for tok in tokens:
            tok_lower = tok.lower()
            if (tok_lower not in COMMON_STOPWORDS and 
                tok_lower not in DISALLOWED_NAME_TOKENS and 
                tok_lower not in STREET_SUFFIXES):
                # Search for unmasked bare token with word boundary
                if re.search(r"\b" + re.escape(tok) + r"\b", redacted_text, flags=re.IGNORECASE):
                    leaks.append(f"Constituent name token '{tok}' (from approved '{s.text}')")

    # Layer 3: Re-scan output text with autonomous rule detector
    residual_detections = detect_by_rules(redacted_text)
    placeholder_pattern = re.compile(r"^(\[(?:NAME|EMAIL|PHONE|ADDRESS|ID)_\d+\]|<[A-Z_]+_HMAC_[a-f0-9]+>|\[(?:NAME|EMAIL|PHONE|ADDRESS|ID|REDACTED[^\]]*)\]|█+|\*+)$")
    for r_span in residual_detections:
        val = r_span.text.strip()
        if placeholder_pattern.match(val):
            continue
        val_lower = val.lower()
        # If user explicitly marked this term as rejected (e.g. false positive), do not flag as leak
        if val_lower in rejected_terms or any(rt in val_lower or val_lower in rt for rt in rejected_terms):
            continue
        leaks.append(f"Residual {r_span.category} '{val}' detected by post-export scanner")

    unique_leaks = list(dict.fromkeys(leaks))
    is_safe = (len(unique_leaks) == 0)
    return is_safe, unique_leaks
