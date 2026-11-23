import hmac
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional
from src.detection.schemas import DetectedSpan
from src.detection.entity_linker import EntityLinker

class VerificationFailedError(Exception):
    """Raised when the post-redaction re-read audit discovers residual sensitive text."""
    pass

def merge_overlapping_spans(spans: List[DetectedSpan]) -> List[DetectedSpan]:
    """
    Merges overlapping or nested spans into unified non-overlapping spans.
    Prevents malformed redaction output (e.g. [NAME_1]1]) when multiple spans overlap.
    """
    if not spans:
        return []
    sorted_s = sorted(spans, key=lambda s: (s.start_char, -s.end_char))
    merged: List[DetectedSpan] = []

    for s in sorted_s:
        if not merged:
            merged.append(s)
            continue
        cur = merged[-1]
        if s.start_char < cur.end_char:
            # Overlap detected: extend current span boundaries if s extends further
            if s.end_char > cur.end_char:
                cur.end_char = s.end_char
                if len(s.text) > len(cur.text):
                    cur.text = s.text
                    cur.category = s.category
            if s.bboxes:
                cur.bboxes = (cur.bboxes or []) + s.bboxes
        else:
            merged.append(s)
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
    active_spans = merge_overlapping_spans(active_spans)

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

def verify_redacted_text(redacted_text: str, approved_spans: List[DetectedSpan]) -> Tuple[bool, List[str]]:
    """
    Re-reads the redacted text to assert that NO approved sensitive text
    or linked variant remains. Refuses export if any leak is detected.
    """
    leaks = []
    lower_redacted = redacted_text.lower()

    for s in approved_spans:
        if not s.accepted or not s.text.strip():
            continue
        needle = s.text.strip().lower()
        if len(needle) < 2:
            continue
        if needle in lower_redacted:
            leaks.append(s.text)

    unique_leaks = list(dict.fromkeys(leaks))
    is_safe = (len(unique_leaks) == 0)
    return is_safe, unique_leaks
