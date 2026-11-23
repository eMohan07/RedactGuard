from src.detection.schemas import DetectedSpan
from src.redaction.text_redactor import redact_text

def test_redact_text_token():
    text = "Hello Alice, your code is 9988."
    spans = [
        DetectedSpan(
            id="1",
            text="Alice",
            category="PERSON",
            start_char=6,
            end_char=11,
            source="rule",
            confidence=1.0,
            accepted=True
        )
    ]
    redacted = redact_text(text, spans, mask_style="TOKEN")
    assert redacted == "Hello [REDACTED: PERSON], your code is 9988."
    assert "Alice" not in redacted

def test_redact_text_rejected_span():
    text = "Hello Bob."
    spans = [
        DetectedSpan(
            id="1",
            text="Bob",
            category="PERSON",
            start_char=6,
            end_char=9,
            source="rule",
            confidence=1.0,
            accepted=False  # User rejected redaction
        )
    ]
    redacted = redact_text(text, spans)
    assert redacted == "Hello Bob."

def test_hmac_masking_security():
    import secrets
    text = "User Alice and Alice again."
    spans = [
        DetectedSpan(id="1", text="Alice", category="NAME", start_char=5, end_char=10, source="rule", confidence=1.0, accepted=True),
        DetectedSpan(id="2", text="Alice", category="NAME", start_char=15, end_char=20, source="rule", confidence=1.0, accepted=True)
    ]
    # Key 1
    key1 = secrets.token_bytes(32)
    res1 = redact_text(text, spans, mask_style="HASH", hmac_key=key1)
    assert "Alice" not in res1
    assert "HMAC" in res1

    # Key 2 (different session)
    key2 = secrets.token_bytes(32)
    res2 = redact_text(text, spans, mask_style="HASH", hmac_key=key2)
    assert res1 != res2, "Different session HMAC keys must yield different irreversible hashes"

def test_length_revealing_protection():
    text = "Short: Al. Long: Alexander."
    spans = [
        DetectedSpan(id="1", text="Al", category="NAME", start_char=7, end_char=9, source="rule", confidence=1.0, accepted=True),
        DetectedSpan(id="2", text="Alexander", category="NAME", start_char=17, end_char=26, source="rule", confidence=1.0, accepted=True)
    ]
    # Default preserve_length=False hides character count
    fixed_res = redact_text(text, spans, mask_style="ASTERISK", preserve_length=False)
    assert fixed_res == "Short: ****. Long: ****."

    # When explicit preserve_length=True is enabled
    leaked_res = redact_text(text, spans, mask_style="ASTERISK", preserve_length=True)
    assert leaked_res == "Short: **. Long: *********."
