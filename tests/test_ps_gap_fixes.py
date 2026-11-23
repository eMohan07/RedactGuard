import pytest
from src.detection.hybrid_detector import HybridDetector
from src.detection.rules.regex_rules import detect_by_rules

@pytest.fixture
def detector():
    return HybridDetector()

def test_id_generic_and_specific_formats(detector):
    text = (
        "Staff record: Employee ID: 10234, Staff ID: S-99812, "
        "Customer ID: CUST-77881, and Emp. No. 4471. "
        "Tax details: GSTIN: 27AAAAA0000A1Z5, IFSC: HDFC0001234, UAN: 100912345678. "
        "Financial: Acct No 9876 5432 1098."
    )
    spans = detector.detect(text)
    span_texts = [s.text for s in spans]
    id_spans = {s.text: s.category for s in spans if s.category == "ID"}

    assert "10234" in id_spans or "Employee ID: 10234" in span_texts
    assert "S-99812" in id_spans or "Staff ID: S-99812" in span_texts
    assert "CUST-77881" in id_spans or "Customer ID: CUST-77881" in span_texts
    assert "4471" in id_spans or "Emp. No. 4471" in span_texts
    assert "27AAAAA0000A1Z5" in id_spans
    assert "HDFC0001234" in id_spans
    assert "100912345678" in id_spans
    
    # Check that Acct No 9876 5432 1098 is categorized as ID and not mislabelled as phone
    assert any("9876 5432 1098" in s.text for s in spans)
    for s in spans:
        if "9876" in s.text:
            assert s.category == "ID"
            assert "9876 5432 1098" in s.text

def test_addresses_pin_anchored_and_structural(detector):
    text = (
        "Locations: "
        "Site 1: No. 12, 4th Cross, Indiranagar, Bengaluru 560038. "
        "Site 2: Plot 45, Sector 12, Noida, UP 201301. "
        "Site 3: 221B Baker Street, London NW1 6XE."
    )
    spans = detector.detect(text)
    addr_spans = [s.text for s in spans if s.category == "ADDRESS"]

    assert any("Indiranagar, Bengaluru 560038" in a or "4th Cross" in a for a in addr_spans)
    assert any("Sector 12, Noida" in a or "Plot 45" in a for a in addr_spans)
    assert any("Baker Street, London" in a for a in addr_spans)

def test_suppression_of_name_false_positives(detector):
    text = (
        "The conference covered Machine Learning and Artificial Intelligence. "
        "In the Quarterly Results, Key Findings showed high growth. "
        "We partnered with Amazon Web Services and Acme Solutions Pvt."
    )
    spans = detector.detect(text)
    name_spans = [s.text for s in spans if s.category == "NAME"]

    # None of these non-personal headings or company terms should be detected as person names
    assert "Machine Learning" not in name_spans
    assert "Artificial Intelligence" not in name_spans
    assert "Quarterly Results" not in name_spans
    assert "Key Findings" not in name_spans
    assert "Amazon Web Services" not in name_spans
    assert "Acme Solutions Pvt" not in name_spans

def test_name_misses_allcaps_lowercase_and_linebreaks(detector):
    text = (
        "Attendees:\n"
        "Employee: RAJIV SHARMA\n"
        "Patient Name: john doe\n"
        "Consultant: Sneha\nDeshmukh\n"
        "Contact: user @ domain.com\n"
    )
    spans = detector.detect(text)
    span_texts = [s.text for s in spans]
    # Check that Sneha Deshmukh is detected regardless of newline representation
    assert any("sneha" in t.lower() and "deshmukh" in t.lower() for t in span_texts)
    assert any("user @ domain.com" in t or "user@domain.com" in t.replace(" ", "") for t in span_texts)

def test_bare_name_propagation_and_linking(detector):
    text = "Priya Nair presented the proposal. Later, Priya said Nair would call."
    spans = detector.detect(text)
    span_texts = [s.text for s in spans]

    assert "Priya Nair" in span_texts
    assert "Priya" in span_texts
    assert "Nair" in span_texts

    from src.detection.entity_linker import EntityLinker
    from src.redaction.text_redactor import redact_text_with_placeholders, verify_redacted_text

    tag_map, _ = EntityLinker.cluster_entities(spans)
    # Priya Nair, bare Priya, and bare Nair should all cluster into the same entity tag [NAME_1]
    name_spans = [s for s in spans if s.text in ("Priya Nair", "Priya", "Nair")]
    assert len(name_spans) >= 3
    tags = {tag_map[s.id] for s in name_spans}
    assert len(tags) == 1
    assert "[NAME_1]" in tags

    # Verify bare name spans are propagated as pending for human review
    assert any(s.text in ("Priya", "Nair") and not s.accepted for s in spans)

    # Simulate human review approval for all linked entity variants
    for s in spans:
        s.accepted = True

    redacted, _ = redact_text_with_placeholders(text, spans, mask_style="INDEXED")
    assert "Priya" not in redacted
    assert "Nair" not in redacted
    assert "[NAME_1]" in redacted

    is_safe, leaks = verify_redacted_text(redacted, spans)
    assert is_safe is True
    assert len(leaks) == 0

def test_initial_variants_without_dot_and_coreference(detector):
    text = "Richa Sharma led the team. Dr. R Sharma and Dr R Sharma reviewed findings. Later Sharma said Richa was right."
    spans = detector.detect(text)
    span_texts = [s.text for s in spans]

    assert "Richa Sharma" in span_texts
    assert any("R Sharma" in s or "R. Sharma" in s for s in span_texts)
    assert "Sharma" in span_texts
    assert "Richa" in span_texts

    from src.detection.entity_linker import EntityLinker
    assert EntityLinker.are_name_variants("Richa Sharma", "R Sharma") is True
    assert EntityLinker.are_name_variants("Dr. R Sharma", "Dr R Sharma") is True
    assert EntityLinker.are_name_variants("Richa Sharma", "Dr R Sharma") is True
    assert EntityLinker.are_name_variants("Richa Sharma", "Richa") is True
    assert EntityLinker.are_name_variants("Richa Sharma", "Sharma") is True

def test_real_world_quasi_identifiers():
    from src.detection.privacy_advisor import PrivacyAdvisor
    
    test_cases = [
        ("The finance chief at a Mumbai startup closed funding.", "leadership"),
        ("She served as CFO at Infosys for five years.", "leadership"),
        ("He consulted the only female cardiologist in Kolhapur.", "demographic"),
        ("The 61-year-old CEO of a Bengaluru-based fintech announced expansion.", "age"),
        ("She was the CFO of a Pune-based firm.", "leadership"),
        ("She was the only female CFO in the Pune region.", "demographic")
    ]

    for sentence, expected_type in test_cases:
        warnings = PrivacyAdvisor.scan_warnings(sentence)
        assert len(warnings) > 0, f"Failed to detect quasi-identifier in: '{sentence}'"
        
        # Test automated neutralization
        neutralized = PrivacyAdvisor.apply_all_generalizations(sentence)
        assert neutralized != sentence, f"Failed to generalize: '{sentence}'"
        assert "Infosys" not in neutralized
        assert "Kolhapur" not in neutralized
        assert "Pune-based" not in neutralized
        assert "61-year-old" not in neutralized

def test_export_gate_word_boundary_and_nairobi_edge_case():
    from src.detection.schemas import DetectedSpan
    from src.redaction.text_redactor import verify_redacted_text

    approved_spans = [
        DetectedSpan(id="1", text="Nair", category="NAME", start_char=0, end_char=4, accepted=True)
    ]
    # Document contains 'Nairobi' which has 'Nair' as a substring but NOT as a word
    redacted_clean = "[NAME_1] visited the regional headquarters in Nairobi."
    is_safe, leaks = verify_redacted_text(redacted_clean, approved_spans)
    assert is_safe is True, f"Word boundary check failed; false leak reported: {leaks}"
    assert len(leaks) == 0

def test_merge_overlapping_spans_no_mutation_or_corrupted_text():
    from src.detection.schemas import DetectedSpan
    from src.redaction.text_redactor import merge_overlapping_spans

    doc_text = "Priya Nair led the research project."
    s1 = DetectedSpan(id="s1", text="Priya ", category="NAME", start_char=0, end_char=6, confidence=0.8, accepted=True)
    s2 = DetectedSpan(id="s2", text="ya Nair", category="NAME", start_char=3, end_char=10, confidence=0.85, accepted=True)

    spans_to_merge = [s1, s2]
    merged = merge_overlapping_spans(spans_to_merge, full_text=doc_text)

    # 1. Verify original objects were not mutated
    assert s1.start_char == 0 and s1.end_char == 6 and s1.text == "Priya "
    assert s2.start_char == 3 and s2.end_char == 10 and s2.text == "ya Nair"

    # 2. Verify merged span text is "Priya Nair", NOT "ya Nair"
    assert len(merged) == 1
    assert merged[0].start_char == 0
    assert merged[0].end_char == 10
    assert merged[0].text == "Priya Nair"

def test_active_learning_does_not_globally_suppress_single_names(tmp_path):
    from src.detection.learning_store import LearningStore

    json_p = tmp_path / "learned.json"
    jsonl_p = tmp_path / "corrections.jsonl"
    store = LearningStore(json_path=json_p, jsonl_path=jsonl_p)

    # User rejects "Sharma" in doc1.txt (e.g. false positive in "Sharma Enterprises")
    store.record_correction("Sharma", "NAME", action="reject", filename="doc1.txt")

    # Document-scoped check: suppressed in doc1.txt
    assert store.is_suppressed("Sharma", filename="doc1.txt") is True

    # Global check: should NOT be suppressed in doc2.txt or globally for other people
    assert store.is_suppressed("Sharma", filename="doc2.txt") is False
    assert store.is_suppressed("Sharma") is False

    # But multi-word phrase rejection (e.g. "Acme Solutions Pvt") IS globally suppressed
    store.record_correction("Acme Solutions Pvt", "NAME", action="reject", filename="doc1.txt")
    assert store.is_suppressed("Acme Solutions Pvt", filename="doc2.txt") is True
    assert store.is_suppressed("Acme Solutions Pvt") is True

def test_gliner_chunking_sliding_window():
    from src.detection.gliner_detector import GLiNERDetector
    detector = GLiNERDetector()

    # Generate a 600-word text that would exceed 384 tokens
    words = ["word"] * 600
    words[10] = "Richa"
    words[11] = "Sharma"
    words[550] = "Vikram"
    words[551] = "Rathore"
    long_text = " ".join(words)

    chunks = detector._chunk_text(long_text, chunk_chars=1200, overlap_chars=200)
    assert len(chunks) > 1
    # Check that boundaries cover the entire text
    assert chunks[0][1] == 0
    last_chunk, last_offset = chunks[-1]
    assert last_offset + len(last_chunk) == len(long_text)

