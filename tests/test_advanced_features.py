from src.detection.entity_linker import EntityLinker
from src.detection.learning_store import LearningStore
from src.detection.privacy_advisor import PrivacyAdvisor
from src.detection.schemas import DetectedSpan
from src.redaction.text_redactor import redact_text_with_placeholders, verify_redacted_text

def test_entity_linking_name_variants():
    # "R. Sharma" and "Richa Sharma" should be recognized as variants of the same person
    assert EntityLinker.are_name_variants("Richa Sharma", "R. Sharma") is True
    assert EntityLinker.are_name_variants("Dr. Arvind Patel", "A. Patel") is True
    assert EntityLinker.are_name_variants("Richa Sharma", "Rajiv Sharma") is False

    spans = [
        DetectedSpan(id="s1", text="Richa Sharma", category="NAME", start_char=0, end_char=12),
        DetectedSpan(id="s2", text="R. Sharma", category="NAME", start_char=20, end_char=29),
        DetectedSpan(id="s3", text="Rajiv Sharma", category="NAME", start_char=40, end_char=52),
        DetectedSpan(id="s4", text="richa@example.com", category="EMAIL", start_char=60, end_char=77),
    ]

    tag_map, _ = EntityLinker.cluster_entities(spans)
    # Linked variants must share the exact same tag [NAME_1]
    assert tag_map["s1"] == "[NAME_1]"
    assert tag_map["s2"] == "[NAME_1]"
    # Different person must get [NAME_2]
    assert tag_map["s3"] == "[NAME_2]"
    # Email must get [EMAIL_1]
    assert tag_map["s4"] == "[EMAIL_1]"

def test_privacy_advisor_quasi_identifiers():
    text = "The candidate is the CFO of a Pune-based firm with 500 employees."
    warnings = PrivacyAdvisor.scan_warnings(text)
    
    assert len(warnings) > 0
    w = warnings[0]
    assert "CFO" in w.original_text
    assert "enterprise" in w.suggested_generalization

    # Test applying generalization
    generalized = PrivacyAdvisor.apply_generalization(text, w)
    assert "CFO of a Pune-based firm" not in generalized
    assert w.suggested_generalization in generalized

def test_export_verification_gate():
    text = "Patient Eleanor Vance visited the hospital."
    approved_spans = [
        DetectedSpan(id="1", text="Eleanor Vance", category="NAME", start_char=8, end_char=21, accepted=True)
    ]

    # Correct redaction
    redacted_clean, _ = redact_text_with_placeholders(text, approved_spans, mask_style="INDEXED")
    is_safe, leaks = verify_redacted_text(redacted_clean, approved_spans)
    assert is_safe is True
    assert len(leaks) == 0
    assert "[NAME_1]" in redacted_clean

    # Compromised text (simulating a leak)
    leaked_text = "Patient Eleanor Vance [NAME_1] visited the hospital."
    is_safe_leaked, leaks_detected = verify_redacted_text(leaked_text, approved_spans)
    assert is_safe_leaked is False
    assert "Eleanor Vance" in leaks_detected

def test_learning_store(tmp_path):
    store_file = tmp_path / "learned.json"
    store = LearningStore(filepath=store_file)

    # Record approval
    store.record_correction("Project Pegasus", "ID", accepted=True)
    assert store.remembered.get("Project Pegasus") == "ID"

    # Record rejection (suppression)
    store.record_correction("General Hospital", "ADDRESS", accepted=False)
    assert store.is_suppressed("General Hospital") is True

    # Check persistence
    store_reloaded = LearningStore(filepath=store_file)
    assert store_reloaded.remembered.get("Project Pegasus") == "ID"
    assert store_reloaded.is_suppressed("General Hospital") is True
