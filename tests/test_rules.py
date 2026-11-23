from src.detection.rules.regex_rules import detect_by_rules

def test_detect_rules():
    text = (
        "Patient Name: Eleanor Vance. "
        "Contact at john.doe@example.com or call +1-555-0199. "
        "His SSN is 123-45-6789 and address is 742 Evergreen Terrace, Springfield, OR 97477."
    )
    spans = detect_by_rules(text)
    
    categories = [s.category for s in spans]
    assert "NAME" in categories
    assert "EMAIL" in categories
    assert "PHONE" in categories
    assert "ID" in categories
    assert "ADDRESS" in categories
    
    email_span = next(s for s in spans if s.category == "EMAIL")
    assert email_span.text == "john.doe@example.com"
    assert email_span.confidence >= 0.85
