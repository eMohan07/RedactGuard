from fastapi.testclient import TestClient
from src.server.app import app

client = TestClient(app)

def test_api_upload_and_review():
    sample_text = (
        "Primary Patient: Richa Sharma. Alternative: R. Sharma. "
        "Email: richa@example.com. Phone: +91 98230 12345. "
        "She is the CFO of a Pune-based firm."
    )
    
    files = {"file": ("test.txt", sample_text.encode("utf-8"), "text/plain")}
    response = client.post("/api/upload", files=files)
    assert response.status_code == 200
    
    data = response.json()
    assert "session_id" in data
    assert len(data["spans"]) > 0
    assert len(data["warnings"]) > 0  # CFO of a Pune-based firm warning detected
    
    session_id = data["session_id"]
    span_id = data["spans"][0]["id"]
    
    # Test update
    update_res = client.post("/api/spans/update", json={
        "session_id": session_id,
        "span_id": span_id,
        "accepted": False
    })
    assert update_res.status_code == 200
    
    # Test export verification
    export_res = client.get(f"/api/export/{session_id}?format=txt")
    assert export_res.status_code == 200
    assert len(export_res.text) > 0

    # Test manual addition
    add_res = client.post("/api/spans/add", json={
        "session_id": session_id,
        "text": "Pune",
        "category": "ADDRESS"
    })
    assert add_res.status_code == 200
    add_data = add_res.json()
    assert any(s["text"] == "Pune" and s["category"] == "ADDRESS" for s in add_data["spans"])

    # Cleanup learning store
    from src.server.app import learning_store
    learning_store.remembered.clear()
    learning_store.suppressed.clear()
    learning_store.save()

def test_api_scanned_pdf_error(tmp_path):
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError:
            return

    pdf_path = tmp_path / "blank.pdf"
    doc = fitz.open()
    doc.new_page()
    doc.save(pdf_path)
    doc.close()

    with open(pdf_path, "rb") as f:
        files = {"file": ("blank.pdf", f.read(), "application/pdf")}
        response = client.post("/api/upload", files=files)
        assert response.status_code == 422
        assert "Scanned PDF Not Supported" in response.json()["detail"]

def test_delete_learning_data_endpoint():
    # Insert temporary learned pattern
    from src.server.app import learning_store
    learning_store.record_correction("CustomSensitiveTerm", "NAME", action="approve")
    assert "CustomSensitiveTerm" in learning_store.remembered

    # Call DELETE /api/learning
    res = client.delete("/api/learning")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert len(learning_store.remembered) == 0
    assert len(learning_store.suppressed) == 0

def test_batch_update_spans():
    sample_text = "Name: Alice Smith. Email: alice@example.com."
    files = {"file": ("batch_test.txt", sample_text.encode("utf-8"), "text/plain")}
    upload_res = client.post("/api/upload", files=files)
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # Deselect all
    batch_res = client.post("/api/spans/batch_update", json={"session_id": session_id, "accepted": False})
    assert batch_res.status_code == 200
    assert all(not s["accepted"] for s in batch_res.json()["spans"])

    # Select all
    batch_res2 = client.post("/api/spans/batch_update", json={"session_id": session_id, "accepted": True})
    assert batch_res2.status_code == 200
    assert all(s["accepted"] for s in batch_res2.json()["spans"])

def test_summary_with_mask_style():
    sample_text = "Patient Name: Robert Hernandez. Phone: 312-555-0199. Prescribed Atorvastatin."
    files = {"file": ("sum_test.txt", sample_text.encode("utf-8"), "text/plain")}
    upload_res = client.post("/api/upload", files=files)
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # Request summary in BLOCK format
    sum_block = client.post("/api/summarize", json={"session_id": session_id, "mask_style": "BLOCK"})
    assert sum_block.status_code == 200
    assert sum_block.json()["mask_style"] == "BLOCK"
    assert "Robert Hernandez" not in sum_block.json()["summary"]

    # Request summary in ASTERISK format
    sum_ast = client.post("/api/summarize", json={"session_id": session_id, "mask_style": "ASTERISK"})
    assert sum_ast.status_code == 200
    assert sum_ast.json()["mask_style"] == "ASTERISK"
    assert "Robert Hernandez" not in sum_ast.json()["summary"]

def test_export_mask_styles():
    sample_text = "Contact person: Richa Sharma. Alternate: Richa Sharma."
    files = {"file": ("mask_export_test.txt", sample_text.encode("utf-8"), "text/plain")}
    upload_res = client.post("/api/upload", files=files)
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # 1. Export as ASTERISK
    res_ast = client.get(f"/api/export/{session_id}?format=txt&mask_style=ASTERISK")
    assert res_ast.status_code == 200
    assert "************" in res_ast.text or "****" in res_ast.text
    assert "Richa Sharma" not in res_ast.text

    # 2. Export as BLOCK
    res_block = client.get(f"/api/export/{session_id}?format=txt&mask_style=BLOCK")
    assert res_block.status_code == 200
    assert "████" in res_block.text
    assert "Richa Sharma" not in res_block.text

    # 3. Export as GENERIC
    res_generic = client.get(f"/api/export/{session_id}?format=txt&mask_style=GENERIC")
    assert res_generic.status_code == 200
    assert "[NAME]" in res_generic.text or "[REDACTED: NAME]" in res_generic.text
    assert "Richa Sharma" not in res_generic.text

    # 4. Export as INDEXED
    res_indexed = client.get(f"/api/export/{session_id}?format=txt&mask_style=INDEXED")
    assert res_indexed.status_code == 200
    assert "[NAME_1]" in res_indexed.text
    assert "Richa Sharma" not in res_indexed.text

def test_manual_add_matches_all_similar_in_doc():
    sample_text = "Lead officer: Vikram Malhotra. Later, Vikram Malhotra approved the release. Also V. Malhotra attended."
    files = {"file": ("manual_sim_test.txt", sample_text.encode("utf-8"), "text/plain")}
    upload_res = client.post("/api/upload", files=files)
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # Manual add of "Vikram Malhotra"
    add_res = client.post("/api/spans/add", json={
        "session_id": session_id,
        "text": "Vikram Malhotra",
        "category": "NAME"
    })
    assert add_res.status_code == 200
    spans = add_res.json()["spans"]

    # All occurrences in document should be matched and accepted
    matching_spans = [s for s in spans if "Malhotra" in s["text"] and s["accepted"]]
    assert len(matching_spans) >= 2, "Manual addition must automatically select all occurrences and related name variants across the document"

def test_reject_span_and_rejected_by_user_flag():
    sample_text = "Doctor: Anita Roy. Email: anita@hospital.org. Phone: 9876543210."
    files = {"file": ("reject_test.txt", sample_text.encode("utf-8"), "text/plain")}
    upload_res = client.post("/api/upload", files=files)
    assert upload_res.status_code == 200
    data = upload_res.json()
    session_id = data["session_id"]
    spans = data["spans"]
    assert len(spans) > 0

    target_span = spans[0]
    span_id = target_span["id"]

    # Reject the target span
    rej_res = client.post("/api/spans/update", json={
        "session_id": session_id,
        "span_id": span_id,
        "accepted": False,
        "rejected_by_user": True
    })
    assert rej_res.status_code == 200
    updated_spans = rej_res.json()["spans"]
    rejected = next(s for s in updated_spans if s["id"] == span_id)
    assert rejected["accepted"] is False
    assert rejected["rejected_by_user"] is True

    # Re-approve the target span
    app_res = client.post("/api/spans/update", json={
        "session_id": session_id,
        "span_id": span_id,
        "accepted": True,
        "rejected_by_user": False
    })
    assert app_res.status_code == 200
    reapproved = next(s for s in app_res.json()["spans"] if s["id"] == span_id)
    assert reapproved["accepted"] is True
    assert reapproved["rejected_by_user"] is False

