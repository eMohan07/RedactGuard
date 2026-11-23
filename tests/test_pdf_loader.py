import pytest
from pathlib import Path
from src.ingestion.pdf_loader import load_pdf_file, ScannedPDFError, EmptyDocumentError

def test_text_based_pdf(tmp_path):
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError:
            pytest.skip("PyMuPDF not installed in environment yet")

    pdf_path = tmp_path / "text_doc.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Confidential Report for John Doe. Email: john@example.com")
    doc.save(pdf_path)
    doc.close()

    content = load_pdf_file(pdf_path)
    assert "John Doe" in content.full_text
    assert content.file_type == "pdf"

def test_scanned_pdf_raises_error(tmp_path):
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError:
            pytest.skip("PyMuPDF not installed in environment yet")

    # Create a PDF with zero text (simulating an image-only / scanned PDF)
    pdf_path = tmp_path / "scanned_doc.pdf"
    doc = fitz.open()
    doc.new_page()  # Blank page without any text layer
    doc.save(pdf_path)
    doc.close()

    with pytest.raises(ScannedPDFError):
        load_pdf_file(pdf_path)
