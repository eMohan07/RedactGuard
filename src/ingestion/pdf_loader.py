from pathlib import Path
from typing import List
from src.detection.schemas import DocumentContent, WordBox

class ScannedPDFError(Exception):
    """Raised when a PDF contains scanned images or non-extractable text rather than native digital text."""
    pass

class EmptyDocumentError(Exception):
    """Raised when an uploaded document has no readable content."""
    pass

def load_pdf_file(file_path: Path | str, min_chars_per_page: float = 10.0) -> DocumentContent:
    """
    Extracts text page-by-page from a PDF using PyMuPDF page.get_text("words"),
    keeping each word's bounding box and maintaining an exact map from character
    offsets to page and bounding box coordinates for unrecoverable redaction.
    Rejects scanned PDFs with a clear message.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise ImportError("PyMuPDF is required to process PDF files. Run: pip install pymupdf")

    doc = fitz.open(path)
    total_pages = len(doc)
    if total_pages == 0:
        raise EmptyDocumentError("The uploaded PDF has 0 pages.")

    pages_text: List[str] = []
    word_boxes: List[WordBox] = []
    full_text_parts: List[str] = []
    current_char_offset = 0

    total_words_count = 0
    pages_with_images = 0

    for page_idx in range(total_pages):
        page = doc[page_idx]
        page_num = page_idx + 1

        # Check for images
        if len(page.get_images()) > 0:
            pages_with_images += 1

        # Extract words: (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        raw_words = page.get_text("words")
        total_words_count += len(raw_words)

        page_words_text = []
        for w in raw_words:
            x0, y0, x1, y1, word_str = w[0], w[1], w[2], w[3], str(w[4])
            if not word_str.strip():
                continue

            w_start = current_char_offset + len(" ".join(page_words_text) + (" " if page_words_text else ""))
            w_end = w_start + len(word_str)

            word_boxes.append(WordBox(
                text=word_str,
                start_char=w_start,
                end_char=w_end,
                page_num=page_num,
                bbox=[float(x0), float(y0), float(x1), float(y1)]
            ))
            page_words_text.append(word_str)

        page_text = " ".join(page_words_text)
        pages_text.append(page_text)
        full_text_parts.append(page_text)
        current_char_offset += len(page_text) + 2  # account for page separator '\n\n'

    full_text = "\n\n".join(full_text_parts).strip()
    total_chars = len(full_text)

    # Scanned PDF rejection: check if extractable digital text is missing or negligible
    if total_words_count == 0 or total_chars == 0:
        raise ScannedPDFError(
            "Scanned PDF detected. This document consists of raster images without an extractable text layer. "
            "Please upload a native text-based PDF or a TXT file, or perform OCR first."
        )

    if (total_chars / total_pages) < min_chars_per_page and pages_with_images > 0:
        raise ScannedPDFError(
            "Scanned PDF detected. The document contains images with insufficient extractable text layers. "
            "Please upload a text-based document."
        )

    return DocumentContent(
        filename=path.name,
        file_type="pdf",
        full_text=full_text,
        pages=pages_text,
        word_boxes=word_boxes
    )
