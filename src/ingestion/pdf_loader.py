import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="fitz")
from pathlib import Path
from typing import List
from src.detection.schemas import DocumentContent, WordBox, DetectedSpan

class ScannedPDFError(Exception):
    """Raised when a PDF contains scanned images or non-extractable text rather than native digital text."""
    pass

class EmptyDocumentError(Exception):
    """Raised when an uploaded document has no readable content."""
    pass

def map_spans_to_word_boxes(spans: List[DetectedSpan], word_boxes: List[WordBox]) -> None:
    """
    Maps detected character-offset spans to exact PDF page numbers and bounding boxes.
    Enables true spatial bounding-box redaction across multiple pages.
    """
    if not word_boxes:
        return

    for span in spans:
        matching = [
            wb for wb in word_boxes 
            if wb.start_char < span.end_char and wb.end_char > span.start_char
        ]
        if matching:
            span.page_num = matching[0].page_num
            span.bboxes = [wb.bbox for wb in matching]
            x0 = min(b[0] for b in span.bboxes)
            y0 = min(b[1] for b in span.bboxes)
            x1 = max(b[2] for b in span.bboxes)
            y1 = max(b[3] for b in span.bboxes)
            span.bbox = [x0, y0, x1, y1]

def load_pdf_file(file_path: Path | str, min_chars_per_page: float = 10.0) -> DocumentContent:
    """
    Extracts text page-by-page from a PDF using PyMuPDF, preserving line breaks
    between lines and paragraph breaks between blocks. Maintains an exact character-offset
    index to page numbers and spatial bounding boxes for unrecoverable redaction.
    Rejects scanned PDFs with a clear message.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
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

        page_str_parts = []
        last_block = None
        last_line = None

        for w in raw_words:
            x0, y0, x1, y1, word_str, block_no, line_no, word_no = w[:8]
            if not word_str.strip():
                continue

            if page_str_parts:
                if block_no != last_block:
                    sep = "\n\n"
                elif line_no != last_line:
                    sep = "\n"
                else:
                    sep = " "
                page_str_parts.append(sep)
                current_char_offset += len(sep)

            w_start = current_char_offset
            page_str_parts.append(word_str)
            current_char_offset += len(word_str)
            w_end = current_char_offset

            last_block = block_no
            last_line = line_no

            word_boxes.append(WordBox(
                text=word_str,
                start_char=w_start,
                end_char=w_end,
                page_num=page_num,
                bbox=[float(x0), float(y0), float(x1), float(y1)]
            ))

        page_text = "".join(page_str_parts)
        pages_text.append(page_text)
        full_text_parts.append(page_text)

        if page_idx < total_pages - 1:
            current_char_offset += 2  # account for page separator '\n\n'

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
