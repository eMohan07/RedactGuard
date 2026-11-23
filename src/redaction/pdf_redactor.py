import re
import zlib
import unicodedata
from pathlib import Path
from typing import List, Tuple, Set
from src.detection.schemas import DetectedSpan
from src.detection.entity_linker import EntityLinker
from src.detection.rules.regex_rules import COMMON_STOPWORDS, DISALLOWED_NAME_TOKENS, STREET_SUFFIXES, detect_by_rules
from src.redaction.text_redactor import VerificationFailedError

def normalize_text_for_audit(s: str) -> str:
    """
    Normalizes string by removing diacritics, spaces, and punctuation
    to ensure hidden, split, or formatted PII cannot evade detection.
    """
    if not s:
        return ""
    nfkd = unicodedata.normalize('NFKD', s)
    stripped = "".join(c for c in nfkd if not unicodedata.combining(c))
    return "".join(c for c in stripped.lower() if c.isalnum())

def secondary_pdf_stream_extractor(pdf_bytes: bytes) -> str:
    """
    Independent pure-Python secondary PDF text extractor:
    Decompresses raw FlateDecode content streams and extracts string literals
    without relying on PyMuPDF's text rendering engine.
    """
    extracted_fragments = []
    
    # Extract string literals from decompressed streams
    stream_pattern = re.compile(rb'stream[\r\n]+(.*?)[\r\n]+endstream', re.DOTALL)
    for match in stream_pattern.finditer(pdf_bytes):
        stream_data = match.group(1)
        # Try zlib decompression
        decompressed = None
        for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16]:
            try:
                decompressed = zlib.decompress(stream_data, wbits)
                break
            except Exception:
                continue
        
        target_bytes = decompressed if decompressed is not None else stream_data
        
        # Extract text within parentheses (text strings in PDF operators: Tj, TJ, ')
        text_literals = re.findall(rb'\((.*?)\)', target_bytes)
        for lit in text_literals:
            try:
                extracted_fragments.append(lit.decode('latin-1', errors='ignore'))
            except Exception:
                pass

        # Also extract hex strings <...>
        hex_literals = re.findall(rb'<([0-9a-fA-F\s]{4,})>', target_bytes)
        for h in hex_literals:
            clean_hex = re.sub(rb'\s+', b'', h)
            if len(clean_hex) % 2 == 0:
                try:
                    extracted_fragments.append(bytes.fromhex(clean_hex.decode('ascii')).decode('latin-1', errors='ignore'))
                except Exception:
                    pass

    # Also scan raw binary outside streams for ASCII/UTF-8 plaintext strings
    raw_ascii = re.findall(rb'[A-Za-z0-9@._+\-]{4,}', pdf_bytes)
    for token in raw_ascii:
        extracted_fragments.append(token.decode('ascii', errors='ignore'))

    return " ".join(extracted_fragments)

def redact_pdf(
    input_pdf_path: Path | str,
    output_pdf_path: Path | str,
    spans: List[DetectedSpan],
    mask_style: str = "INDEXED",
    preserve_length: bool = False,
    hmac_key: bytes | None = None
) -> Tuple[Path, bool, List[str]]:
    """
    Applies true, unrecoverable PDF redaction and multi-engine verification:
    1. Uses add_redact_annot() and apply_redactions() to permanently strip underlying text & glyphs.
    2. Strips all metadata, XML metadata streams, attachments, and annotations.
    3. Purges object streams and compacts with garbage=4.
    4. Dual verification gate:
       - Layer 1: PyMuPDF re-read of rendered pages.
       - Layer 2: Independent secondary stream decompressor & raw byte scanner.
       - Text normalization (NFKD + alphanumeric) to catch split/masked/kerned tokens.
    5. Refuses export and purges output file if any sensitive string is recoverable.
    """
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz  # PyMuPDF
        except ImportError:
            raise ImportError("PyMuPDF is required for PDF redaction. Run: pip install pymupdf")

    import secrets
    import hmac
    import hashlib

    if hmac_key is None:
        hmac_key = secrets.token_bytes(32)

    in_path = Path(input_pdf_path)
    out_path = Path(output_pdf_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    active_spans = [s for s in spans if s.accepted]
    tag_map, _ = EntityLinker.cluster_entities(active_spans)

    doc = fitz.open(in_path)

    for page_idx in range(len(doc)):
        page = doc[page_idx]
        page_num = page_idx + 1
        page_spans = [s for s in active_spans if s.page_num == page_num or s.page_num is None]

        for span in page_spans:
            if mask_style == "INDEXED":
                replacement_tag = tag_map.get(span.id, f"[{span.category}]")
            elif mask_style == "BLOCK":
                replacement_tag = "█" * len(span.text) if preserve_length else "████"
            elif mask_style == "ASTERISK":
                replacement_tag = "*" * len(span.text) if preserve_length else "****"
            elif mask_style == "HASH":
                h = hmac.new(hmac_key, span.text.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
                replacement_tag = f"<{span.category}_HMAC_{h}>"
            else:
                replacement_tag = f"[REDACTED: {span.category}]"

            def _get_optimal_fontsize(r, text_to_fit: str) -> float:
                if not text_to_fit:
                    return 8.0
                w = max(float(r.width) - 2.0, 6.0)
                h = max(float(r.height) - 1.0, 6.0)
                # Average character width is ~0.52em in Helvetica
                max_w_fs = w / (max(len(text_to_fit), 1) * 0.52)
                max_h_fs = h * 0.75
                return max(min(min(max_w_fs, max_h_fs), 9.5), 4.5)

            if span.bboxes:
                for idx, b in enumerate(span.bboxes):
                    rect = fitz.Rect(b[0], b[1], b[2], b[3])
                    tag_text = replacement_tag if idx == 0 else ""
                    fs = _get_optimal_fontsize(rect, tag_text)
                    page.add_redact_annot(
                        rect,
                        text=tag_text,
                        fill=(0, 0, 0),
                        text_color=(1, 1, 1),
                        fontsize=fs,
                        align=fitz.TEXT_ALIGN_CENTER
                    )
            else:
                quads = page.search_for(span.text)
                for rect in quads:
                    fs = _get_optimal_fontsize(rect, replacement_tag)
                    page.add_redact_annot(
                        rect,
                        text=replacement_tag,
                        fill=(0, 0, 0),
                        text_color=(1, 1, 1),
                        fontsize=fs,
                        align=fitz.TEXT_ALIGN_CENTER
                    )

        # Permanently excise glyphs and pixel streams
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS)

    # Clear document metadata and XML stream
    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass

    # Purge embedded files / attachments
    try:
        if hasattr(doc, "embfile_count") and doc.embfile_count() > 0:
            for name in list(doc.embfile_names()):
                doc.embfile_del(name)
    except Exception:
        pass

    # Clear all annotations and interactive links
    for page in doc:
        for annot in list(page.annots()):
            page.delete_annot(annot)
        for link in list(page.get_links()):
            page.delete_link(link)

    # Save purged PDF with maximal garbage collection
    doc.save(
        out_path,
        garbage=4,
        deflate=True,
        clean=True
    )
    doc.close()

    # --- DUAL-ENGINE VERIFICATION GATE ---
    leaks: List[str] = []

    # Verification Layer 1: PyMuPDF Re-read
    verify_doc = fitz.open(out_path)
    primary_exported_text = " ".join(page.get_text("text") for page in verify_doc)
    verify_doc.close()

    primary_lower = primary_exported_text.lower()
    primary_normalized = normalize_text_for_audit(primary_exported_text)

    # Verification Layer 2: Independent Raw Stream Extraction
    with open(out_path, "rb") as pf:
        raw_pdf_bytes = pf.read()
    secondary_text = secondary_pdf_stream_extractor(raw_pdf_bytes)
    secondary_lower = secondary_text.lower()
    secondary_normalized = normalize_text_for_audit(secondary_text)

    # Audit each sensitive span (full text and constituent tokens)
    for s in active_spans:
        raw_needle = s.text.strip()
        if len(raw_needle) < 2:
            continue
        needle_lower = raw_needle.lower()
        needle_norm = normalize_text_for_audit(raw_needle)

        # 1. Plain substring check in PyMuPDF extraction
        if needle_lower in primary_lower:
            leaks.append(f"{s.text} (found in primary page text)")
            continue

        # 2. Normalized check in PyMuPDF extraction
        if len(needle_norm) >= 4 and needle_norm in primary_normalized:
            leaks.append(f"{s.text} (found in normalized primary text)")
            continue

        # 3. Plain substring check in secondary stream extractor
        if needle_lower in secondary_lower:
            leaks.append(f"{s.text} (found in decompressed content streams)")
            continue

        # 4. Normalized check in secondary stream extractor
        if len(needle_norm) >= 4 and needle_norm in secondary_normalized:
            leaks.append(f"{s.text} (found in normalized content streams)")
            continue

        # 5. Constituent name token check (e.g. bare "Priya" or "Nair" from "Priya Nair")
        if s.category == "NAME":
            clean_name = re.sub(r"^(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+", "", raw_needle, flags=re.IGNORECASE)
            tokens = [t.strip(".,") for t in re.split(r"\s+", clean_name) if len(t.strip(".,")) >= 3]
            for tok in tokens:
                tok_l = tok.lower()
                if tok_l not in COMMON_STOPWORDS and tok_l not in DISALLOWED_NAME_TOKENS and tok_l not in STREET_SUFFIXES:
                    if re.search(r"\b" + re.escape(tok) + r"\b", primary_exported_text, flags=re.IGNORECASE):
                        leaks.append(f"Constituent token '{tok}' from approved entity '{s.text}' found in exported PDF")

    # 6. Autonomous rules scanner over exported PDF text
    rejected_terms = {s.text.strip().lower() for s in spans if not s.accepted and s.text.strip()}
    residual_detections = detect_by_rules(primary_exported_text)
    placeholder_pattern = re.compile(r"^(\[(?:NAME|EMAIL|PHONE|ADDRESS|ID)_\d+\]|<[A-Z_]+_HMAC_[a-f0-9]+>|\[(?:NAME|EMAIL|PHONE|ADDRESS|ID|REDACTED[^\]]*)\]|█+|\*+)$")
    for r_span in residual_detections:
        val = r_span.text.strip()
        if placeholder_pattern.match(val):
            continue
        val_lower = val.lower()
        if val_lower in rejected_terms or any(rt in val_lower or val_lower in rt for rt in rejected_terms):
            continue
        leaks.append(f"Residual {r_span.category} '{val}' detected in PDF by post-export scanner")

    unique_leaks = list(dict.fromkeys(leaks))
    if unique_leaks:
        # Refuse export by purging output file completely
        if out_path.exists():
            try:
                out_path.unlink()
            except Exception:
                pass
        return out_path, False, unique_leaks

    return out_path, True, []
