import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import tempfile
import uuid
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import ensure_directories
from src.ingestion.text_loader import load_text_file
from src.ingestion.pdf_loader import load_pdf_file, map_spans_to_word_boxes, ScannedPDFError, EmptyDocumentError
from src.detection.hybrid_detector import HybridDetector
from src.detection.schemas import DetectedSpan
from src.detection.entity_linker import EntityLinker
from src.detection.learning_store import LearningStore
from src.detection.privacy_advisor import PrivacyAdvisor, PrivacyWarning
from src.redaction.text_redactor import redact_text_with_placeholders, verify_redacted_text
from src.redaction.pdf_redactor import redact_pdf
from src.summarizer.safe_summary import SafeSummarizer

app = FastAPI(title="Offline Document Sanitizer & Redactor")
config = ensure_directories()
learning_store = LearningStore()
detector = HybridDetector(learning_store=learning_store)

sessions: Dict[str, Dict[str, Any]] = {}

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def get_favicon():
    fav_file = STATIC_DIR / "favicon.png"
    if fav_file.exists():
        return FileResponse(fav_file, media_type="image/png")
    return Response(status_code=204)

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h3>Loading interface...</h3>", status_code=200)
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...), use_slm: bool = Form(False)):
    # Auto-cleanup files older than 30 mins
    LearningStore.cleanup_old_files([config.UPLOAD_DIR, config.OUTPUT_DIR], max_age_seconds=1800)
    suffix = Path(file.filename).suffix.lower()
    if suffix not in [".txt", ".pdf"]:
        raise HTTPException(status_code=400, detail="Only .txt and text-based .pdf files are supported.")

    with tempfile.NamedTemporaryFile(dir=config.UPLOAD_DIR, delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        if suffix == ".pdf":
            doc_data = load_pdf_file(tmp_path)
        else:
            doc_data = load_text_file(tmp_path)
        doc_data.filename = file.filename

        # Detect PII (GLiNER + Presidio + Validators + Learning)
        spans = detector.detect(doc_data.full_text, use_slm=use_slm)

        # Map spans to exact word bounding boxes and page numbers for PDFs
        if doc_data.file_type == "pdf" and doc_data.word_boxes:
            map_spans_to_word_boxes(spans, doc_data.word_boxes)

        # Review Gating: auto-accept high confidence (>= 0.85); leave low/medium confidence pending review
        for s in spans:
            if s.source == "manual":
                s.accepted = True
            else:
                s.accepted = (s.confidence >= 0.85)

        # Quasi-identifier scan
        warnings = PrivacyAdvisor.scan_warnings(doc_data.full_text)

        # Entity clustering and name ambiguity detection
        tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in spans if s.accepted])

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "doc_data": doc_data,
            "spans": spans,
            "warnings": warnings,
            "tmp_path": tmp_path,
            "tag_map": tag_map,
            "ambiguity_flags": ambiguity_flags,
            "summary": None
        }

        return {
            "session_id": session_id,
            "filename": doc_data.filename,
            "file_type": doc_data.file_type,
            "full_text": doc_data.full_text,
            "spans": [s.model_dump() for s in spans],
            "warnings": [w.__dict__ for w in warnings],
            "tag_map": tag_map,
            "ambiguity_flags": ambiguity_flags,
            "learning_stats": learning_store.get_stats()
        }

    except ScannedPDFError as e:
        raise HTTPException(status_code=422, detail=f"Scanned PDF Not Supported: {str(e)}")
    except EmptyDocumentError as e:
        raise HTTPException(status_code=422, detail=f"Empty Document: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")

class DirectTextRequest(BaseModel):
    text: str
    filename: Optional[str] = "custom_input.txt"
    use_slm: bool = False

@app.get("/api/presets")
async def get_presets():
    benchmark_dir = PROJECT_ROOT / "data" / "benchmark"
    unseen_dir = benchmark_dir / "unseen_manual_docs"
    presets = []
    preset_files = [
        ("📋 Unseen: Mutual NDA (Legal & Entities)", unseen_dir / "unseen_01_public_nda.txt", "unseen_01_public_nda.txt"),
        ("📋 Unseen: Clinical Discharge (Medical PII)", unseen_dir / "unseen_02_clinical_discharge.txt", "unseen_02_clinical_discharge.txt"),
        ("📋 Unseen: IT Security Incident Log (IP & Accounts)", unseen_dir / "unseen_03_it_incident_log.txt", "unseen_03_it_incident_log.txt"),
        ("📋 Unseen: Academic Transcript (Student PII)", unseen_dir / "unseen_04_academic_transcript.txt", "unseen_04_academic_transcript.txt"),
        ("📋 Unseen: Corporate HR Grievance", unseen_dir / "unseen_05_corporate_grievance.txt", "unseen_05_corporate_grievance.txt"),
        ("Meeting Notes (Name Variants & Obfuscation)", benchmark_dir / "doc_01_meeting_notes.txt", "doc_01_meeting_notes.txt"),
        ("Patient Clinical Intake (Aadhaar & Vitals)", benchmark_dir / "doc_02_medical_intake.txt", "doc_02_medical_intake.txt"),
        ("Vendor Invoice (PAN & Account Numbers)", benchmark_dir / "doc_03_vendor_invoice.txt", "doc_03_vendor_invoice.txt"),
        ("Executive Profile (Quasi-Identifier Risk)", benchmark_dir / "doc_12_executive_bio.txt", "doc_12_executive_bio.txt"),
        ("HR Incident Report (Ambiguous Surnames)", benchmark_dir / "doc_08_hr_incident.txt", "doc_08_hr_incident.txt"),
        ("Customer Support Desk (Landline & Addresses)", benchmark_dir / "doc_11_landline_inquiry.txt", "doc_11_landline_inquiry.txt"),
    ]
    for label, fpath, fname in preset_files:
        if fpath.exists():
            presets.append({
                "label": label,
                "filename": fname,
                "text": fpath.read_text(encoding="utf-8")
            })
    return {"presets": presets}

@app.post("/api/analyze_text")
async def analyze_direct_text(req: DirectTextRequest):
    # Auto-cleanup temporary files older than 30 mins
    LearningStore.cleanup_old_files([config.UPLOAD_DIR, config.OUTPUT_DIR], max_age_seconds=1800)
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
        
    from src.detection.schemas import DocumentContent
    doc_data = DocumentContent(
        filename=req.filename or "input.txt",
        file_type="txt",
        full_text=req.text,
        pages=[req.text],
        word_boxes=[],
        spans=[]
    )
    
    spans = detector.detect(doc_data.full_text, use_slm=req.use_slm)
    # Review Gating: auto-accept high confidence (>= 0.85); leave low/medium confidence pending review
    for s in spans:
        if s.source == "manual":
            s.accepted = True
        else:
            s.accepted = (s.confidence >= 0.85)
    warnings = PrivacyAdvisor.scan_warnings(doc_data.full_text)
    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in spans if s.accepted])
    
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "doc_data": doc_data,
        "spans": spans,
        "warnings": warnings,
        "tmp_path": None,
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "summary": None
    }
    
    return {
        "session_id": session_id,
        "filename": doc_data.filename,
        "file_type": doc_data.file_type,
        "full_text": doc_data.full_text,
        "spans": [s.model_dump() for s in spans],
        "warnings": [w.__dict__ for w in warnings],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "learning_stats": learning_store.get_stats()
    }

@app.get("/api/system_status")
async def get_system_status():
    return {
        "gliner_available": detector.gliner_detector.is_available(),
        "slm_available": detector.slm_client.is_available(),
        "learning_stats": learning_store.get_stats()
    }

class ListUpdateRequest(BaseModel):
    term: str
    category: Optional[str] = "NAME"

@app.post("/api/learning/allowlist")
async def add_to_allowlist(req: ListUpdateRequest):
    learning_store.record_correction(req.term, req.category or "NAME", action="reject")
    return {"status": "ok", "stats": learning_store.get_stats()}

@app.post("/api/learning/denylist")
async def add_to_denylist(req: ListUpdateRequest):
    learning_store.record_correction(req.term, req.category or "NAME", action="manual_add")
    return {"status": "ok", "stats": learning_store.get_stats()}

@app.get("/api/learning/lists")
async def get_learning_lists():
    return {
        "allowlist": list(learning_store.suppressed),
        "denylist": learning_store.remembered,
        "stats": learning_store.get_stats()
    }

class UpdateSpanRequest(BaseModel):
    session_id: str
    span_id: str
    accepted: bool
    category: Optional[str] = None

@app.post("/api/spans/update")
async def update_span(req: UpdateSpanRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    target_span = next((s for s in sess["spans"] if s.id == req.span_id), None)
    if not target_span:
        raise HTTPException(status_code=404, detail="Span not found")

    target_span.accepted = req.accepted
    if req.category:
        target_span.category = req.category

    # Active learning feedback logging
    action = "approve" if req.accepted else "reject"
    learning_store.record_correction(
        target_span.text, 
        target_span.category, 
        action=action, 
        filename=sess["doc_data"].filename
    )

    # Linked name variants move together as one person
    if target_span.category == "NAME":
        for s in sess["spans"]:
            if s.category == "NAME" and s.id != target_span.id:
                if EntityLinker.are_name_variants(target_span.text, s.text):
                    s.accepted = req.accepted
                    learning_store.record_correction(s.text, s.category, action=action, filename=sess["doc_data"].filename)

    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in sess["spans"] if s.accepted])
    sess["tag_map"] = tag_map
    sess["ambiguity_flags"] = ambiguity_flags

    return {
        "spans": [s.model_dump() for s in sess["spans"]],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "learning_stats": learning_store.get_stats()
    }

class AddSpanRequest(BaseModel):
    session_id: str
    text: str
    category: str = "NAME"
    start_char: Optional[int] = None
    end_char: Optional[int] = None

@app.post("/api/spans/add")
async def add_manual_span(req: AddSpanRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    full_text = sess["doc_data"].full_text
    raw_term = req.text.strip()
    if not raw_term:
        raise HTTPException(status_code=400, detail="Text cannot be empty")

    import re
    # Clean surrounding quotes, brackets, and trailing colons/commas
    search_term = re.sub(r'^[«"\'`“”‘’\(\[\{]+|[»"\'`“”‘’\)\]\}]+$', '', raw_term).rstrip(':,;')
    if search_term.endswith('.') and not re.match(r'^[A-Za-z]\.$|^(?:Mr|Mrs|Ms|Dr|Prof)\.$', search_term, re.IGNORECASE):
        search_term = search_term[:-1].strip()
    if not search_term:
        search_term = raw_term

    # 1. Find all occurrences using robust boundary detection
    prefix = r"\b" if re.match(r"^\w", search_term) else r"(?<!\w)"
    suffix = r"\b" if re.search(r"\w$", search_term) else r"(?!\w)"
    pattern = re.compile(prefix + re.escape(search_term) + suffix, re.IGNORECASE)
    matches_found = list(pattern.finditer(full_text))

    # Fallback to exact literal substring search if boundary search yielded no matches
    if not matches_found:
        idx = 0
        term_lower = search_term.lower()
        full_lower = full_text.lower()
        while True:
            pos = full_lower.find(term_lower, idx)
            if pos == -1:
                break
            m_val = full_text[pos:pos + len(search_term)]
            class SubstringMatch:
                def __init__(self, start_pos, val):
                    self._start = start_pos
                    self._val = val
                def start(self): return self._start
                def end(self): return self._start + len(self._val)
                def group(self, _=0): return self._val
            matches_found.append(SubstringMatch(pos, m_val))
            idx = pos + len(search_term)

    if not matches_found and (req.start_char is None or req.end_char is None):
        raise HTTPException(status_code=400, detail="Text phrase not found in document text")

    # Add all matching spans across the entire document
    for match in matches_found:
        m_start = match.start()
        m_end = match.end()
        m_val = match.group(0)

        existing = next((s for s in sess["spans"] if s.start_char == m_start and s.end_char == m_end), None)
        if existing:
            existing.accepted = True
            existing.category = req.category
        else:
            new_span = DetectedSpan(
                id=str(uuid.uuid4())[:8],
                text=m_val,
                category=req.category,
                start_char=m_start,
                end_char=m_end,
                source="manual",
                confidence=1.0,
                accepted=True
            )
            sess["spans"].append(new_span)

    # If explicit coordinates provided and not covered by regex search
    if req.start_char is not None and req.end_char is not None:
        explicit_exist = next((s for s in sess["spans"] if s.start_char == req.start_char and s.end_char == req.end_char), None)
        if not explicit_exist:
            sess["spans"].append(DetectedSpan(
                id=str(uuid.uuid4())[:8],
                text=req.text,
                category=req.category,
                start_char=req.start_char,
                end_char=req.end_char,
                source="manual",
                confidence=1.0,
                accepted=True
            ))

    # 2. Automatically identify and select other related similar name variants in the document!
    if req.category == "NAME":
        for s in sess["spans"]:
            if s.category == "NAME" and not s.accepted:
                if EntityLinker.are_name_variants(search_term, s.text):
                    s.accepted = True

    sess["spans"].sort(key=lambda s: s.start_char)
    if sess["doc_data"].file_type == "pdf" and sess["doc_data"].word_boxes:
        map_spans_to_word_boxes(sess["spans"], sess["doc_data"].word_boxes)
    learning_store.record_correction(
        search_term, 
        req.category, 
        action="manual_add", 
        filename=sess["doc_data"].filename
    )
    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in sess["spans"] if s.accepted])
    sess["tag_map"] = tag_map
    sess["ambiguity_flags"] = ambiguity_flags

    return {
        "spans": [s.model_dump() for s in sess["spans"]],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "learning_stats": learning_store.get_stats()
    }



class RedactSimilarRequest(BaseModel):
    session_id: str
    text: str
    category: str

@app.post("/api/spans/redact_similar")
async def redact_similar(req: RedactSimilarRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    import re
    full_text = sess["doc_data"].full_text
    raw_term = req.text.strip()
    search_term = re.sub(r'^[«"\'`“”‘’\(\[\{]+|[»"\'`“”‘’\)\]\}]+$', '', raw_term).rstrip(':,;')
    if search_term.endswith('.') and not re.match(r'^[A-Za-z]\.$|^(?:Mr|Mrs|Ms|Dr|Prof)\.$', search_term, re.IGNORECASE):
        search_term = search_term[:-1].strip()
    if not search_term:
        search_term = raw_term

    prefix = r"\b" if re.match(r"^\w", search_term) else r"(?<!\w)"
    suffix = r"\b" if re.search(r"\w$", search_term) else r"(?!\w)"
    pattern = re.compile(prefix + re.escape(search_term) + suffix, re.IGNORECASE)
    matches_found = list(pattern.finditer(full_text))

    if not matches_found:
        idx = 0
        term_lower = search_term.lower()
        full_lower = full_text.lower()
        while True:
            pos = full_lower.find(term_lower, idx)
            if pos == -1:
                break
            m_val = full_text[pos:pos + len(search_term)]
            class SubstringMatch:
                def __init__(self, start_pos, val):
                    self._start = start_pos
                    self._val = val
                def start(self): return self._start
                def end(self): return self._start + len(self._val)
                def group(self, _=0): return self._val
            matches_found.append(SubstringMatch(pos, m_val))
            idx = pos + len(search_term)

    for match in matches_found:
        m_start = match.start()
        m_end = match.end()
        m_val = match.group(0)

        existing = next((s for s in sess["spans"] if s.start_char == m_start and s.end_char == m_end), None)
        if existing:
            existing.accepted = True
            existing.category = req.category
        else:
            new_span = DetectedSpan(
                id=str(uuid.uuid4())[:8],
                text=m_val,
                category=req.category,
                start_char=m_start,
                end_char=m_end,
                source="similar",
                confidence=1.0,
                accepted=True
            )
            sess["spans"].append(new_span)

    sess["spans"].sort(key=lambda s: s.start_char)
    if sess["doc_data"].file_type == "pdf" and sess["doc_data"].word_boxes:
        map_spans_to_word_boxes(sess["spans"], sess["doc_data"].word_boxes)
    learning_store.record_correction(req.text, req.category, action="approve", filename=sess["doc_data"].filename)
    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in sess["spans"] if s.accepted])
    sess["tag_map"] = tag_map
    sess["ambiguity_flags"] = ambiguity_flags

    return {
        "spans": [s.model_dump() for s in sess["spans"]],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "learning_stats": learning_store.get_stats()
    }

class GeneralizeRequest(BaseModel):
    session_id: str
    warning_id: str

@app.post("/api/generalize")
async def apply_generalization(req: GeneralizeRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    warning = next((w for w in sess["warnings"] if w.id == req.warning_id), None)
    if not warning:
        raise HTTPException(status_code=404, detail="Warning not found")

    new_text = PrivacyAdvisor.apply_generalization(sess["doc_data"].full_text, warning)
    sess["doc_data"].full_text = new_text
    sess["warnings"] = PrivacyAdvisor.scan_warnings(new_text)

    # Preserve previous user approvals and manual additions across generalization
    prev_accepted_texts = {s.text.strip(): s.accepted for s in sess["spans"]}
    prev_manual_spans = [s for s in sess["spans"] if s.source in ("manual", "similar")]

    new_spans = detector.detect(new_text, use_slm=False)
    for s in new_spans:
        if s.text.strip() in prev_accepted_texts:
            s.accepted = prev_accepted_texts[s.text.strip()]
        else:
            s.accepted = (s.confidence >= 0.85)

    for ms in prev_manual_spans:
        if ms.text in new_text:
            idx = new_text.find(ms.text)
            if not any(s.start_char == idx and s.end_char == idx + len(ms.text) for s in new_spans):
                new_spans.append(DetectedSpan(
                    id=ms.id,
                    text=ms.text,
                    category=ms.category,
                    start_char=idx,
                    end_char=idx + len(ms.text),
                    source=ms.source,
                    confidence=ms.confidence,
                    accepted=ms.accepted
                ))

    new_spans.sort(key=lambda s: s.start_char)
    sess["spans"] = new_spans
    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in sess["spans"] if s.accepted])
    sess["tag_map"] = tag_map
    sess["ambiguity_flags"] = ambiguity_flags

    return {
        "full_text": new_text,
        "warnings": [w.__dict__ for w in sess["warnings"]],
        "spans": [s.model_dump() for s in sess["spans"]],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags
    }

class SummarizeRequest(BaseModel):
    session_id: str
    model: str = "llama3.2:1b"
    mask_style: Optional[str] = "INDEXED"
    preserve_length: Optional[bool] = False

@app.post("/api/summarize")
async def generate_summary(req: SummarizeRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    mask_style = req.mask_style or "INDEXED"
    preserve_length = req.preserve_length or False

    # Structural guarantee: summarizer receives ONLY redacted text in user-chosen masking format
    redacted_text, _ = redact_text_with_placeholders(
        sess["doc_data"].full_text, 
        sess["spans"], 
        mask_style=mask_style,
        preserve_length=preserve_length
    )
    
    summarizer = SafeSummarizer(model=req.model)
    raw_summary, engine = summarizer.summarize_redacted_only(redacted_text)
    
    # Audit summary against all removed PII
    purged_summary, caught_leaks = summarizer.audit_summary_leaks(raw_summary, sess["spans"])

    # Also scan summary for quasi-identifiers
    summary_warnings = PrivacyAdvisor.scan_warnings(purged_summary)

    sess["summary"] = purged_summary
    sess["summary_mask_style"] = mask_style

    return {
        "summary": purged_summary,
        "engine": engine,
        "mask_style": mask_style,
        "caught_leaks": caught_leaks,
        "summary_warnings": [w.__dict__ for w in summary_warnings]
    }

@app.get("/api/export_summary/{session_id}")
async def export_summary_file(session_id: str, mask_style: str = "INDEXED", preserve_length: bool = False):
    sess = sessions.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Always regenerate and run leak audit to guarantee freshness and safety
    redacted_text, _ = redact_text_with_placeholders(
        sess["doc_data"].full_text, 
        sess["spans"], 
        mask_style=mask_style,
        preserve_length=preserve_length
    )
    summarizer = SafeSummarizer()
    raw_summary, _ = summarizer.summarize_redacted_only(redacted_text)
    purged_summary, _ = summarizer.audit_summary_leaks(raw_summary, sess["spans"])
    sess["summary"] = purged_summary
    sess["summary_mask_style"] = mask_style

    filename = f"summary_{mask_style.lower()}_{sess['doc_data'].filename}.txt"
    return PlainTextResponse(
        content=sess["summary"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

class BatchUpdateRequest(BaseModel):
    session_id: str
    accepted: bool
    category: Optional[str] = None

@app.post("/api/spans/batch_update")
async def batch_update_spans(req: BatchUpdateRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    for s in sess["spans"]:
        if req.category is None or s.category == req.category:
            s.accepted = req.accepted

    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in sess["spans"] if s.accepted])
    sess["tag_map"] = tag_map
    sess["ambiguity_flags"] = ambiguity_flags

    return {
        "spans": [s.model_dump() for s in sess["spans"]],
        "tag_map": tag_map,
        "ambiguity_flags": ambiguity_flags,
        "learning_stats": learning_store.get_stats()
    }

@app.delete("/api/learning")
async def purge_learning_data():
    success = learning_store.purge_all()
    return {
        "status": "success" if success else "error",
        "message": "All stored learning data and corrections securely wiped.",
        "stats": learning_store.get_stats()
    }

@app.get("/api/export/{session_id}")
async def export_redacted(
    session_id: str, 
    format: str = "txt", 
    mask_style: str = "INDEXED",
    preserve_length: bool = False
):
    # Auto-cleanup expired files
    LearningStore.cleanup_old_files([config.UPLOAD_DIR, config.OUTPUT_DIR], max_age_seconds=1800)
    sess = sessions.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    doc_data = sess["doc_data"]
    spans = sess["spans"]
    clean_stem = Path(doc_data.filename).stem

    # 1. Plaintext Export
    if format == "txt" or doc_data.file_type == "txt":
        redacted_text, _ = redact_text_with_placeholders(
            doc_data.full_text, spans, mask_style=mask_style, preserve_length=preserve_length
        )
        
        # Automated Verification Gate
        is_safe, leaks = verify_redacted_text(redacted_text, spans)
        if not is_safe:
            raise HTTPException(
                status_code=400,
                detail=f"Export Refused by Security Gate: Residual sensitive text detected: {leaks}"
            )

        out_name = f"redacted_{mask_style.lower()}_{clean_stem}.txt"
        out_file = config.OUTPUT_DIR / out_name
        out_file.write_text(redacted_text, encoding="utf-8")

        response = FileResponse(out_file, media_type="text/plain; charset=utf-8", filename=out_name)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # 2. True PDF Redaction
    else:
        out_name = f"redacted_{mask_style.lower()}_{clean_stem}.pdf"
        out_file = config.OUTPUT_DIR / out_name
        try:
            _, is_clean, leaks = redact_pdf(
                sess["tmp_path"], 
                out_file, 
                spans, 
                mask_style=mask_style, 
                preserve_length=preserve_length
            )
            if not is_clean:
                raise HTTPException(
                    status_code=400,
                    detail=f"Export Refused by Dual-Engine Verification Gate: Residual text detected: {leaks}"
                )
            response = FileResponse(out_file, media_type="application/pdf", filename=out_name)
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Export Refused: {str(e)}")
