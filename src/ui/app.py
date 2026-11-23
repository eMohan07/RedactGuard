import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import streamlit.components.v1 as components
import tempfile
import re
import uuid
import pandas as pd

from config import ensure_directories
from src.ingestion.text_loader import load_text_file
from src.ingestion.pdf_loader import load_pdf_file, ScannedPDFError, EmptyDocumentError
from src.detection.hybrid_detector import HybridDetector
from src.detection.schemas import DetectedSpan, DocumentContent
from src.detection.entity_linker import EntityLinker
from src.detection.learning_store import LearningStore
from src.detection.privacy_advisor import PrivacyAdvisor, PrivacyWarning
from src.redaction.text_redactor import (
    redact_text_with_placeholders, 
    verify_redacted_text, 
    VerificationFailedError
)
from src.redaction.pdf_redactor import redact_pdf
from src.summarizer.safe_summary import SafeSummarizer
from src.ui.highlighter import render_highlighted_document

st.set_page_config(
    page_title="RedactGuard — Local PII Redactor & Shield",
    page_icon="🛡️",
    layout="wide"
)

config = ensure_directories()
learning_store = LearningStore()

st.title("🛡️ RedactGuard — Offline Document Sanitizer & Redactor")
st.caption("100% Local Processing — Presidio Pattern Recognizers + Local SLM — Zero Cloud Uploads")

# Sidebar
with st.sidebar:
    st.header("⚙️ De-Identification Settings")
    use_slm = st.checkbox("Enable Local SLM (Ollama)", value=False, help="Extracts contextual names and entities using local SLM")
    slm_model = st.text_input("Ollama Model Name", value=config.OLLAMA_MODEL)
    
    # Presidio Anonymizer Masking Strategies
    mask_style = st.selectbox(
        "Anonymization Strategy", 
        ["INDEXED", "BLOCK", "ASTERISK", "HASH", "GENERIC"], 
        index=0, 
        help="INDEXED: [NAME_1], BLOCK: ████, ASTERISK: ****, HASH: <NAME_HMAC_hash>, GENERIC: [REDACTED: NAME]"
    )
    preserve_length = False
    if mask_style in ["BLOCK", "ASTERISK"]:
        preserve_length = st.checkbox(
            "Reveal Exact Character Length", 
            value=False, 
            help="⚠️ Warning: Preserving exact character counts can allow attackers to infer short names or phone numbers."
        )
    
    # Presidio Confidence Threshold Filter
    min_confidence = st.slider("Confidence Threshold", 0.0, 1.0, 0.0, 0.05, help="Filter candidate entities below this score")

    st.divider()
    st.subheader("🧠 Active Learning Store")
    enc_status = "🔒 AES-128 Encrypted" if learning_store.cipher else "⚠️ Plaintext"
    st.caption(f"Storage Status: **{enc_status}**")
    st.caption(f"Learned Redactions: **{len(learning_store.remembered)}**")
    st.caption(f"Suppressed Terms: **{len(learning_store.suppressed)}**")
    if st.button("🗑️ Purge All Learning Data", help="Permanently delete all stored dictionary entries, suppression rules, and feedback logs"):
        learning_store.purge_all()
        st.success("All stored learning data securely wiped.")
        st.rerun()

    st.divider()
    st.info("🔒 100% Offline: Documents and extracted entities never leave your local machine.")

# Initialize Session State
if "doc_data" not in st.session_state:
    st.session_state.doc_data = None
if "spans" not in st.session_state:
    st.session_state.spans = []
if "error_message" not in st.session_state:
    st.session_state.error_message = None
if "file_sig" not in st.session_state:
    st.session_state.file_sig = None
if "privacy_warnings" not in st.session_state:
    st.session_state.privacy_warnings = []

# Input Options: File Upload, Sample Presets, or Direct Paste
input_mode = st.radio(
    "Select Input Source", 
    ["📁 Upload File (TXT/PDF)", "📋 Sample Presets", "✍️ Direct Text Paste"], 
    horizontal=True
)

benchmark_dir = PROJECT_ROOT / "data" / "benchmark"
unseen_dir = benchmark_dir / "unseen_manual_docs"
presets_map = {
    "📋 Unseen: Mutual NDA (Legal & Entities)": str(unseen_dir / "unseen_01_public_nda.txt"),
    "📋 Unseen: Clinical Discharge (Medical PII)": str(unseen_dir / "unseen_02_clinical_discharge.txt"),
    "📋 Unseen: IT Security Incident Log (IP & Accounts)": str(unseen_dir / "unseen_03_it_incident_log.txt"),
    "📋 Unseen: Academic Transcript (Student PII)": str(unseen_dir / "unseen_04_academic_transcript.txt"),
    "📋 Unseen: Corporate HR Grievance": str(unseen_dir / "unseen_05_corporate_grievance.txt"),
    "Meeting Notes (Name Variants & Obfuscation)": str(benchmark_dir / "doc_01_meeting_notes.txt"),
    "Patient Clinical Intake (Aadhaar & Vitals)": str(benchmark_dir / "doc_02_medical_intake.txt"),
    "Vendor Invoice (PAN & Account Numbers)": str(benchmark_dir / "doc_03_vendor_invoice.txt"),
    "Executive Profile (Quasi-Identifier Risk)": str(benchmark_dir / "doc_12_executive_bio.txt"),
    "HR Incident Report (Ambiguous Surnames)": str(benchmark_dir / "doc_08_hr_incident.txt"),
    "Customer Support Desk (Landline & Addresses)": str(benchmark_dir / "doc_11_landline_inquiry.txt")
}

def process_text_content(text: str, filename: str, tmp_path=None):
    doc_data = DocumentContent(
        filename=filename,
        file_type="pdf" if filename.lower().endswith(".pdf") else "txt",
        full_text=text,
        pages=[text],
        word_boxes=[],
        spans=[]
    )
    detector = HybridDetector(learning_store=learning_store)
    detector.slm_client.model = slm_model
    spans = detector.detect(doc_data.full_text, use_slm=use_slm)
    privacy_warnings = PrivacyAdvisor.scan_warnings(doc_data.full_text)

    st.session_state.doc_data = doc_data
    st.session_state.spans = spans
    st.session_state.uploaded_tmp_path = str(tmp_path) if tmp_path else None
    st.session_state.file_sig = f"{filename}_{len(text)}"
    st.session_state.privacy_warnings = privacy_warnings
    st.session_state.error_message = None

if input_mode == "📁 Upload File (TXT/PDF)":
    uploaded_file = st.file_uploader(
        "Upload Document (TXT or text-based PDF)", 
        type=["txt", "pdf"],
        help="Note: Scanned PDFs (image-only) are not supported. Only files with selectable text can be processed."
    )
    if uploaded_file is not None:
        current_sig = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.file_sig != current_sig or st.session_state.doc_data is None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = Path(tmp.name)

            try:
                with st.spinner("Inspecting document & running Presidio-style pattern recognizers..."):
                    if uploaded_file.name.lower().endswith(".pdf"):
                        doc_data = load_pdf_file(tmp_path)
                    else:
                        doc_data = load_text_file(tmp_path)
                    process_text_content(doc_data.full_text, uploaded_file.name, tmp_path=tmp_path)
            except ScannedPDFError as e:
                st.session_state.doc_data = None
                st.session_state.error_message = ("scanned", str(e))
            except EmptyDocumentError as e:
                st.session_state.doc_data = None
                st.session_state.error_message = ("empty", str(e))
            except Exception as e:
                st.session_state.doc_data = None
                st.session_state.error_message = ("general", f"Error processing file: {e}")

elif input_mode == "📋 Sample Presets":
    preset_choice = st.selectbox("Choose a benchmark preset", list(presets_map.keys()))
    if st.button("🚀 Load & Analyze Preset", use_container_width=True):
        fpath = Path(presets_map[preset_choice])
        if fpath.exists():
            txt = fpath.read_text(encoding="utf-8")
            with st.spinner("Analyzing preset..."):
                process_text_content(txt, fpath.name)
            st.rerun()

elif input_mode == "✍️ Direct Text Paste":
    custom_txt = st.text_area("Paste or type raw text here", height=150, placeholder="Paste text containing names, phones, emails, or IDs...")
    c1, c2 = st.columns([3, 1])
    doc_name_input = c1.text_input("Document Name", value="pasted_text.txt")
    if c2.button("🚀 Analyze Pasted Text", use_container_width=True) and custom_txt.strip():
        with st.spinner("Analyzing text..."):
            process_text_content(custom_txt.strip(), doc_name_input)
        st.rerun()

# Helper: Redact All Similar Occurrences
def redact_all_similar(target_text: str, category: str):
    full_text = st.session_state.doc_data.full_text
    pattern = re.compile(re.escape(target_text), re.IGNORECASE)
    
    for match in pattern.finditer(full_text):
        m_start = match.start()
        m_end = match.end()
        m_val = match.group(0)

        existing = next((s for s in st.session_state.spans if s.start_char == m_start and s.end_char == m_end), None)
        if existing:
            existing.accepted = True
            existing.category = category
        else:
            new_span = DetectedSpan(
                id=str(uuid.uuid4())[:8],
                text=m_val,
                category=category,
                start_char=m_start,
                end_char=m_end,
                source="similar_rule",
                confidence=1.0,
                accepted=True
            )
            st.session_state.spans.append(new_span)
            
    learning_store.record_correction(target_text, category, accepted=True)
    st.session_state.spans.sort(key=lambda s: s.start_char)

# Render View
if st.session_state.error_message:
    err_type, err_text = st.session_state.error_message
    if err_type == "scanned":
        st.error(f"🚫 **Scanned PDF Not Supported**\n\n{err_text}")
        st.info("💡 **How to resolve:** This tool requires selectable digital text to accurately locate and permanently excise personal information. Run OCR on your scanned PDF, or export it as a text-based PDF or TXT file before uploading.")
    elif err_type == "empty":
        st.warning(f"⚠️ **Empty Document:** {err_text}")
    else:
        st.error(f"⚠️ **Processing Error:** {err_text}")

elif st.session_state.doc_data is not None:
    # 1. Privacy Warnings Banner (Quasi-identifiers)
    if st.session_state.privacy_warnings:
        for p_warn in list(st.session_state.privacy_warnings):
            with st.container(border=True):
                w_col1, w_col2 = st.columns([4, 1])
                w_col1.warning(
                    f"⚠️ **Privacy Warning (Re-identification Risk):** `{p_warn.original_text}`\n\n"
                    f"{p_warn.explanation}\n\n"
                    f"**Suggested Generalization:** `\"{p_warn.suggested_generalization}\"`"
                )
                if w_col2.button(f"🔄 Generalize", key=f"btn_gen_{p_warn.id}", use_container_width=True):
                    new_text = PrivacyAdvisor.apply_generalization(st.session_state.doc_data.full_text, p_warn)
                    st.session_state.doc_data.full_text = new_text
                    st.session_state.privacy_warnings = PrivacyAdvisor.scan_warnings(new_text)
                    st.success(f"Generalized '{p_warn.original_text}' into safer phrasing.")
                    st.rerun()

    # 2. Header and Entity Link status
    tag_map, ambiguity_flags = EntityLinker.cluster_entities([s for s in st.session_state.spans if s.accepted])

    top_c1, top_c2 = st.columns([3, 1])
    with top_c1:
        st.markdown(
            """
            <div style="display: flex; gap: 8px; align-items: center; margin: 4px 0 10px 0; font-size: 0.85rem; flex-wrap: wrap;">
                <span style="font-weight: 600;">Confidence:</span>
                <span style="background: #ecfdf5; border: 1.5px solid #10b981; color: #064e3b; padding: 2px 8px; border-radius: 4px; font-weight: 600;">🟢 High (&ge;85%)</span>
                <span style="background: #fffbeb; border: 1.5px solid #f59e0b; color: #78350f; padding: 2px 8px; border-radius: 4px; font-weight: 600;">🟡 Medium (60%–84%)</span>
                <span style="background: #fef2f2; border: 1.5px solid #ef4444; color: #7f1d1d; padding: 2px 8px; border-radius: 4px; font-weight: 600;">🔴 Low (&lt;60%)</span>
                <span style="background: #f3f4f6; border: 1.5px solid #9ca3af; color: #6b7280; padding: 2px 8px; border-radius: 4px; text-decoration: line-through;">⚪ Excluded</span>
            </div>
            """, 
            unsafe_allow_html=True
        )
    with top_c2:
        active_cnt = sum(1 for s in st.session_state.spans if s.accepted)
        st.caption(f"Document: **{st.session_state.doc_data.filename}** | **{active_cnt}/{len(st.session_state.spans)}** redacted")

    # Main columns
    doc_col, review_col = st.columns([7, 5])

    # Left Column: Document Viewer with Presidio Analysis Tab
    with doc_col:
        tab_highlight, tab_redacted, tab_analysis, tab_summary = st.tabs([
            "🔍 Highlighted Document",
            "👁️ Sanitized Preview",
            "📊 Presidio Analysis Inspector",
            "📝 Leak-Free Summary"
        ])

        with tab_highlight:
            html_content = render_highlighted_document(
                st.session_state.doc_data.full_text,
                st.session_state.spans,
                tag_map=tag_map
            )
            components.html(html_content, height=530, scrolling=True)

        with tab_redacted:
            redacted_preview, _ = redact_text_with_placeholders(
                st.session_state.doc_data.full_text,
                st.session_state.spans,
                mask_style=mask_style,
                preserve_length=preserve_length
            )
            st.text_area(
                "Sanitized Output Text",
                redacted_preview,
                height=490,
                label_visibility="collapsed"
            )

        with tab_analysis:
            st.markdown("**Presidio-Style Detailed Detection Breakdown:**")
            if st.session_state.spans:
                records = []
                for s in st.session_state.spans:
                    records.append({
                        "Entity Text": s.text,
                        "Category": s.category,
                        "Confidence": f"{round(s.confidence * 100)}%",
                        "Source Recognizer": s.source,
                        "Offsets": f"{s.start_char}:{s.end_char}",
                        "Redacted": "Yes" if s.accepted else "No"
                    })
                df = pd.DataFrame(records)
                st.dataframe(df, use_container_width=True, height=450)
            else:
                st.info("No entities detected in this document.")

        with tab_summary:
            st.markdown("**Local Zero-Leak Summary:**")
            st.caption("Generated strictly from pre-sanitized text and verified against all removed private details.")
            if st.button("Generate Safe Summary", key="btn_gen_summary"):
                with st.spinner("Writing leak-free summary with local SLM..."):
                    summarizer = SafeSummarizer(model=slm_model)
                    summary = summarizer.summarize(st.session_state.doc_data.full_text, st.session_state.spans)
                    st.success(summary)
            else:
                st.info("Click 'Generate Safe Summary' to produce an anonymized overview.")

    # Right Column: Review & Corrections
    with review_col:
        st.subheader("📋 Candidate Review & Correction")
        
        btn_c1, btn_c2 = st.columns([1, 1])
        if btn_c1.button("Select All", use_container_width=True):
            for s in st.session_state.spans:
                s.accepted = True
            st.rerun()
        if btn_c2.button("Deselect All", use_container_width=True):
            for s in st.session_state.spans:
                s.accepted = False
            st.rerun()

        # Dynamic category list
        if "custom_categories" not in st.session_state:
            st.session_state.custom_categories = ["ALL", "EMAIL", "ADDRESS", "NAME", "PHONE", "ID", "ORGANIZATION", "FINANCIAL", "CONFIDENTIAL", "DATE"]
        
        # Ensure any newly detected categories in spans are present
        for s in st.session_state.spans:
            if s.category.upper() not in st.session_state.custom_categories:
                st.session_state.custom_categories.append(s.category.upper())

        # Manual addition / Add Redaction
        with st.expander("➕ Add Redaction / Custom Entity"):
            custom_input = st.text_input("Type entity name or text to redact", key="custom_text_input")
            add_c1, add_c2 = st.columns([2, 1])
            selected_cat_to_add = add_c1.selectbox(
                "Category", 
                [c for c in st.session_state.custom_categories if c != "ALL"], 
                key="custom_cat_select"
            )
            if add_c2.button("+ Add Redaction", use_container_width=True) and custom_input:
                clean_cat = custom_input.strip().upper().replace(" ", "_")
                if clean_cat not in st.session_state.custom_categories:
                    st.session_state.custom_categories.append(clean_cat)
                
                # If document contains this text phrase, redact it under this entity
                full_doc_text = st.session_state.doc_data.full_text
                if custom_input.strip().lower() in full_doc_text.lower():
                    import re
                    pat = re.compile(re.escape(custom_input.strip()), re.IGNORECASE)
                    for m in pat.finditer(full_doc_text):
                        m_start, m_end, m_val = m.start(), m.end(), m.group(0)
                        existing = next((s for s in st.session_state.spans if s.start_char == m_start and s.end_char == m_end), None)
                        if existing:
                            existing.accepted = True
                            existing.category = selected_cat_to_add
                        else:
                            st.session_state.spans.append(DetectedSpan(
                                id=str(uuid.uuid4())[:8],
                                text=m_val,
                                category=selected_cat_to_add,
                                start_char=m_start,
                                end_char=m_end,
                                source="manual",
                                confidence=1.0,
                                accepted=True
                            ))
                    learning_store.record_correction(custom_input.strip(), selected_cat_to_add, accepted=True)
                
                st.session_state.selected_entity_filter = clean_cat
                st.session_state.spans.sort(key=lambda s: s.start_char)
                st.rerun()

        st.divider()

        # Entity-Based Sorting & Filtering
        if "selected_entity_filter" not in st.session_state:
            st.session_state.selected_entity_filter = "ALL"

        sort_col1, sort_col2 = st.columns([3, 2])
        default_idx = st.session_state.custom_categories.index(st.session_state.selected_entity_filter) if st.session_state.selected_entity_filter in st.session_state.custom_categories else 0
        selected_entity = sort_col1.selectbox(
            "Sort by Entity", 
            st.session_state.custom_categories, 
            index=default_idx
        )
        st.session_state.selected_entity_filter = selected_entity
        filter_only = sort_col2.checkbox("Filter Only", value=False, help="Only display candidates matching selected entity")

        # Candidates List with Confidence Threshold Filtering & Entity Sorting
        filtered_spans = [s for s in st.session_state.spans if s.confidence >= min_confidence]
        if selected_entity != "ALL":
            if filter_only:
                filtered_spans = [s for s in filtered_spans if s.category.upper() == selected_entity.upper()]
            else:
                filtered_spans = sorted(
                    filtered_spans, 
                    key=lambda s: (0 if s.category.upper() == selected_entity.upper() else 1, s.start_char)
                )
        else:
            filtered_spans = sorted(filtered_spans, key=lambda s: s.start_char)

        st.caption(f"Showing **{len(filtered_spans)}** of {len(st.session_state.spans)} detected candidates")

        for idx, span in enumerate(filtered_spans):
            conf_pct = int(round(span.confidence * 100))
            if span.confidence >= 0.85:
                conf_badge = "🟢"
            elif span.confidence >= 0.60:
                conf_badge = "🟡"
            else:
                conf_badge = "🔴"

            linked_tag = tag_map.get(span.id, "")

            with st.container(border=True):
                r_c1, r_c2, r_c3 = st.columns([1, 4, 2])

                new_accepted = r_c1.checkbox(
                    "Include",
                    value=span.accepted,
                    key=f"chk_{span.id}",
                    label_visibility="collapsed"
                )

                if new_accepted != span.accepted:
                    span.accepted = new_accepted
                    learning_store.record_correction(span.text, span.category, accepted=new_accepted)

                    if span.category == "NAME":
                        for other_span in st.session_state.spans:
                            if other_span.category == "NAME" and other_span.id != span.id:
                                if EntityLinker.are_name_variants(span.text, other_span.text):
                                    other_span.accepted = new_accepted
                                    learning_store.record_correction(other_span.text, other_span.category, accepted=new_accepted)
                    st.rerun()

                r_c2.markdown(
                    f"**`{span.text}`** &nbsp; {conf_badge} `{conf_pct}%` "
                    f"<span style='color:#6366f1; font-weight:600; font-size:0.8rem;'>{linked_tag}</span>",
                    unsafe_allow_html=True
                )

                if r_c3.button("All Similar", key=f"sim_{span.id}", help="Redact all occurrences across the document"):
                    redact_all_similar(span.text, span.category)
                    st.rerun()

                cat_col, src_col = st.columns([3, 2])
                cat_idx = config.TARGET_CATEGORIES.index(span.category) if span.category in config.TARGET_CATEGORIES else 0
                new_cat = cat_col.selectbox(
                    "Type",
                    config.TARGET_CATEGORIES,
                    index=cat_idx,
                    key=f"sel_cat_{span.id}",
                    label_visibility="collapsed"
                )
                if new_cat != span.category:
                    span.category = new_cat
                    learning_store.record_correction(span.text, new_cat, accepted=span.accepted)
                    st.rerun()

                src_col.caption(f"Source: `{span.source}`")

        # 3. Export with Verification Gate
        st.divider()
        st.subheader("💾 Export Redacted Document")

        redacted_content, _ = redact_text_with_placeholders(
            st.session_state.doc_data.full_text,
            st.session_state.spans,
            mask_style=mask_style,
            preserve_length=preserve_length
        )
        is_safe, leaked_terms = verify_redacted_text(redacted_content, st.session_state.spans)

        if not is_safe:
            st.error(
                f"🛑 **Export Refused (Verification Gate Triggered):**\n\n"
                f"The tool re-read the sanitized output and discovered residual approved text: `{leaked_terms}`.\n"
                f"Export is blocked until resolved."
            )
        else:
            st.success("✅ **Export Verification Gate Passed:** Re-read audit confirmed 0 approved sensitive strings remain.")

            if st.session_state.doc_data.file_type == "txt":
                st.download_button(
                    label="📥 Download Verified Redacted TXT",
                    data=redacted_content,
                    file_name=f"redacted_{st.session_state.doc_data.filename}",
                    mime="text/plain",
                    use_container_width=True
                )
            else:
                if st.button("🔒 Generate & Verify Redacted PDF", use_container_width=True):
                    with st.spinner("Applying burned-in PDF redaction and performing re-read audit..."):
                        out_path = Path(config.OUTPUT_DIR) / f"redacted_{st.session_state.doc_data.filename}"
                        try:
                            redact_pdf(
                                input_pdf_path=st.session_state.uploaded_tmp_path,
                                output_pdf_path=out_path,
                                spans=st.session_state.spans
                            )
                            with open(out_path, "rb") as f:
                                pdf_bytes = f.read()

                            st.download_button(
                                label="📥 Download Verified Redacted PDF",
                                data=pdf_bytes,
                                file_name=out_path.name,
                                mime="application/pdf",
                                use_container_width=True
                            )
                        except VerificationFailedError as e:
                            st.error(f"🛑 {str(e)}")

else:
    st.info("👆 **Choose an input source above** (Upload File, Select Preset, or Paste Text) to begin interactive redaction.")
