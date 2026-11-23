import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    # 16:9 widescreen
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6] # blank layout

    # Color Palette: Modern Cybersecurity / AI Theme
    BG_DARK = RGBColor(15, 23, 42)       # Slate 900 #0F172A
    CARD_BG = RGBColor(30, 41, 59)       # Slate 800 #1E293B
    CARD_BORDER = RGBColor(51, 65, 85)   # Slate 700 #334155
    ACCENT_CYAN = RGBColor(56, 189, 248) # Sky 400   #38BDF8
    ACCENT_BLUE = RGBColor(96, 165, 250) # Blue 400  #60A5FA
    ACCENT_GREEN = RGBColor(52, 211, 153)# Emerald 400 #34D399
    ACCENT_AMBER = RGBColor(251, 191, 36)# Amber 400 #FBBF24
    ACCENT_RED = RGBColor(248, 113, 113) # Red 400   #F87171
    TEXT_MAIN = RGBColor(248, 250, 252)  # Slate 50  #F8FAFC
    TEXT_MUTED = RGBColor(148, 163, 184) # Slate 400 #94A3B8
    TEXT_SUB = RGBColor(203, 213, 225)   # Slate 300 #CBD5E1

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.color.rgb = BG_DARK
        return bg

    def add_header(slide, slide_num, title, subtitle):
        # Header Box
        header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(1.1))
        tf = header_box.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        
        p_badge = tf.paragraphs[0]
        p_badge.text = f"SLIDE {slide_num}  |  REDACTGUARD : PRIVACY-PRESERVING AI DOCUMENT SYSTEM"
        p_badge.font.size = Pt(10)
        p_badge.font.bold = True
        p_badge.font.color.rgb = ACCENT_CYAN
        p_badge.font.name = "Arial"
        p_badge.space_after = Pt(4)

        p_title = tf.add_paragraph()
        p_title.text = title
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_MAIN
        p_title.font.name = "Arial"
        p_title.space_after = Pt(2)

        p_sub = tf.add_paragraph()
        p_sub.text = subtitle
        p_sub.font.size = Pt(12)
        p_sub.font.color.rgb = TEXT_MUTED
        p_sub.font.name = "Arial"

    # -------------------------------------------------------------
    # SLIDE 1: Problem Statement and Existing Solutions
    # -------------------------------------------------------------
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)
    add_header(s1, "01", "Problem Statement & Limitations of Existing Solutions", 
               "Why traditional redaction fails and why air-gapped document de-identification is critical today")

    # 3 Columns: The Crisis, Existing Tools, Critical Limitations
    cards_data_1 = [
        ("The Core Problem & Context", ACCENT_RED, [
            ("Who it Affects", "Enterprises, healthcare providers, legal firms, government bodies handling sensitive PII (Aadhaar, PAN, SSN, medical vitals, salaries)."),
            ("The High Stakes", "Regulatory compliance (GDPR, HIPAA, India DPDP Act 2023). Unintended PII disclosure triggers catastrophic fines and legal liability."),
            ("Implicit Leak Vectors", "De-identification isn't just masking names; indirect quasi-identifiers ('CFO of Pune firm') and name variants cause re-identification.")
        ]),
        ("Existing Tools & Approaches", ACCENT_AMBER, [
            ("Cloud APIs & Services", "AWS Comprehend, Google Cloud DLP, Microsoft Presidio Cloud. Effective, but require transmitting plaintext confidential docs across the internet."),
            ("PDF Viewer Blackout Bars", "Adobe Acrobat manual black highlighter / black boxes. Cosmetic only; characters remain extractable in underlying raw streams."),
            ("Naive Regex / Dictionary Tools", "Static keyword matchers. High false positive rate (flags invoice numbers, medical codes) and fails on unstructured variations.")
        ]),
        ("Critical Limitations & Gaps", ACCENT_CYAN, [
            ("Privacy & Compliance Gap", "Cloud DLP violates strict air-gapped data residency mandates. Zero telemetry is non-negotiable for defense and health records."),
            ("Superficial Masking", "Visual overlay without underlying glyph excision leads to catastrophic data extraction from the PDF stream."),
            ("Summary Hallucination Leaks", "Feeding confidential docs to generative LLMs leaks confidential data into summaries or LLM training logs.")
        ])
    ]

    left_margin = Inches(0.8)
    col_width = Inches(3.64)
    col_gap = Inches(0.4)
    top_pos = Inches(1.65)
    card_height = Inches(5.35)

    for i, (title, accent_col, bullet_tuples) in enumerate(cards_data_1):
        x = left_margin + i * (col_width + col_gap)
        card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top_pos, col_width, card_height)
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = CARD_BORDER
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = Inches(0.25)
        tf.margin_bottom = Inches(0.2)

        # Header
        p_hdr = tf.paragraphs[0]
        p_hdr.text = title.upper()
        p_hdr.font.size = Pt(13)
        p_hdr.font.bold = True
        p_hdr.font.color.rgb = accent_col
        p_hdr.font.name = "Arial"
        p_hdr.space_after = Pt(14)

        for b_title, b_desc in bullet_tuples:
            p_bt = tf.add_paragraph()
            p_bt.text = f"• {b_title}"
            p_bt.font.size = Pt(11)
            p_bt.font.bold = True
            p_bt.font.color.rgb = TEXT_MAIN
            p_bt.font.name = "Arial"
            p_bt.space_after = Pt(2)

            p_bd = tf.add_paragraph()
            p_bd.text = f"   {b_desc}"
            p_bd.font.size = Pt(10)
            p_bd.font.color.rgb = TEXT_SUB
            p_bd.font.name = "Arial"
            p_bd.space_after = Pt(10)

    s1_notes = (
        "Slide 1 Speaker Notes:\n"
        "- Hook: Document sanitization is currently broken. Organizations either leak confidential PII to cloud DLP APIs, "
        "or use cosmetic black bars that anyone can highlight and copy from the PDF stream.\n"
        "- Emphasize Problem: Highlight India DPDP Act 2023, HIPAA, and GDPR penalties. "
        "Mention who is impacted: HR teams sharing resumes, legal teams sharing discovery contracts, hospitals sharing case studies.\n"
        "- Explain Gaps: Detail how naive regex fails on Indian IDs and context, how cloud APIs breach data sovereignty, "
        "and how LLMs hallucinate leaked PII during summarization."
    )
    s1.notes_slide.notes_text_frame.text = s1_notes

    # -------------------------------------------------------------
    # SLIDE 2: Proposed Solution
    # -------------------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "02", "Proposed Solution: RedactGuard Architecture", 
               "An intelligent, air-gapped document de-identification & leak-free summarization platform")

    # 4 Feature Cards Layout: 2x2 Grid or Left Highlight + Right Columns
    # Let's do: Left Panel (Workflow & Core Concept) + Right Top/Bottom Cards (Key Differentiators)
    left_w = Inches(4.5)
    card_l = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.65), left_w, Inches(5.35))
    card_l.fill.solid()
    card_l.fill.fore_color.rgb = CARD_BG
    card_l.line.color.rgb = ACCENT_CYAN
    card_l.line.width = Pt(1.5)

    tf_l = card_l.text_frame
    tf_l.word_wrap = True
    tf_l.margin_left = tf_l.margin_right = tf_l.margin_top = Inches(0.25)
    tf_l.margin_bottom = Inches(0.2)

    p0 = tf_l.paragraphs[0]
    p0.text = "WHAT WE ARE BUILDING"
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = ACCENT_CYAN
    p0.font.name = "Arial"
    p0.space_after = Pt(8)

    p_desc = tf_l.add_paragraph()
    p_desc.text = "RedactGuard is a 100% offline, privacy-preserving document de-identification and safe summarization engine running locally on CPU with zero telemetry."
    p_desc.font.size = Pt(10.5)
    p_desc.font.color.rgb = TEXT_SUB
    p_desc.font.name = "Arial"
    p_desc.space_after = Pt(14)

    p_wf = tf_l.add_paragraph()
    p_wf.text = "END-TO-END USER WORKFLOW"
    p_wf.font.size = Pt(12)
    p_wf.font.bold = True
    p_wf.font.color.rgb = ACCENT_BLUE
    p_wf.font.name = "Arial"
    p_wf.space_after = Pt(8)

    steps = [
        ("1. Ingestion", "Upload searchable PDF or raw text. Non-text scans are pre-screened."),
        ("2. Hybrid Detection", "Rules + GLiNER small PII + Checksum validators (Aadhaar Verhoeff, PAN)."),
        ("3. Coreference Linking", "Resolves variants (e.g. 'R. Sharma' ↔ 'Richa Sharma' -> [NAME_1])."),
        ("4. Interactive HITL Review", "Confidence-tiered visual review (🟢≥85%, 🟡60-84%, 🔴<60%) with rapid keyboard shortcuts (A/R/S)."),
        ("5. Dual-Engine Redaction", "Excision of PDF glyphs & metadata; dual verification before export.")
    ]
    for s_title, s_sub in steps:
        p_st = tf_l.add_paragraph()
        p_st.text = f"• {s_title}: {s_sub}"
        p_st.font.size = Pt(10)
        p_st.font.color.rgb = TEXT_MAIN
        p_st.font.name = "Arial"
        p_st.space_after = Pt(6)

    # Right Side: 3 Horizontal Cards for Differentiators
    right_x = Inches(5.6)
    right_w = Inches(6.933)
    diff_cards = [
        ("True Glyph Excision vs. Cosmetic Overlay", ACCENT_GREEN,
         "Standard tools draw black rectangles over text while leaving character bytecode intact. RedactGuard excises character streams, purges XML metadata & embedded files, and applies fitz.PDF_REDACT_IMAGE_PIXELS compaction."),
        ("Dual-Engine Independent Verification Gate", ACCENT_AMBER,
         "Before serving any redacted PDF download, two separate engines (PyMuPDF + raw Python zlib stream decompressor with NFKD normalization) inspect the file. If even one byte of residual PII exists, the file is instantly deleted from disk."),
        ("Quasi-Identifier Shield & Structurally Isolated Summaries", ACCENT_CYAN,
         "Detects subtle re-identification clues ('CFO of Pune firm') with 1-click generalization. LLM summarizer receives ONLY pre-masked structural placeholders ([NAME_1]) followed by a 4-layer leak interceptor.")
    ]
    diff_h = Inches(1.65)
    for i, (d_title, d_accent, d_desc) in enumerate(diff_cards):
        y = Inches(1.65) + i * (diff_h + Inches(0.2))
        card_r = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, right_x, y, right_w, diff_h)
        card_r.fill.solid()
        card_r.fill.fore_color.rgb = CARD_BG
        card_r.line.color.rgb = CARD_BORDER
        card_r.line.width = Pt(1.5)

        tf_r = card_r.text_frame
        tf_r.word_wrap = True
        tf_r.margin_left = tf_r.margin_right = Inches(0.25)
        tf_r.margin_top = Inches(0.18)
        tf_r.margin_bottom = Inches(0.15)

        p_t = tf_r.paragraphs[0]
        p_t.text = d_title.upper()
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = d_accent
        p_t.font.name = "Arial"
        p_t.space_after = Pt(4)

        p_b = tf_r.add_paragraph()
        p_b.text = d_desc
        p_b.font.size = Pt(9.5)
        p_b.font.color.rgb = TEXT_SUB
        p_b.font.name = "Arial"

    s2_notes = (
        "Slide 2 Speaker Notes:\n"
        "- Present the 3 Pillars: Hybrid Detection, Human-in-the-Loop Velocity, and Cryptographic Security.\n"
        "- Walkthrough Workflow: User uploads document -> GLiNER & Presidio patterns find candidate entities -> "
        "EntityLinker clusters name variants to maintain document coherence -> User rapidly reviews via keyboard shortcuts (A/R/S) -> "
        "Dual-engine verification guarantees 0 residual leaks.\n"
        "- Contrast with Competition: Emphasize that unlike Adobe Acrobat, we destroy the underlying glyphs. "
        "Unlike cloud LLMs, our summarizer never sees sensitive tokens."
    )
    s2.notes_slide.notes_text_frame.text = s2_notes

    # -------------------------------------------------------------
    # SLIDE 3: Tech Stack
    # -------------------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "03", "Technical Stack & Architectural Decisions", 
               "Carefully selected, lightweight, local-first technologies optimized for security, latency, and CPU execution")

    # 4 Category Cards across the screen
    stack_categories = [
        ("AI / ML & NLP Pipeline", ACCENT_CYAN, [
            ("GLiNER Small PII", "Zero-shot bidirectional transformer NER; high accuracy for names & organizations without full LLM overhead."),
            ("Presidio-Style Pattern Engine", "Deterministic regex recognizers for high-speed pattern matching (phones, emails, IDs)."),
            ("Algorithmic Checksums", "Verhoeff algorithm (Aadhaar), PAN 4th-char status checks, and non-PII boundary filters."),
            ("Optional Local SLM", "Ollama (Llama 3.2 1B / Qwen 2.5 1.5B) for offline generative summarization.")
        ]),
        ("Backend & Ingestion Engine", ACCENT_BLUE, [
            ("FastAPI & Uvicorn", "High-throughput asynchronous REST API for rapid response & clean modular routing."),
            ("PyMuPDF (fitz)", "Ultra-fast PDF text extraction, coordinate bounding-box mapping, and true glyph excision."),
            ("Pydantic v2", "Strict request/response schema validation and type safety across all endpoints."),
            ("Automated TTL Cleanup", "Background routine purges all temporary files older than 30 mins.")
        ]),
        ("Security, Storage & Audit", ACCENT_GREEN, [
            ("AES-128 Fernet Encryption", "Active learning store & audit logs encrypted at rest; zero plaintext PII on disk."),
            ("Keyed HMAC-SHA256 Masking", "Session-ephemeral salt prevents rainbow table inversion on hashed tokens."),
            ("Dual Verification Engine", "Custom raw zlib stream parser independent of PyMuPDF ensures zero PII leakage."),
            ("1-Click Data Purge", "Immediate in-memory and disk eradication of learned patterns upon user request.")
        ]),
        ("Frontend & User Experience", ACCENT_AMBER, [
            ("Vanilla JS & HTML5 UI", "100% self-contained frontend with ZERO external CDNs, Google Fonts, or telemetry."),
            ("Streamlit Dashboard", "Interactive data science dashboard for benchmarking, inspections, and analytics."),
            ("Dual-Panel HITL UI", "Side-by-side original vs sanitized comparison with visual confidence banding."),
            ("Keyboard Accelerator", "Single-key shortcuts (A/R/S/N/P) for enterprise high-speed review workflows.")
        ])
    ]

    card_w3 = Inches(2.78)
    card_gap3 = Inches(0.2)
    left_m3 = Inches(0.8)

    for i, (cat_title, cat_accent, tech_items) in enumerate(stack_categories):
        x = left_m3 + i * (card_w3 + card_gap3)
        card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top_pos, card_w3, card_height)
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = CARD_BORDER
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = Inches(0.18)
        tf.margin_top = Inches(0.22)
        tf.margin_bottom = Inches(0.15)

        p_h = tf.paragraphs[0]
        p_h.text = cat_title.upper()
        p_h.font.size = Pt(11.5)
        p_h.font.bold = True
        p_h.font.color.rgb = cat_accent
        p_h.font.name = "Arial"
        p_h.space_after = Pt(12)

        for t_name, t_reason in tech_items:
            p_tn = tf.add_paragraph()
            p_tn.text = f"• {t_name}"
            p_tn.font.size = Pt(10)
            p_tn.font.bold = True
            p_tn.font.color.rgb = TEXT_MAIN
            p_tn.font.name = "Arial"
            p_tn.space_after = Pt(2)

            p_tr = tf.add_paragraph()
            p_tr.text = f"   {t_reason}"
            p_tr.font.size = Pt(9)
            p_tr.font.color.rgb = TEXT_SUB
            p_tr.font.name = "Arial"
            p_tr.space_after = Pt(8)

    # Bottom Callout banner: Why Local SLM / Small Models?
    # Actually card_height of 5.35 already fills nicely!
    s3_notes = (
        "Slide 3 Speaker Notes:\n"
        "- Justify Architectural Decisions:\n"
        "  1. Why GLiNER & Small SLM? Eliminates expensive GPU requirements; runs on standard commodity laptops in 2.9 milliseconds per doc with under 0.4MB peak memory.\n"
        "  2. Why Dual-Engine PDF Verification? Never trust a single library when security is on the line. We use PyMuPDF AND our own pure-Python byte-level stream decompressor.\n"
        "  3. Why Fernet AES-128 at rest? Even if the host machine is compromised, the active learning dictionary cannot be inspected without the ephemeral security key.\n"
        "  4. Why Zero-CDN Vanilla JS? To guarantee true air-gapped security. Zero HTTP requests escape the machine."
    )
    s3.notes_slide.notes_text_frame.text = s3_notes

    # -------------------------------------------------------------
    # SLIDE 4: Architecture Diagram & Data Flow
    # -------------------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "04", "System Architecture & Security Flow", 
               "End-to-end data processing pipeline from ingestion to cryptographic verification")

    # 5 Sequential Pipeline Stages across the top/middle + Security/Feedback Loops below
    stages = [
        ("1. INGESTION", ACCENT_BLUE, [
            "Searchable PDF / TXT",
            "Coordinate Extractor",
            "Scanned PDF Gatekeeper",
            "(Rejects Non-Text Scans)"
        ]),
        ("2. DETECTION", ACCENT_CYAN, [
            "Presidio Regex Engine",
            "GLiNER Zero-Shot Model",
            "Verhoeff / PAN Checks",
            "Non-PII Boundary Filter"
        ]),
        ("3. LINKING", ACCENT_AMBER, [
            "EntityLinker Coreference",
            "First/Last/Initial Align",
            "Surname Ambiguity Guard",
            "Unified Tag Mapping"
        ]),
        ("4. HITL REVIEW", ACCENT_GREEN, [
            "Dual-Panel Visual UI",
            "Confidence Bands (G/Y/R)",
            "Keyboard Navigation",
            "AES Encrypted Learning"
        ]),
        ("5. REDACTION", ACCENT_RED, [
            "True Glyph Excision",
            "Dual Verification Gate",
            "NFKD Text Normalizer",
            "Zero Residual Leak Export"
        ])
    ]

    pipe_w = Inches(2.18)
    pipe_gap = Inches(0.2)
    left_m4 = Inches(0.8)
    pipe_h = Inches(2.8)
    top_pipe = Inches(1.65)

    for i, (st_name, st_col, st_points) in enumerate(stages):
        x = left_m4 + i * (pipe_w + pipe_gap)
        box = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top_pipe, pipe_w, pipe_h)
        box.fill.solid()
        box.fill.fore_color.rgb = CARD_BG
        box.line.color.rgb = st_col
        box.line.width = Pt(1.5)

        tf = box.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = Inches(0.15)
        tf.margin_top = Inches(0.18)
        tf.margin_bottom = Inches(0.1)

        p_h = tf.paragraphs[0]
        p_h.text = st_name
        p_h.font.size = Pt(11)
        p_h.font.bold = True
        p_h.font.color.rgb = st_col
        p_h.font.name = "Arial"
        p_h.space_after = Pt(8)

        for pt in st_points:
            p_p = tf.add_paragraph()
            p_p.text = f"• {pt}"
            p_p.font.size = Pt(9)
            p_p.font.color.rgb = TEXT_MAIN
            p_p.font.name = "Arial"
            p_p.space_after = Pt(4)

        # Draw arrow to next stage if not last
        if i < len(stages) - 1:
            arrow_x = x + pipe_w + Inches(0.04)
            arrow_y = top_pipe + Inches(1.2)
            arr = s4.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, arrow_x, arrow_y, Inches(0.12), Inches(0.2))
            arr.fill.solid()
            arr.fill.fore_color.rgb = ACCENT_CYAN
            arr.line.fill.background()

    # Bottom Two System Modules: (A) Active Learning Feedback Loop & (B) Dual-Engine Verification Gate
    bot_y = Inches(4.7)
    bot_h = Inches(2.3)
    bot_w = Inches(5.76)

    # Box A: Active Learning & Privacy Feedback Loop
    box_a = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_m4, bot_y, bot_w, bot_h)
    box_a.fill.solid()
    box_a.fill.fore_color.rgb = CARD_BG
    box_a.line.color.rgb = CARD_BORDER
    box_a.line.width = Pt(1.5)

    tf_a = box_a.text_frame
    tf_a.word_wrap = True
    tf_a.margin_left = tf_a.margin_right = Inches(0.2)
    tf_a.margin_top = Inches(0.18)
    tf_a.margin_bottom = Inches(0.15)

    pa_h = tf_a.paragraphs[0]
    pa_h.text = "🔄 ACTIVE LEARNING & FEEDBACK LOOP"
    pa_h.font.size = Pt(11)
    pa_h.font.bold = True
    pa_h.font.color.rgb = ACCENT_GREEN
    pa_h.font.name = "Arial"
    pa_h.space_after = Pt(6)

    pa_desc = [
        "Human Approval / Rejection: Immediate update to local runtime memory.",
        "Encrypted Persistence: Learned dictionary saved via AES-128 Fernet key.",
        "Privacy Protection: Zero plaintext sensitive terms stored on disk.",
        "Instant Revocation: 1-click purge button immediately wipes all learning memory."
    ]
    for d in pa_desc:
        p_d = tf_a.add_paragraph()
        p_d.text = f"• {d}"
        p_d.font.size = Pt(9.5)
        p_d.font.color.rgb = TEXT_SUB
        p_d.font.name = "Arial"
        p_d.space_after = Pt(3)

    # Box B: Dual-Engine Verification Gate & Leak Interceptor
    box_b = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_m4 + bot_w + Inches(0.2), bot_y, bot_w, bot_h)
    box_b.fill.solid()
    box_b.fill.fore_color.rgb = CARD_BG
    box_b.line.color.rgb = CARD_BORDER
    box_b.line.width = Pt(1.5)

    tf_b = box_b.text_frame
    tf_b.word_wrap = True
    tf_b.margin_left = tf_b.margin_right = Inches(0.2)
    tf_b.margin_top = Inches(0.18)
    tf_b.margin_bottom = Inches(0.15)

    pb_h = tf_b.paragraphs[0]
    pb_h.text = "🛡️ DUAL-ENGINE VERIFICATION GATE & LEAK INTERCEPTOR"
    pb_h.font.size = Pt(11)
    pb_h.font.bold = True
    pb_h.font.color.rgb = ACCENT_RED
    pb_h.font.name = "Arial"
    pb_h.space_after = Pt(6)

    pb_desc = [
        "Engine 1: PyMuPDF rendered page text extraction.",
        "Engine 2: Pure-Python raw PDF FlateDecode stream decompressor.",
        "NFKD Text Normalization: Uncovers spaced, kerned, or hidden bytecode tokens.",
        "Zero-Tolerance Fail-Safe: If PII detected, export is aborted & wiped instantly."
    ]
    for d in pb_desc:
        p_d = tf_b.add_paragraph()
        p_d.text = f"• {d}"
        p_d.font.size = Pt(9.5)
        p_d.font.color.rgb = TEXT_SUB
        p_d.font.name = "Arial"
        p_d.space_after = Pt(3)

    s4_notes = (
        "Slide 4 Speaker Notes:\n"
        "- Architecture Flow Walkthrough:\n"
        "  1. Ingestion: Filter out unscannable documents gracefully.\n"
        "  2. Hybrid Detection: Combine precision regex checksums with recall-oriented GLiNER.\n"
        "  3. Coreference: Unify name occurrences to prevent context loss.\n"
        "  4. HITL Review: Put the human operator in the driver's seat with confidence banding.\n"
        "  5. Dual Verification: Stress that RedactGuard uses an independent second verification engine. "
        "Even if PyMuPDF has a bug, the raw zlib decompressor will catch any leftover sensitive strings!"
    )
    s4.notes_slide.notes_text_frame.text = s4_notes

    # -------------------------------------------------------------
    # SLIDE 5: Impact (Social, Economic, Technical)
    # -------------------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "05", "Demonstrated Impact & Performance Evaluation", 
               "Quantifiable real-world benefits across social privacy, economic savings, and technical benchmarks")

    # Top Metric Banners: 96.39% F1 | 0.0029s Latency | 0.40MB RAM | 0 Leak Exports
    metrics = [
        ("96.39%", "COMBINED F1 SCORE", "96.00% Prec. / 96.77% Rec.", ACCENT_GREEN),
        ("0.0029s", "PROCESSING SPEED", "Sub-3ms per document", ACCENT_CYAN),
        ("0.40 MB", "PEAK MEMORY FOOTPRINT", "Runs on any laptop CPU", ACCENT_BLUE),
        ("0 LEAKS", "RESIDUAL PII EXPORTS", "100% verified across all tests", ACCENT_AMBER)
    ]
    m_w = Inches(2.78)
    m_h = Inches(1.15)
    m_gap = Inches(0.2)
    m_top = Inches(1.65)

    for i, (val, label, subtext, color) in enumerate(metrics):
        x = Inches(0.8) + i * (m_w + m_gap)
        m_box = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, m_top, m_w, m_h)
        m_box.fill.solid()
        m_box.fill.fore_color.rgb = CARD_BG
        m_box.line.color.rgb = color
        m_box.line.width = Pt(1.5)

        tf = m_box.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = Inches(0.15)
        tf.margin_top = Inches(0.12)
        tf.margin_bottom = Inches(0.08)

        p_v = tf.paragraphs[0]
        p_v.text = val
        p_v.font.size = Pt(20)
        p_v.font.bold = True
        p_v.font.color.rgb = color
        p_v.font.name = "Arial"
        p_v.alignment = PP_ALIGN.CENTER

        p_l = tf.add_paragraph()
        p_l.text = label
        p_l.font.size = Pt(8.5)
        p_l.font.bold = True
        p_l.font.color.rgb = TEXT_MAIN
        p_l.font.name = "Arial"
        p_l.alignment = PP_ALIGN.CENTER

        p_s = tf.add_paragraph()
        p_s.text = subtext
        p_s.font.size = Pt(8)
        p_s.font.color.rgb = TEXT_MUTED
        p_s.font.name = "Arial"
        p_s.alignment = PP_ALIGN.CENTER

    # Bottom 3 Columns: Social Impact, Economic Value, Technical Innovation
    impact_cards = [
        ("Social & Privacy Impact", ACCENT_GREEN, [
            ("Citizen & Patient Dignity", "Protects sensitive patient histories, incident reports, and Aadhaar/PAN records from identity theft and public leaks."),
            ("Legal & Whistleblower Safety", "Allows investigative journalists and legal teams to safely share evidence without compromising confidential sources."),
            ("Guaranteed Data Sovereignty", "Ensures zero citizen data is exported to foreign cloud servers, fully complying with national data protection acts.")
        ]),
        ("Economic & Business Value", ACCENT_AMBER, [
            ("Zero Cloud API Costs", "Eliminates recurring per-page cloud DLP SaaS charges ($0.05 - $0.20 per page). Runs completely free on local hardware."),
            ("10x Review Productivity", "Keyboard-driven batch redaction ('Redact All Similar') accelerates legal discovery and compliance reviews from hours to minutes."),
            ("Regulatory Penalty Shield", "Averts severe financial fines under GDPR (up to €20M or 4% turnover) and India DPDP Act (up to ₹250 Crores per breach).")
        ]),
        ("Technical Innovation", ACCENT_CYAN, [
            ("Hybrid CPU Efficiency", "Delivers 96.39% F1 at 0.0029s latency on plain CPU, defying the assumption that high-accuracy privacy AI requires heavy GPUs."),
            ("Breakthrough Dual Verification", "Pioneers independent raw-stream byte decompression to guarantee true non-recoverable PDF redaction."),
            ("Structural Summary Isolation", "Solves LLM PII hallucinations by isolating summarization to pre-masked entity placeholders.")
        ])
    ]

    card_h5 = Inches(4.0)
    top_pos5 = Inches(3.0)

    for i, (title, accent_col, bullet_tuples) in enumerate(impact_cards):
        x = Inches(0.8) + i * (col_width + col_gap)
        card = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top_pos5, col_width, card_h5)
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = CARD_BORDER
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = Inches(0.2)
        tf.margin_top = Inches(0.2)
        tf.margin_bottom = Inches(0.15)

        p_hdr = tf.paragraphs[0]
        p_hdr.text = title.upper()
        p_hdr.font.size = Pt(12)
        p_hdr.font.bold = True
        p_hdr.font.color.rgb = accent_col
        p_hdr.font.name = "Arial"
        p_hdr.space_after = Pt(10)

        for b_title, b_desc in bullet_tuples:
            p_bt = tf.add_paragraph()
            p_bt.text = f"• {b_title}"
            p_bt.font.size = Pt(10)
            p_bt.font.bold = True
            p_bt.font.color.rgb = TEXT_MAIN
            p_bt.font.name = "Arial"
            p_bt.space_after = Pt(2)

            p_bd = tf.add_paragraph()
            p_bd.text = f"   {b_desc}"
            p_bd.font.size = Pt(9)
            p_bd.font.color.rgb = TEXT_SUB
            p_bd.font.name = "Arial"
            p_bd.space_after = Pt(8)

    s5_notes = (
        "Slide 5 Speaker Notes:\n"
        "- Open with Hard Numbers: Point directly to the top metric cards (96.39% F1, 2.9ms processing latency, zero byte leaks across all benchmark documents).\n"
        "- Social Impact: Frame privacy as a fundamental human right. Protecting victims of harassment, whistleblowers, and medical patients.\n"
        "- Economic Value: Cost reduction—enterprises save thousands of dollars on cloud API subscriptions and eliminate multimillion-dollar regulatory fines.\n"
        "- Conclusion: RedactGuard proves that modern AI doesn't need cloud centralization or GPU supercomputers to achieve enterprise-grade privacy and speed."
    )
    s5.notes_slide.notes_text_frame.text = s5_notes

    output_path = "RedactGuard_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation successfully created at {output_path}")

if __name__ == "__main__":
    create_presentation()
