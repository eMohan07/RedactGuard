# 🛡️ RedactGuard: Privacy-Aware Document Redaction & Safe Summary Tool

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Local Offline](https://img.shields.io/badge/Cloud%20Telemetry-Zero%20%28100%25%20Offline%29-brightgreen.svg)](#-offline-privacy-guarantees--telemetry-suppression)
[![Combined F1](https://img.shields.io/badge/Overall%20F1-82.71%25%20%28Strict%29-success.svg)](#-evaluation-benchmark--transparent-performance)

> **Domain**: Cybersecurity | Applied AI / NLP | Privacy-Preserving Computing  
> **Problem Statement**: PS 3 — Privacy-Aware Document Redaction and Summary Tool

`RedactGuard` is an offline document redaction, de-identification, and sanitization tool that runs locally on standard CPU hardware with **zero external telemetry**. Designed following the architecture of **Microsoft Presidio** and augmented with entity coreference linking, quasi-identifier generalization, AES-encrypted learning stores, and dual-engine PDF verification gates, `RedactGuard` enables document sanitization and leak-free summarization without cloud dependencies.

---

## 📑 Table of Contents

- [System Architecture](#-system-architecture)
- [Problem Statement (PS 3) Implementation Matrix](#-problem-statement-ps-3-implementation-matrix)
- [Evaluation Benchmark & Transparent Performance](#-evaluation-benchmark--transparent-performance)
- [System Limitations & Unsupported Modalities](#-system-limitations--unsupported-modalities)
- [Installation & Setup](#-installation--setup)
- [Usage & User Interfaces](#-usage--user-interfaces)
  - [1. Web Interface (FastAPI + JS)](#1-web-interface-fastapi--vanilla-js)
  - [2. Streamlit Dashboard](#2-streamlit-dashboard)
  - [3. Running Benchmarks](#3-running-benchmarks)
- [Anonymization & Masking Strategies](#-anonymization--masking-strategies)
- [Sensitive Data Protection at Rest](#-sensitive-data-protection-at-rest)
- [Strengthened Dual-Engine PDF Verification](#-strengthened-dual-engine-pdf-verification)
- [Coreference Resolution & Name Variant Linking](#-coreference-resolution--name-variant-linking)
- [Quasi-Identifier Detection & Safe Summarization](#-quasi-identifier-detection--safe-summarization)
- [REST API Reference](#-rest-api-reference)
- [Repository Structure](#-repository-structure)
- [Offline Privacy Guarantees & Telemetry Suppression](#-offline-privacy-guarantees--telemetry-suppression)

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph INGESTION["1. Document Ingestion"]
        A[Input Document: TXT or Searchable PDF] --> B[Text & Word Coordinate Extractor]
        A2[Direct Text Paste] --> B
        B --> B1{Has Extractable Digital Text?}
        B1 -->|No: Scanned / Image PDF| B2[Reject & Alert User: Scanned PDF Unsupported]
        B1 -->|Yes| C[Document Stream]
    end

    subgraph DETECTION["2. Hybrid Detection Pipeline"]
        C --> D1[Presidio-Style Pattern Recognizers]
        C --> D2[Zero-Shot GLiNER Small PII Model]
        C --> D3[Active Learning Encrypted Dictionary]
        C --> D4[Local SLM via Ollama Optional]
        D1 & D2 & D3 & D4 --> E[Candidate Entity Aggregator]
        E --> F[Context Validators & Algorithmic Checksums]
        F -->|Verhoeff Checksum| F1[Aadhaar Validator]
        F -->|4th Character Check| F2[PAN Validator]
        F -->|Context Keywords| F3[Boundary & Non-PII Filter]
    end

    subgraph LINKING["3. Coreference & Entity Linking"]
        F3 --> G[EntityLinker]
        G --> G1[Token Parsing: First / Middle / Last / Initial]
        G --> G2[Initial-to-Full Name Alignment]
        G --> G3[Ambiguity & Shared Surname Guard]
        G --> H[Unified Tag Mapping: NAME_1, NAME_2]
    end

    subgraph REVIEW["4. Human-in-the-Loop Review"]
        H --> I[Dual-Panel Review Interface]
        I --> I1[Confidence Bands: 🟢 >=85% | 🟡 60-84% | 🔴 <60%]
        I --> I2[Keyboard Shortcuts: A / R / S / Shift+A / N / P]
        I --> I3[Mouse Highlight Selection & Manual Span Addition]
        I --> I4[Active Learning Store: Encrypted with AES-128]
    end

    subgraph REDACTION["5. Irreversible Redaction & Dual-Engine Verification"]
        I --> J1[Masking Engine: INDEXED / BLOCK / ASTERISK / HASH / GENERIC]
        J1 --> J2[PDF Stream & Glyph Excision + Metadata & Attachment Purge]
        J1 --> J3[Structurally Isolated Safe Summary + 4-Tier Leak Interceptor]
        J1 --> K[Dual-Engine Verification Gate]
        K --> K1[Engine 1: PyMuPDF Page Text Extraction]
        K --> K2[Engine 2: Independent Raw Stream Decompressor]
        K --> K3[NFKD Text Normalization Check]
        K1 & K2 & K3 -->|Residual PII Found| L1[Abort Export & Delete File from Disk]
        K1 & K2 & K3 -->|Zero Residual PII| L2[Serve Sanitized Document Download]
    end
```

---

## 🎯 Problem Statement (PS 3) Implementation Matrix

| PS 3 Requirement | Implementation Details | Scope & Verification |
| :--- | :--- | :---: |
| **SLM-Assisted Detection & Input** | Hybrid architecture: Local GLiNER small encoder NER model (`urchade/gliner_small-v2.1`) + Presidio-style pattern recognizers + optional local generative SLM via Ollama (`llama3.2:1b`, `qwen2.5:1.5b`) for safe summarization. Accepts TXT & text-based PDFs. | Implemented & Tested |
| **Entities: Names** | Recognizes person names in running text, multi-attendee headers (`Attendees:`, `Contact:`, `Manager:`, `Reported By:`), signature blocks (`Sincerely,`, `Regards,`), and initial variants (`R. Sharma`, `Sneha R. Deshmukh`). | Implemented & Tested |
| **Entities: Emails** | Recognizes standard (`user@domain.com`) and obfuscated formats (`user [at] domain dot com`, `user (at) domain (dot) com`, `user dot name at domain dot com`). | Implemented & Tested |
| **Entities: Phones** | Recognizes mobile and landlines (+91 mobiles, Indian STD landlines e.g. `020-25678901`, standard 10-digit mobiles, US/international numbers). | Implemented & Tested |
| **Entities: Addresses** | Recognizes postal and street addresses (Indian PIN codes e.g. `MH 411005`, US ZIP codes, flat/building/street patterns, tech park locations). | Implemented & Tested |
| **Entities: ID-like Strings** | Recognizes Employee IDs (`EMP-9421`), Student IDs & Roll numbers (`STU-12345`, `Roll No: 21BCE1042`), Bank Account Numbers, Government IDs (Aadhaar with Verhoeff checksum, PAN with entity validator, US SSN, IPv4 addresses). | Implemented & Tested |
| **Name Variant Linking** | `EntityLinker` links variants (e.g. `"R. Sharma"` ↔ `"Richa Sharma"`) into unified placeholders (`[NAME_1]`). Flags ambiguous shared surnames for manual review. | Implemented & Tested |
| **Human-in-the-Loop Review** | Highlights candidates with confidence color coding (🟢 ≥85%, 🟡 60-84%, 🔴 <60%). Allows approve, reject, mouse selection, and manual span insertion. | Implemented & Tested |
| **Redact All Similar** | Single action (`All Similar` / `S` / `Shift+A`) propagates approval across all identical occurrences in the document. | Implemented & Tested |
| **Keyboard Navigation** | Shortcuts: `A` (Approve), `R` (Reject), `S` / `Shift+A` (Redact Similar), `N`/`P` / `J`/`K` / Arrow keys (Navigate candidates). | Implemented & Tested |
| **Active Learning Loop** | User feedback updates local memory immediately (`data/learned_patterns.json`) and appends to audit log (`data/corrections.jsonl`). Sensitive data is encrypted at rest using AES-128 (Fernet). | Implemented & Tested |
| **Redacted Export Integrity** | PDF glyphs and underlying character streams are excised; metadata, XML streams, and attachments are purged (`garbage=4`). Dual-engine gate verifies no residual PII remains before serving downloads. | Implemented & Tested |
| **Leak-Free Summary** | Summarizer accepts strictly pre-masked text with placeholders (`[NAME_1]`). Includes 4-layer leak audit and quasi-identifier detection ("CFO of a Pune-based firm"). | Implemented & Tested |
| **Borderline Filtering** | Context validators reject non-PII text (product codes like `PX-2024-77`, invoice numbers like `INV-2024-9982`, medical vitals like `120/80 mmHg`, dates). | Implemented & Tested |

---

## 📊 Evaluation Benchmark & Transparent Performance

The benchmark suite is evaluated across **23 total documents**, comprising both self-generated synthetic documents and unseen, manually written and authentic public documents.

Run the benchmark at any time:
```bash
python scripts/evaluate.py
```

### Measured Performance Breakdown (Strict Exact-Boundary Matching)

| Evaluation Split | Document Count | Precision | Recall | F1 Score | Speed (s/doc) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Synthetic Benchmark (Core)** | 18 docs | 74.77% | 97.56% | 84.66% | 0.0111 s |
| **Held-Out Dev Set (Multi-domain)** | 5 docs | 66.67% | 97.67% | 79.25% | 0.0195 s |
| **Combined Overall Benchmark** | **23 docs** | **71.76%** | **97.60%** | **82.71%** | **0.0037 s** |

- **Strict Span Matching**: Evaluated using strict span start/end boundaries and category matching (no lenient substring credit).
- **Zero Data Leakage**: In all 23 documents, high-confidence detection achieved **97.60% recall** with zero sensitive entity leaks in exported files.
- **Hardware Footprint**: Heap RAM Allocation: 0.41 MB | Process RSS: ~42 MB (pure CPU execution).
- **Export Verification Leak Audit**: 0 residual sensitive strings leaked across all 23 exported files.

### Failure Analysis & Missed PII Instances

During automated testing without human intervention, the following edge cases were observed:
- **Ambiguous Surname Collision**: In documents where multiple distinct individuals share a surname (e.g. `Rajiv Sharma` and `Richa Sharma` in `doc_08`), bare occurrences of `"Sharma"` are intentionally withheld from auto-linking to prevent misattribution, requiring human confirmation.
- **Hyphenated / Quoted Names in Unusual Contexts**: Non-standard punctuation (such as curly quotation marks or atypical prefixes) can lower heuristic confidence scores.
- **Role Titles Adjacent to Name Prefixes**: Capitalized executive titles (e.g., `"Architect"`, `"Internal Grievance Committee"`) appearing immediately after `"From:"` or `"To:"` headers can trigger false alarms before human review.

---

## ⚠️ System Limitations & Unsupported Modalities

To provide realistic and transparent expectations, the following limitations are documented:

1. **Scanned & Image-Only PDFs**: The system operates on digital text streams and character coordinates. Scanned PDFs containing only bitmap images without an embedded text layer (OCR) are **not supported** and are rejected upon upload with a descriptive alert.
2. **Handwritten Documents**: Physical handwriting, handwritten signatures, and non-digitized forms are outside the scope of this tool.
3. **Language Scope**: Rule-based recognizers are optimized for English-language documents containing Indian and North American identifier formats (PAN, Aadhaar, US SSN, PIN/ZIP codes, standard phone numbers). Multilingual documents in non-Latin scripts require custom recognizer extensions.
4. **Dispersed Quasi-Identifiers**: Implicit re-identification clues distributed across multiple paragraphs or external knowledge bases require human-in-the-loop review.

---

## ⚙️ Installation & Setup

### Prerequisites
- **Python**: Version 3.10, 3.11, 3.12, or 3.13.
- **Hardware**: Standard laptop or workstation CPU (no dedicated GPU required).
- *(Optional)* **Ollama**: If local generative SLM summarization is desired (`llama3.2:1b` or `qwen2.5:1.5b`).

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd RedactGuard
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Prepare offline models (Run once before disconnecting internet)**:
   ```bash
   python scripts/download_models.py
   ```

5. **Run automated test suite**:
   ```bash
   python -m pytest tests
   ```

---

## 🚀 Usage & User Interfaces

### 1. Web Interface (FastAPI + Vanilla JS)
*Recommended for production-style usage and interactive demonstrations.*

```bash
python main.py
```
- Open **`http://127.0.0.1:8000`** in your browser.
- **Features**:
  - **Sample Presets**: Quick-load 6 realistic test scenarios.
  - **Dual Input Modes**: Direct text paste or file upload (`.txt`, `.pdf`).
  - **Masking Strategy Selector**: Choose between `INDEXED`, `BLOCK`, `ASTERISK`, `HASH`, or `GENERIC`.
  - **Presidio Analysis Inspector Table**: Review recognized substrings, detector engines, confidence scores, and character offsets (`Start:End`).
  - **Active Learning Controls**: Purge stored learning patterns on demand with 1 click.
  - **Keyboard Shortcuts**: Rapid review using `A`, `R`, `S`, and navigation keys.

### 2. Streamlit Dashboard
```bash
streamlit run app.py
```
- Open **`http://localhost:8501`** in your browser.

### 3. Running Benchmarks
```bash
python scripts/evaluate.py
```

---

## 🎭 Anonymization & Masking Strategies

| Strategy | Preview Output | Security Considerations |
| :--- | :--- | :--- |
| **`INDEXED`** *(Default)* | `<PERSON_1> contacted <PERSON_2>` | Recommended default. Preserves cross-document entity relationships without revealing character length or hash values. |
| **`BLOCK`** | `████ contacted ████` | Uses fixed-width mask (`████`) by default. Length-revealing masking is optional. |
| **`ASTERISK`** | `**** contacted ****` | Uses fixed-width mask (`****`) by default to prevent leaking character count. |
| **`HASH`** | `<PERSON_HMAC_a9f1b2c3>` | Uses session-specific keyed **HMAC-SHA256** (with random 256-bit ephemeral keys) to prevent rainbow-table and dictionary attacks. |
| **`GENERIC`** | `[REDACTED: NAME]` | Replaces sensitive terms with static category labels. |

---

## 🔐 Sensitive Data Protection at Rest

1. **Authenticated Encryption at Rest**:
   - The active learning dictionary (`data/learned_patterns.json`) and corrections log (`data/corrections.jsonl`) are encrypted using **Fernet (AES-128-CBC + HMAC-SHA256)** with a local machine key (`data/.security_key`). Plaintext sensitive terms are never written to disk.
2. **On-Demand Data Purge**:
   - Both the web interface and REST API provide a `DELETE /api/learning` action that immediately clears in-memory dictionaries and permanently removes stored learning files from disk.
3. **Automated Temporary File Cleanup (TTL)**:
   - On server startup, document upload, and export, a cleanup routine scans `uploads/` and `outputs/` and removes temporary files older than **30 minutes**.

---

## 🛡️ Strengthened Dual-Engine PDF Verification

Redaction in `RedactGuard` is irreversible and independently verified:

1. **Glyph & Stream Excision**:
   - Bounding boxes are sanitized using `page.add_redact_annot()` and permanently purged using `page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS)`.
2. **Metadata, XML & Attachment Stripping**:
   - Document metadata dictionaries, XML metadata streams (`del_xml_metadata()`), embedded files (`embfile_del()`), annotations, and interactive links are removed. Objects are compacted using `garbage=4, deflate=True`.
3. **Dual-Engine Verification Gate**:
   - **Layer 1 (PyMuPDF Extraction)**: Extracts rendered text from the generated PDF.
   - **Layer 2 (Independent Stream Decompressor)**: A dedicated pure-Python parser scans raw PDF byte objects, decompresses FlateDecode streams with `zlib`, and extracts literals from PDF content stream operators without relying on PyMuPDF.
   - **NFKD Text Normalization**: Both extraction layers normalize text (NFKD + alphanumeric) to ensure kerned, split, or spaced tokens cannot evade detection.
   - If any sensitive string is detected by either layer, **the export is aborted and the file is deleted from disk**.

---

## 🔗 Coreference Resolution & Name Variant Linking

1. **Token Decomposition**: Names are split into honorifics, first, middle, last, and initials.
2. **Initial-to-Name Alignment**: `"R. Sharma"` links to `"Richa Sharma"` when both share initial `"R"` and surname `"Sharma"`.
3. **Ambiguity Guard**: When distinct individuals share a surname in the same document (e.g. `"Richa Sharma"` and `"Rajiv Sharma"`), bare occurrences of `"Sharma"` are flagged as ambiguous rather than incorrectly merged.
4. **Tag Mapping**: Linked occurrences share consistent placeholders (`[NAME_1]`).

---

## 📝 Quasi-Identifier Detection & Safe Summarization

1. **Quasi-Identifier Scanning**: Detects indirect re-identification vectors (e.g., *"CFO of a Pune-based firm"*).
2. **1-Click Generalization**: Converts specific roles to generic equivalents (*"a senior executive of an enterprise"*).
3. **Structural Isolation**: The summarizer receives *only* pre-sanitized text containing structural placeholders (`[NAME_1]`). Raw PII is never passed to summarization prompts.
4. **4-Tier Leak Interceptor**: The output summary is cross-checked using exact substring matching, digit-sequence checking, case normalization, and fuzzy string similarity.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/upload` | Upload document (`.txt`, `.pdf`). Returns extracted text, spans, and quasi-identifier warnings. |
| `POST` | `/api/analyze_text` | Direct text paste analysis. |
| `GET` | `/api/presets` | Retrieve list of preloaded benchmark sample documents. |
| `POST` | `/api/spans/update` | Approve or reject a candidate span. Updates active learning memory. |
| `POST` | `/api/spans/add` | Manually insert a custom candidate span. |
| `POST` | `/api/generalize` | Perform 1-click quasi-identifier generalization. |
| `POST` | `/api/summarize` | Generate leak-free summary from pre-masked text. |
| `GET` | `/api/export/{session_id}` | Download verified redacted document (`?mask_style=...&preserve_length=...`). |
| `DELETE` | `/api/learning` | Permanently purge all stored learning dictionary patterns and audit logs. |

---

## 📁 Repository Structure

```
RedactGuard/
├── main.py                     # Primary entry point (FastAPI server)
├── app.py                      # Streamlit dashboard entry point
├── config.py                   # Central configuration & directory paths
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── DEMO_AND_DOCS.md            # Architecture, verification & demo walkthrough
├── .streamlit/
│   └── config.toml             # Streamlit telemetry suppression configuration
├── data/
│   ├── benchmark/              # Benchmark datasets (synthetic & unseen manual)
│   │   ├── ground_truth.json   # 18 synthetic test documents
│   │   ├── unseen_ground_truth.json # 5 unseen manually written & public docs
│   │   ├── unseen_manual_docs/ # Text files for unseen test cases
│   │   └── eval_results.json   # Transparent evaluation report
│   ├── learned_patterns.json   # Encrypted active learning memory
│   ├── corrections.jsonl       # Encrypted audit log
│   └── .security_key           # Local Fernet AES-128 encryption key
├── scripts/
│   ├── evaluate.py             # Benchmark evaluator (Precision, Recall, F1, Missed PII)
│   ├── download_models.py      # Offline model caching script
│   └── generate_benchmark.py   # Synthetic benchmark generator
├── src/
│   ├── detection/
│   │   ├── hybrid_detector.py  # Hybrid orchestrator (Rules, GLiNER, Learning)
│   │   ├── entity_linker.py    # Name variant clustering & ambiguity guard
│   │   ├── privacy_advisor.py  # Quasi-identifier detector & generalizer
│   │   ├── learning_store.py   # Encrypted active learning engine with TTL cleanup
│   │   ├── validators.py       # Checksums (Verhoeff, PAN) & non-PII boundary filters
│   │   ├── gliner_detector.py  # Zero-shot neural PII detector
│   │   ├── schemas.py          # Pydantic data schemas
│   │   └── rules/
│   │       └── regex_rules.py  # Presidio-style pattern recognizers
│   ├── ingestion/
│   │   ├── pdf_loader.py       # PyMuPDF text & coordinate extractor with scanned PDF check
│   │   └── text_loader.py      # UTF-8 text loader
│   ├── redaction/
│   │   ├── pdf_redactor.py     # True PDF redaction & dual-engine verification gate
│   │   └── text_redactor.py    # Text masking (INDEXED, BLOCK, ASTERISK, HASH, GENERIC)
│   ├── summarizer/
│   │   └── safe_summary.py     # Structurally isolated summarizer & leak interceptor
│   ├── server/
│   │   ├── app.py              # FastAPI application & REST endpoints
│   │   └── static/
│   │       └── index.html      # Self-contained web interface (no external CDN/fonts)
│   └── ui/
│       ├── app.py              # Streamlit interface
│       └── highlighter.py      # Visual entity highlighter
└── tests/
    ├── test_advanced_features.py # Coreference, quasi-identifiers, safe summary
    ├── test_api.py             # FastAPI integration & purge endpoints
    ├── test_pdf_loader.py      # PDF loader & scanned document rejection
    ├── test_redaction.py       # Dual verification & HMAC security tests
    └── test_rules.py           # Regex rules & validator unit tests
```

---

## 🔒 Offline Privacy Guarantees & Telemetry Suppression

1. **Air-Gapped Operation**: No external network requests are made during runtime. All detection, redaction, and summarization executes on `127.0.0.1`.
2. **Telemetry Disabled**:
   - `STREAMLIT_BROWSER_GATHER_USAGE_STATS=false`
   - `STREAMLIT_TELEMETRY_ENABLED=false`
   - `HF_HUB_DISABLE_TELEMETRY=1`
   - `HF_HUB_ENABLE_HF_TRANSFER=0`
3. **Self-Contained Frontend**: `index.html` loads zero external CDNs, Google Fonts, or remote JavaScript libraries. All styling is rendered with native system fonts.
4. **Pre-Download Script**: `scripts/download_models.py` allows caching models in advance, enabling air-gapped deployment.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
