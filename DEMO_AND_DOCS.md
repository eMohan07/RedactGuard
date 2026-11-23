# 🛡️ Architecture, Verification & Demo Guide

## 1. Approach & Overview
This local document privacy tool is architected to run completely offline on a standard laptop with zero cloud telemetry. It combines machine learning with deterministic validators, enforces irreversible redaction on text and PDFs, and prevents data leakage through structural verification gates.

---

## 2. Models & Technologies
- **Local PII Token Classification**: GLiNER small (`urchade/gliner_small-v2.1`, ~150MB parameters), a lightweight zero-shot bidirectional transformer.
- **Pattern Recognizers**: Presidio-style regex recognizers equipped with surrounding context keyword evaluation and deterministic checksum algorithms (Verhoeff for Aadhaar, entity-type regex for PAN, digit counts for Indian landline & mobile phones).
- **Coreference & Name Linking**: Plain Python + RapidFuzz (token sort ratio & initial parsing) with multi-person surname collision detection.
- **Local Summarization**: Small Language Model (SLM) via Ollama (`llama3.2:1b` or `qwen2.5:1.5b`, ~1.3GB), receiving strictly masked text.
- **Document Engine**: PyMuPDF (`fitz`) for word-level coordinate tracking, bounding box mapping, and stream-purging redaction (`garbage=4`).
- **Web Interface**: FastAPI + Vanilla HTML/CSS/JavaScript with keyboard listeners and native browser text selection.

---

## 3. How Names Are Linked & Disambiguated
1. **Token Parsing**: Names are parsed into `first`, `middle`, `last`, and `initial` components while stripping honorifics (`Dr.`, `Mr.`, `Ms.`).
2. **Initial + Surname Alignment**: `"R. Sharma"` links to `"Richa Sharma"` when both share initial `"R"` and surname `"Sharma"`.
3. **Collision / Ambiguity Safeguard**: If two distinct individuals share a surname in the same document (e.g. `"Richa Sharma"` and `"Rajiv Sharma"`), a bare token `"Sharma"` is **not** auto-linked. Instead, it is flagged as ambiguous for the user to resolve manually.
4. **Unified Entity Tagging**: All resolved members of a cluster are assigned matching placeholders (`[NAME_1]`).

---

## 4. How the Safe Summary & Export are Audited
1. **Structural Isolation**: The summarizer function accepts *only* the sanitized text with placeholders (`[NAME_1]`, `[EMAIL_1]`). It has no access to original text.
2. **Multi-Layer Summary Audit**: The output summary is cross-checked against every removed sensitive string via:
   - Case-insensitive substring match
   - Digit-sequence comparison (protects phone numbers and IDs)
   - RapidFuzz similarity scoring (catches near-misses and spelling variants)
   - Any leak is automatically purged before display.
3. **Export Verification Gate**: After writing the redacted TXT or PDF, the tool re-opens the output from disk and re-extracts all text. If any approved sensitive string remains, the tool **aborts the export and purges the file**.

---

## 5. Step-by-Step Demo Walkthrough
1. **Launch App**: Run `python main.py`. The browser automatically opens to `http://127.0.0.1:8000`.
2. **Upload Test Document**: Upload `data/benchmark/doc_10_consulting_agreement.txt` or `samples/sample_input.txt`.
3. **Observe In-Place Highlights**:
   - High confidence (🟢 Green), Medium (🟡 Yellow), Low (🔴 Red).
   - Linked name variants share matching `[NAME_1]` tags.
4. **Review Quasi-Identifier Warning**:
   - Notice the amber warning: *"The patient serves as the CFO of a Pune-based firm"*.
   - Click **`🔄 Generalize`** to convert it to *"a senior executive of an enterprise"*.
5. **Use Keyboard Shortcuts**:
   - Press `N` / `P` to navigate candidates.
   - Press `A` to approve, `R` to reject.
   - Press `S` or `Shift+A` to redact all similar occurrences.
6. **Select Text to Redact**: Highlight any custom phrase in the viewer with your mouse and click `+ Redact Selection`.
7. **Generate Safe Summary**: Click **`📝 Safe Summary`** to receive an executive overview with automated leak audit.
8. **Export Verified Copy**: Click **`💾 Export Verified`**. The verification gate confirms zero residual sensitive text and serves the clean redacted file.
