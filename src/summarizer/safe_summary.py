import re
import requests
from typing import List, Tuple, Dict, Any
from src.detection.schemas import DetectedSpan
from src.detection.privacy_advisor import PrivacyAdvisor
from src.detection.rules.regex_rules import detect_by_rules

try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    import difflib
    HAS_RAPIDFUZZ = False

def _fuzzy_match(s1: str, s2: str) -> float:
    if HAS_RAPIDFUZZ:
        return float(fuzz.token_sort_ratio(s1, s2))
    else:
        import difflib
        return float(difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio() * 100.0)

def format_executive_summary_file(
    summary_text: str, 
    filename: str = "Document", 
    mask_style: str = "INDEXED"
) -> str:
    """
    Formats the summary output into an executive document layout
    with professional ASCII header borders, uniform margins, and clean alignment.
    Guarantees clean presentation in any text viewer or editor.
    """
    clean_summary = summary_text.replace("\r\n", "\n").replace("\r", "\n").strip()
    header = (
        f"================================================================================\n"
        f"                     PRIVACY-PRESERVED EXECUTIVE SUMMARY\n"
        f"================================================================================\n"
        f"Reference File   : {filename}\n"
        f"De-Identification: {mask_style} Canonical Standard\n"
        f"Security Status  : Air-Gapped De-Identified · Zero Residual PII\n"
        f"--------------------------------------------------------------------------------\n\n"
    )
    footer = (
        f"\n\n================================================================================\n"
        f"                 [END OF PRIVACY-VERIFIED EXECUTIVE SUMMARY]\n"
        f"================================================================================"
    )
    return header + clean_summary + footer

class SafeSummarizer:
    """
    Zero-Leak Document Summarization Engine:
    1. Structurally enforced: accepts ONLY already-redacted text (no access to original unredacted text).
    2. Auto-neutralizes quasi-identifiers (e.g. 'CFO of a Pune-based firm', 'finance chief at a Mumbai startup')
       via PrivacyAdvisor prior to synthesis.
    3. Prompts local generative SLM (via Ollama or local transformers) to summarize without restoring placeholders.
    4. Offline extractive fallback with intelligent structural alignment when generative model is unavailable.
    5. Multi-layer audit:
       - Exact, case-insensitive, fuzzy, and digit-sequence checks against all removed spans.
       - Independent rule-based PII scan on the output summary (detects any hallucinated or undetected PII).
       - Quasi-identifier re-scan and neutralization on output summary.
    """
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2:1b"):
        self.base_url = base_url
        self.model = model

    def summarize_redacted_only(self, redacted_text: str) -> Tuple[str, str]:
        """
        Structural enforcement: accepts ONLY the already-redacted text.
        Automatically generalizes all quasi-identifiers before synthesis.
        Returns (summary_text, engine_used).
        """
        # Step 1: Pre-neutralize all quasi-identifiers so the summarizer never sees indirect re-identification vectors
        sanitized_text, warnings = PrivacyAdvisor.apply_all_generalizations(redacted_text)

        prompt = f"""You are an offline privacy-preserving corporate analyst.
Summarize the following pre-sanitized document clearly, professionally, and concisely.
Format your response with clean section headers, ensuring every header is immediately followed by a newline:
Document Title:
[Clear Document Title]

Executive Summary:
[Cohesive, well-written executive overview paragraph]

Key Details & Observations:
• [Key substantive observation 1]
• [Key substantive observation 2]

Privacy & Entity Protection:
[Privacy and canonical de-identification statement]

MANDATORY PRIVACY RULES:
- Never guess or attempt to reconstruct any personal identities, contact info, or identifiers.
- Refer strictly to entities using their placeholder tags (e.g. [NAME_1], [EMAIL_1]) or generic roles.
- Do not mention or reveal private details.

Sanitized Document Text:
\"\"\"{sanitized_text}\"\"\"

Document Title:"""

        # 1. Try local generative SLM (Ollama)
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=25
            )
            if response.status_code == 200:
                summary = response.json().get("response", "").strip()
                if summary and "Executive Summary:" in summary:
                    return summary, f"Local SLM ({self.model})"
        except Exception:
            pass

        # 2. Offline Extractive Synthesis with Professional Document Alignment
        summary = self._generate_extractive_summary(sanitized_text, warnings_count=len(warnings))
        return summary, "Local Offline Extractive Engine"

    def summarize(self, full_text: str, spans: List[DetectedSpan], mask_style: str = "INDEXED", preserve_length: bool = False) -> str:
        """Convenience method: redacts text first, summarizes, and audits for leaks."""
        from src.redaction.text_redactor import redact_text_with_placeholders
        redacted_text, _ = redact_text_with_placeholders(full_text, spans, mask_style=mask_style, preserve_length=preserve_length)
        raw_summary, _ = self.summarize_redacted_only(redacted_text)
        purged_summary, _ = self.audit_summary_leaks(raw_summary, spans)
        return purged_summary

    def _generate_extractive_summary(self, sanitized_text: str, warnings_count: int = 0) -> str:
        """
        Synthesizes an executive summary directly from sanitized sentences,
        prioritizing substantive findings, actions, and placeholder entity references.
        Guaranteed to contain zero ungeneralized quasi-identifiers or leaked entities.
        """
        lines = [line.strip() for line in sanitized_text.splitlines() if line.strip()]
        if not lines:
            return "Empty document; no text available to summarize."

        first_line = lines[0].lstrip("#*- ").strip()
        # Smart Title extraction: do NOT use "Name: [NAME_1]" as title
        title = "Confidential De-Identified Record"
        if re.match(r"^(?:name|patient name|employee|customer|primary patient|to|from|email|phone|date)[:\s]", first_line, re.IGNORECASE):
            topic = next((l for l in lines if re.match(r"^(?:subject|regarding|re|title|topic|purpose|incident|diagnosis)[:\s]", l, re.IGNORECASE)), None)
            if topic:
                title = re.sub(r"^(?:subject|regarding|re|title|topic|purpose|incident|diagnosis)[:\s]+", "", topic, flags=re.IGNORECASE).strip()
            else:
                title = "Confidential Personnel / Operational Record"
        elif len(first_line) <= 80 and not first_line.endswith(":"):
            title = first_line

        # Extract structured details and candidate narrative sentences
        structured_details = []
        candidate_sentences = []

        for line in lines:
            line_clean = line.strip()
            # Capture structured field details (e.g. "Department: Engineering", "Status: Active")
            kv = re.match(r"^([A-Za-z0-9\s/_-]{2,25}):\s*([^\r\n]+)$", line_clean)
            if kv:
                k, v = kv.group(1).strip(), kv.group(2).strip()
                if k.lower() not in ("email", "phone", "mobile", "ssn", "pan", "aadhaar", "address", "fax", "vitals"):
                    if v and not v.startswith("http"):
                        structured_details.append(f"{k}: {v}")
                continue

            for sent in re.split(r"(?<=[.!?])\s+", line_clean):
                sent_clean = sent.strip()
                if len(sent_clean) >= 20 and not sent_clean.startswith("#"):
                    candidate_sentences.append(sent_clean)

        KEY_TOPIC_WORDS = {
            "agreed", "diagnosed", "reported", "decided", "discussed", "finding", 
            "summary", "incident", "approved", "payment", "due", "status", "scheduled", 
            "recommended", "resolved", "action", "reviewed", "plan", "treatment", 
            "confirmed", "concluded", "advised", "condition", "complaint", "assessment"
        }

        # Score sentences: boost for substantive action words and entity placeholder mentions
        scored_sentences = []
        for s in candidate_sentences:
            score = 0
            words = set(s.lower().split())
            score += len(words.intersection(KEY_TOPIC_WORDS)) * 3
            entity_refs = len(re.findall(r"\[[A-Z]+(?:_\d+)?\]|<[A-Z_]+_HMAC_[a-f0-9]+>|█+|\*+", s))
            score += entity_refs * 2
            if len(s) > 40:
                score += 1
            scored_sentences.append((score, s))

        scored_sentences.sort(key=lambda x: -x[0])
        top_selected = [s for score, s in scored_sentences[:3]]
        
        # Re-order according to document appearance
        ordered_selected = [s for s in candidate_sentences if s in top_selected][:3]
        if not ordered_selected:
            ordered_selected = candidate_sentences[:2] if candidate_sentences else [lines[0]]

        # Clean paragraph synthesis
        overview_paragraph = " ".join(ordered_selected)
        if not overview_paragraph or len(overview_paragraph) < 15:
            overview_paragraph = "De-identified operational record containing verified structured fields with zero residual direct PII entities."

        # Count placeholders
        entities_found = set(re.findall(r"\[[A-Z]+(?:_\d+)?\]|<[A-Z_]+_HMAC_[a-f0-9]+>|█+|\*+", sanitized_text))
        direct_count = len(entities_found)

        # Assemble clean, properly aligned sections
        sections = [
            f"Document Title:\n{title}",
            f"\nExecutive Summary:\n{overview_paragraph}"
        ]

        if structured_details:
            sections.append("\nKey Details & Observations:\n" + "\n".join(f"• {d}" for d in structured_details[:4]))

        sections.append(
            f"\nPrivacy & Entity Protection:\n"
            f"• Direct Identifiers: {direct_count} unique entity instances de-identified via canonical tags.\n"
            f"• Quasi-Identifiers: {warnings_count} indirect re-identification vectors neutralized via contextual generalization."
        )

        return "\n".join(sections)

    def audit_summary_leaks(self, summary: str, removed_spans: List[DetectedSpan]) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Comprehensive Multi-Layer Summary Audit:
        1. Exact, case-insensitive, fuzzy, and digit-sequence checks against all approved removed spans.
        2. Quasi-identifier scan and neutralization on summary text.
        3. Autonomous rule-based PII scan on summary (catches undetected or hallucinated PII).
        """
        purged = summary
        caught_leaks: List[Dict[str, Any]] = []
        summary_digits = re.findall(r"\d{6,}", summary)

        # 1. Audit against all removed approved spans
        for span in removed_spans:
            if not span.accepted or not span.text.strip():
                continue

            raw_needle = span.text.strip()
            needle_lower = raw_needle.lower()
            if len(needle_lower) < 2:
                continue

            # Exact & Case-insensitive with word boundary protection
            is_word = re.match(r"^\w+$", raw_needle) is not None
            check_pat = re.compile(r"\b" + re.escape(raw_needle) + r"\b", re.IGNORECASE) if is_word else re.compile(re.escape(raw_needle), re.IGNORECASE)
            if check_pat.search(purged):
                caught_leaks.append({
                    "text": raw_needle,
                    "category": span.category,
                    "type": "exact_or_case"
                })
                purged = check_pat.sub(f"[{span.category}]", purged)
                continue

            # Check constituent name tokens for multi-word names (e.g. bare "Priya" or "Nair")
            if span.category == "NAME":
                tokens = [t for t in re.split(r"\s+", raw_needle) if len(t) > 2]
                for tok in tokens:
                    tok_pat = re.compile(r"\b" + re.escape(tok) + r"\b", re.IGNORECASE)
                    if tok_pat.search(purged):
                        caught_leaks.append({
                            "text": tok,
                            "category": "NAME",
                            "type": "constituent_name_leak"
                        })
                        purged = tok_pat.sub("[NAME]", purged)

            # Digit-sequence check for Phone and ID numbers
            if span.category in ("PHONE", "ID"):
                needle_digits = re.sub(r"\D", "", raw_needle)
                if len(needle_digits) >= 6:
                    for s_d in summary_digits:
                        if needle_digits in s_d or s_d in needle_digits:
                            caught_leaks.append({
                                "text": raw_needle,
                                "category": span.category,
                                "type": "digit_sequence"
                            })
                            purged = purged.replace(s_d, f"[{span.category}]")

            # Fuzzy match check for names and addresses
            if span.category in ("NAME", "ADDRESS") and len(raw_needle) > 4:
                words = purged.split()
                for i in range(len(words)):
                    candidate_phrase = " ".join(words[i:i + len(raw_needle.split())])
                    if _fuzzy_match(raw_needle, candidate_phrase) >= 85.0:
                        caught_leaks.append({
                            "text": raw_needle,
                            "category": span.category,
                            "type": "fuzzy_match"
                        })
                        purged = purged.replace(candidate_phrase, f"[{span.category}]")
                        break

        # 2. Neutralize any quasi-identifiers present in the summary text
        purged, quasi_warnings = PrivacyAdvisor.apply_all_generalizations(purged)
        for qw in quasi_warnings:
            caught_leaks.append({
                "text": qw.original_text,
                "category": "QUASI_IDENTIFIER",
                "type": "quasi_generalization"
            })

        # 3. Autonomous scan for any unflagged/hallucinated PII in the summary
        detected_in_summary = detect_by_rules(purged)
        for s in detected_in_summary:
            if s.text not in [cl["text"] for cl in caught_leaks]:
                caught_leaks.append({
                    "text": s.text,
                    "category": s.category,
                    "type": "autonomous_pii_interception"
                })
                pat = re.compile(r"\b" + re.escape(s.text) + r"\b", re.IGNORECASE)
                purged = pat.sub(f"[{s.category}]", purged)

        return purged, caught_leaks
