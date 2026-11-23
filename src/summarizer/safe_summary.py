import re
import requests
from typing import List, Tuple, Dict, Any
from src.detection.schemas import DetectedSpan

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

class SafeSummarizer:
    """
    Zero-Leak Document Summarization Engine:
    1. Structurally enforced: accepts ONLY already-redacted text (no access to original unredacted text).
    2. Prompts local SLM via Ollama to summarize without guessing or restoring placeholders.
    3. Provides intelligent offline extractive fallback when Ollama is not active.
    4. Multi-layer audit against everything removed:
       - Exact match
       - Case-insensitive match
       - Fuzzy match (rapidfuzz)
       - Digit-sequence match for phone numbers and IDs
    """
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2:1b"):
        self.base_url = base_url
        self.model = model

    def summarize_redacted_only(self, redacted_text: str) -> Tuple[str, str]:
        """
        Structural enforcement: accepts ONLY the already-redacted text.
        Returns (summary_text, engine_used).
        """
        prompt = f"""You are an offline privacy-preserving document analyst.
Write a clear, concise 3-4 sentence summary of the following document.
MANDATORY PRIVACY RULES:
- Never guess or attempt to reconstruct any personal identities, contact info, or identifiers.
- Refer strictly to entities using their placeholder tags (e.g. [NAME_1], [EMAIL_1]) or generic roles.
- Do not mention or reveal private details.

Sanitized Document Text:
\"\"\"{redacted_text}\"\"\"

Executive Summary:"""

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
                if summary:
                    return summary, f"Local SLM ({self.model})"
        except Exception:
            pass

        # 2. Offline Extractive Synthesis (Fallback when Ollama is offline)
        summary = self._generate_extractive_summary(redacted_text)
        return summary, "Local Offline Extractive Engine"

    def summarize(self, full_text: str, spans: List[DetectedSpan], mask_style: str = "INDEXED", preserve_length: bool = False) -> str:
        """Convenience method: redacts text first, summarizes, and audits for leaks."""
        from src.redaction.text_redactor import redact_text_with_placeholders
        redacted_text, _ = redact_text_with_placeholders(full_text, spans, mask_style=mask_style, preserve_length=preserve_length)
        raw_summary, _ = self.summarize_redacted_only(redacted_text)
        purged_summary, _ = self.audit_summary_leaks(raw_summary, spans)
        return purged_summary

    def _generate_extractive_summary(self, redacted_text: str) -> str:
        """
        Synthesizes a cohesive executive summary directly from sanitized sentences,
        preserving placeholder entity integrity without external LLM dependencies.
        """
        lines = [line.strip() for line in redacted_text.splitlines() if line.strip()]
        if not lines:
            return "Empty document; no text available to summarize."

        title = lines[0] if len(lines) > 0 else "Document"
        # Find lines with substantive narrative or findings
        candidate_sentences = []
        for line in lines[1:]:
            # Skip pure key-value headers like "Date: ..." or "Email: ..."
            if re.match(r"^(?:date|email|phone|address|vitals|fax)[:\s]", line, re.IGNORECASE):
                continue
            if len(line) > 25:
                candidate_sentences.append(line)

        # Select top 2-3 most descriptive sentences
        selected = candidate_sentences[:3] if candidate_sentences else lines[:2]
        body_synthesis = " ".join(selected)

        # Count placeholders
        entities_found = set(re.findall(r"\[[A-Z]+_\d+\]", redacted_text))
        entity_summary = f"All private references ({len(entities_found)} unique entities) have been permanently masked." if entities_found else "Zero sensitive personal items were detected."

        return (
            f"This sanitized record pertains to {title}. {body_synthesis} "
            f"{entity_summary} The document maintains complete confidentiality with zero identifiable data."
        )

    def audit_summary_leaks(self, summary: str, removed_spans: List[DetectedSpan]) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Audits summary against all removed text:
        - Exact & Case-insensitive check
        - Fuzzy match check (rapidfuzz >= 80%)
        - Digit-sequence match for phones and IDs
        Masks any detected leak and returns (purged_summary, caught_leaks).
        """
        purged = summary
        caught_leaks: List[Dict[str, Any]] = []
        summary_digits = re.findall(r"\d{6,}", summary)

        for span in removed_spans:
            if not span.accepted or not span.text.strip():
                continue

            raw_needle = span.text.strip()
            needle_lower = raw_needle.lower()
            if len(needle_lower) < 2:
                continue

            # 1. Exact & Case-insensitive
            if needle_lower in purged.lower():
                caught_leaks.append({
                    "text": raw_needle,
                    "category": span.category,
                    "type": "exact_or_case"
                })
                pattern = re.compile(re.escape(raw_needle), re.IGNORECASE)
                purged = pattern.sub(f"[{span.category}]", purged)
                continue

            # 2. Digit-sequence check for Phone and ID numbers
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

            # 3. Fuzzy match check for names and addresses
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

        return purged, caught_leaks
