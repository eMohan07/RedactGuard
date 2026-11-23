import re
import uuid
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class PrivacyWarning:
    id: str
    original_text: str
    risk_type: str
    explanation: str
    suggested_generalization: str
    start_char: int
    end_char: int

class PrivacyAdvisor:
    """
    Quasi-Identifier & Re-Identification Risk Engine:
    Detects combinations that could single someone out:
    - Role + City / Location (e.g. 'CFO of a Pune-based firm')
    - Executive Title + Localized Company (e.g. 'Vice President at a Mumbai fintech startup')
    - Role + Specific Date or Specialty
    Scans both document text and summaries, providing one-click generalization.
    """
    
    QUASI_RULES = [
        {
            # Role + localized firm/company/startup (e.g. CFO of a Pune-based firm)
            "pattern": r"\b(?:the|a|an)?\s*(?:CFO|CEO|CTO|COO|Chief\s+[A-Za-z]+|Director|Vice\s+President|VP|Managing\s+Director|Founder)\s+(?:of|at)\s+(?:a|an|the)?\s*([A-Za-z0-9\s-]+?(?:based\s+firm|based\s+company|startup|hospital|clinic|university|bank|enterprise))\b",
            "risk": "Executive Role + Localized Organization",
            "gen_fn": lambda m: "a senior executive of an enterprise",
            "explanation": "Combining an executive title with a specific city or firm characteristic creates a high re-identification risk via public searches."
        },
        {
            # Role + specific city (e.g. Head of Cardiology in Pune)
            "pattern": r"\b(?:Head\s+of\s+[A-Za-z\s]+|Chief\s+Surgeon|Mayor|Director)\s+(?:in|at|of)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",
            "risk": "Niche Role + City",
            "gen_fn": lambda m: "a department specialist",
            "explanation": "Niche roles paired with specific cities easily narrow identities down to 1-2 individuals."
        },
        {
            # Age + Specialty (e.g. 42-year-old neurosurgeon)
            "pattern": r"\b\d{2}-year-old\s+[A-Za-z\s]+?(?:surgeon|director|partner|specialist)\b",
            "risk": "Demographic + Rare Role",
            "gen_fn": lambda m: "a senior specialist",
            "explanation": "Age combined with rare professional titles constitutes a quasi-identifier."
        }
    ]

    @classmethod
    def scan_warnings(cls, text: str) -> List[PrivacyWarning]:
        """Scans any text (document or summary) for quasi-identifier re-identification risks."""
        warnings: List[PrivacyWarning] = []

        for rule in cls.QUASI_RULES:
            for match in re.finditer(rule["pattern"], text, re.IGNORECASE):
                full_match = match.group(0).strip()
                suggested = rule["gen_fn"](match)
                
                warnings.append(PrivacyWarning(
                    id=str(uuid.uuid4())[:8],
                    original_text=full_match,
                    risk_type=rule["risk"],
                    explanation=rule["explanation"],
                    suggested_generalization=suggested,
                    start_char=match.start(),
                    end_char=match.end()
                ))

        return warnings

    @staticmethod
    def apply_generalization(text: str, warning: PrivacyWarning) -> str:
        """Replaces the quasi-identifier with the suggested generalization in the text."""
        return text[:warning.start_char] + warning.suggested_generalization + text[warning.end_char:]
