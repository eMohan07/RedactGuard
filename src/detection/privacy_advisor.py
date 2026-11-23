import re
import uuid
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

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
    Detects indirect identification combinations that could single someone out:
    1. Role + Localized Organization (e.g. 'CFO of a Pune-based firm', 'finance chief at a Mumbai startup')
    2. Executive Title + Named Enterprise (e.g. 'CFO at Infosys', 'CEO of Microsoft')
    3. Demographic Uniqueness + Specialty + Region (e.g. 'only female cardiologist in Kolhapur', 'the only female CFO in the Pune region')
    4. Age + Senior Role + Sector (e.g. '61-year-old CEO of a Bengaluru-based fintech', '42-year-old neurosurgeon')
    5. Niche Role + City / Institution (e.g. 'Head of Cardiology in Pune')
    """
    
    QUASI_RULES = [
        # 1. Uniqueness / Superlative Demographics + Specialty / Role + Location
        # e.g. "only female cardiologist in Kolhapur", "the only female CFO in the Pune region"
        {
            "pattern": (
                r"\b(?:the\s+)?(?:only|sole|youngest|oldest|first)\s+"
                r"(?:female|male|woman|man|senior|junior)?\s*"
                r"([A-Za-z\s]+?)\s+(?:in|at|of)\s+(?:the\s+)?"
                r"((?:[A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+)?|[A-Za-z0-9\s-]+?(?:region|district|office|area|hospital|firm|city|state|zone)))\b"
            ),
            "risk": "Demographic Uniqueness + Role + Regional Location",
            "gen_fn": lambda m: "a specialized professional in the regional sector",
            "explanation": "Combining uniqueness traits (e.g. 'only female') with a specific professional role and region uniquely re-identifies an individual."
        },

        # 2. Functional leadership / chief role + localized startup / firm
        # e.g. "finance chief at a Mumbai startup", "tech lead of a Pune-based firm"
        {
            "pattern": (
                r"\b(?:the|a|an)?\s*"
                r"(?:finance\s+chief|financial\s+controller|tech\s+lead|technology\s+head|marketing\s+head|"
                r"operations\s+head|operations\s+lead|chief\s+[a-z]+|head\s+of\s+[a-z]+)\s+"
                r"(?:at|of|in)\s+(?:a|an|the)?\s*"
                r"([A-Za-z0-9\s-]+?(?:based\s+firm|based\s+company|startup|firm|company|enterprise|agency|clinic))\b"
            ),
            "risk": "Functional Role + Localized Startup/Firm",
            "gen_fn": lambda m: "a department executive of an organization",
            "explanation": "Pairing a specialized leadership title with a localized firm type allows immediate single-person re-identification via search queries."
        },

        # 3. Executive title + localized organization / based firm
        # e.g. "CFO of a Pune-based firm", "Vice President at a Mumbai fintech startup"
        {
            "pattern": (
                r"\b(?:the|a|an)?\s*"
                r"(?:CFO|CEO|CTO|COO|Chief\s+[A-Za-z]+|Director|Vice\s+President|VP|Managing\s+Director|Founder|President)\s+"
                r"(?:of|at|in)\s+(?:a|an|the)?\s*"
                r"([A-Za-z0-9\s-]+?(?:based\s+firm|based\s+company|based\s+fintech|startup|hospital|clinic|university|bank|enterprise))\b"
            ),
            "risk": "Executive Role + Localized Organization",
            "gen_fn": lambda m: "a senior corporate enterprise executive",
            "explanation": "Combining an executive title with city characteristics narrows identity down to 1-2 individuals."
        },

        # 4. Executive title + prominent named company
        # e.g. "CFO at Infosys", "CEO of Google", "Managing Director at Wipro"
        {
            "pattern": (
                r"\b(?:the|a|an)?\s*"
                r"(?:CFO|CEO|CTO|COO|Chief\s+[A-Za-z]+|Managing\s+Director|VP|Vice\s+President|Director|General\s+Counsel)\s+"
                r"(?:at|of)\s+([A-Z][a-zA-Z0-9&.-]+(?:\s+[A-Z][a-zA-Z0-9&.-]+){0,2})\b"
            ),
            "risk": "Executive Role + Named Corporation",
            "gen_fn": lambda m: "an executive leader of an enterprise",
            "explanation": "Executive roles at named corporations are publicly indexed and immediately deanonymize the individual."
        },

        # 5. Age + Executive Role / Specialty + Location / Sector
        # e.g. "61-year-old CEO of a Bengaluru-based fintech", "42-year-old neurosurgeon"
        {
            "pattern": (
                r"\b\d{2}-year-old\s+"
                r"(?:CEO|CFO|CTO|COO|founder|director|executive|surgeon|neurosurgeon|cardiologist|specialist|leader|partner)\s*"
                r"(?:(?:at|of|in)\s+[A-Za-z0-9\s-]+)?\b"
            ),
            "risk": "Demographic (Age) + Specialized Executive/Medical Role",
            "gen_fn": lambda m: "an experienced senior professional",
            "explanation": "Exact age combined with a specialized role or location constitutes a quasi-identifier."
        },

        # 6. Medical / Academic Niche Role + City
        # e.g. "Head of Cardiology in Pune", "Chief Surgeon in Kolhapur"
        {
            "pattern": (
                r"\b(?:Head\s+of\s+[A-Za-z\s]+|Chief\s+Surgeon|Mayor|Director\s+General)\s+"
                r"(?:in|at|of)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
            ),
            "risk": "Specialized Medical/Civil Role + City",
            "gen_fn": lambda m: "a senior departmental specialist",
            "explanation": "Niche roles in specific municipalities directly isolate the individual in local registries."
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

        # Filter overlapping warnings, prioritizing longer spans
        sorted_w = sorted(warnings, key=lambda w: (w.start_char, -(w.end_char - w.start_char)))
        filtered: List[PrivacyWarning] = []
        for w in sorted_w:
            if not filtered:
                filtered.append(w)
                continue
            prev = filtered[-1]
            if w.start_char < prev.end_char:
                # Overlap: keep the longer span
                if (w.end_char - w.start_char) > (prev.end_char - prev.start_char):
                    filtered[-1] = w
            else:
                filtered.append(w)

        return filtered

    @staticmethod
    def apply_generalization(text: str, warning: PrivacyWarning) -> str:
        """Replaces a specific quasi-identifier with the suggested generalization in the text."""
        return text[:warning.start_char] + warning.suggested_generalization + text[warning.end_char:]

    @classmethod
    def apply_all_generalizations(cls, text: str) -> Tuple[str, List[PrivacyWarning]]:
        """
        Scans and automatically neutralizes all quasi-identifiers in the text
        by replacing them with their generalized equivalents in reverse offset order.
        """
        warnings = cls.scan_warnings(text)
        if not warnings:
            return text, []

        sanitized = text
        # Apply in reverse offset order so character indices remain valid
        for w in sorted(warnings, key=lambda x: -x.start_char):
            sanitized = sanitized[:w.start_char] + w.suggested_generalization + sanitized[w.end_char:]

        return sanitized, warnings
