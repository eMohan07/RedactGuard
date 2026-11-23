import os
import re
import json
import uuid
import requests
from typing import List, Tuple, Optional, Dict, Any
from src.detection.schemas import DetectedSpan
from src.detection.rules.regex_rules import normalize_category, is_valid_name
from src.detection.validators import is_likely_non_pii

class LocalSLMClient:
    """
    Local Small Language Model (SLM) Client:
    Supports dual-mode offline inference:
      Mode A: Local Ollama daemon (e.g. Qwen2.5-1.5B, Llama-3.2-1B/3B, Phi-3.5-mini at http://127.0.0.1:11434)
      Mode B: Embedded HuggingFace Transformers pipeline (e.g. Qwen/Qwen2.5-0.5B-Instruct / 1.5B)
      Fallback: Deterministic context-aware borderline validator (when no GPU/daemon is running)

    Zero cloud dependencies: All execution is strictly local on 127.0.0.1.
    """
    def __init__(
        self, 
        base_url: str = "http://localhost:11434", 
        model: str = "qwen2.5:1.5b",
        transformers_model_id: Optional[str] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.transformers_model_id = transformers_model_id
        self._transformers_pipe = None
        self._init_transformers_pipeline()

    def _init_transformers_pipeline(self):
        """Attempts to initialize local transformers pipeline if model ID is provided."""
        if self.transformers_model_id:
            try:
                import torch
                from transformers import pipeline
                device = 0 if torch.cuda.is_available() else -1
                self._transformers_pipe = pipeline(
                    "text-generation",
                    model=self.transformers_model_id,
                    device=device,
                    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
                )
            except Exception:
                self._transformers_pipe = None

    def is_available(self) -> bool:
        """Checks if local Ollama daemon or embedded transformers pipeline is available."""
        if self._transformers_pipe is not None:
            return True
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=1.0)
            return r.status_code == 200
        except Exception:
            return False

    def verify_borderline_candidate(
        self, 
        candidate_text: str, 
        context: str, 
        category: str
    ) -> Tuple[bool, float, str]:
        """
        Uses the local SLM to verify borderline / ambiguous candidates
        (e.g. confidence between 0.40 and 0.85, such as terms that could be
        company names vs person names, or internal codes vs IDs).

        Returns:
            (is_pii: bool, adjusted_confidence: float, rationale: str)
        """
        clean_text = candidate_text.strip()
        if not clean_text:
            return False, 0.0, "Empty candidate text"

        # Fast pre-validation: check against known non-PII terms
        if is_likely_non_pii(clean_text, context):
            return False, 0.10, "Matched non-PII entity dictionary (organization, framework, or document heading)"

        prompt = f"""You are a strict data privacy auditor. Determine whether the candidate substring '{clean_text}' inside the context below is truly sensitive private personal information ({category}).

Context:
\"\"\"{context}\"\"\"

Candidate: \"{clean_text}\"
Category: {category}

Respond with ONLY a JSON object:
{{"is_pii": true/false, "confidence": float between 0.0 and 1.0, "rationale": "one-sentence explanation"}}"""

        # 1. Try Ollama daemon
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=10
            )
            if resp.status_code == 200:
                raw_json = resp.json().get("response", "{}")
                data = json.loads(raw_json)
                is_pii = bool(data.get("is_pii", False))
                conf = float(data.get("confidence", 0.50))
                rationale = str(data.get("rationale", "Verified by local SLM"))
                return is_pii, conf, rationale
        except Exception:
            pass

        # 2. Try embedded transformers pipeline
        if self._transformers_pipe is not None:
            try:
                outputs = self._transformers_pipe(
                    prompt, 
                    max_new_tokens=100, 
                    do_sample=False,
                    pad_token_id=self._transformers_pipe.tokenizer.eos_token_id
                )
                generated = outputs[0]["generated_text"][len(prompt):]
                match = re.search(r"\{.*?\}", generated, re.DOTALL)
                if match:
                    data = json.loads(match.group(0))
                    return bool(data.get("is_pii", False)), float(data.get("confidence", 0.70)), str(data.get("rationale", "Verified by embedded SLM"))
            except Exception:
                pass

        # 3. Graceful offline heuristic verification
        if category == "NAME":
            valid = is_valid_name(clean_text)
            return valid, 0.85 if valid else 0.20, "Validated via offline linguistic pattern rules"
        elif category in ("ID", "PHONE", "EMAIL", "ADDRESS"):
            return True, 0.80, f"Candidate matches {category} structural format"

        return True, 0.75, "Offline fallback approval"

    def detect_entities(
        self, 
        text_chunk: str, 
        start_offset: int = 0, 
        page_num: int = 1
    ) -> List[DetectedSpan]:
        """
        Prompts the local SLM to extract named PII entities from the text chunk.
        """
        prompt = f"""You are a local data privacy assistant. Extract all personal identifying information (PII) from the text below.
Only categorize into one of these 5 types:
- "NAME": Person full or partial names
- "EMAIL": Email addresses
- "PHONE": Telephone / mobile numbers
- "ADDRESS": Physical street addresses, locations
- "ID": Identification numbers, SSN, passport, account, card numbers

Return ONLY a JSON array with objects containing:
- "text": the exact substring from the text
- "category": one of ["NAME", "EMAIL", "PHONE", "ADDRESS", "ID"]
- "confidence": confidence float between 0.50 and 0.99

Do not add commentary or markdown code blocks. If none found, return [].

Text:
\"\"\"{text_chunk}\"\"\"

JSON Response:"""

        items = []
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=30
            )
            if response.status_code == 200:
                result = response.json().get("response", "[]")
                parsed = json.loads(result)
                if isinstance(parsed, list):
                    items = parsed
                elif isinstance(parsed, dict) and "entities" in parsed:
                    items = parsed["entities"]
        except Exception:
            items = []

        spans: List[DetectedSpan] = []
        for item in items:
            val = item.get("text", "").strip()
            cat = normalize_category(item.get("category", "NAME"))
            conf = float(item.get("confidence", 0.75))
            conf = max(0.1, min(1.0, conf))

            if not val or len(val) < 2:
                continue

            idx = text_chunk.find(val)
            if idx != -1:
                spans.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=val,
                    category=cat,
                    start_char=start_offset + idx,
                    end_char=start_offset + idx + len(val),
                    page_num=page_num,
                    source=f"slm:{self.model}",
                    confidence=conf,
                    accepted=True
                ))

        return spans
