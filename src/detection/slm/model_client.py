import json
import uuid
import requests
from src.detection.schemas import DetectedSpan
from src.detection.rules.regex_rules import normalize_category

class LocalSLMClient:
    """
    Interface to communicate with a local small language model (SLM)
    such as Llama-3.2-1B/3B, Qwen-2.5-1.5B/3B, or Phi-3.5-mini via local Ollama
    or an embedded offline inference server.
    """
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2:1b"):
        self.base_url = base_url
        self.model = model

    def detect_entities(self, text_chunk: str, start_offset: int = 0, page_num: int = 1) -> list[DetectedSpan]:
        """
        Prompts the local model to identify named entities (NAME, EMAIL, PHONE, ADDRESS, ID)
        and estimate detection confidence.
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
            if response.status_code != 200:
                return []
            
            result = response.json().get("response", "[]")
            items = json.loads(result)
            if not isinstance(items, list):
                if isinstance(items, dict) and "entities" in items:
                    items = items["entities"]
                else:
                    items = []
        except Exception:
            # Fallback when local Ollama is offline or uninstalled
            return []

        spans = []
        for item in items:
            val = item.get("text", "").strip()
            cat = normalize_category(item.get("category", "NAME"))
            conf = float(item.get("confidence", 0.75))
            # Clamp confidence to [0.1, 1.0]
            conf = max(0.1, min(1.0, conf))

            if not val or len(val) < 2:
                continue

            # Find position in text chunk
            idx = text_chunk.find(val)
            if idx != -1:
                spans.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=val,
                    category=cat,
                    start_char=start_offset + idx,
                    end_char=start_offset + idx + len(val),
                    page_num=page_num,
                    source="slm",
                    confidence=conf,
                    accepted=True
                ))

        return spans
