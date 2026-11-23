import uuid
from typing import List
from src.detection.schemas import DetectedSpan

class GLiNERDetector:
    """
    Local entity extraction using GLiNER small PII model.
    Falls back gracefully if the optional gliner package is not installed or weights not yet cached.
    """
    def __init__(self, model_name: str = "urchade/gliner_small-v2.1"):
        self.model_name = model_name
        self.model = None
        self._init_model()

    def _init_model(self):
        try:
            from gliner import GLiNER
            # Loads lightweight model (~150MB) locally
            self.model = GLiNER.from_pretrained(self.model_name)
        except Exception:
            self.model = None

    def is_available(self) -> bool:
        return self.model is not None

    def detect(self, text: str, page_num: int = 1, threshold: float = 0.50) -> List[DetectedSpan]:
        if not self.model or not text.strip():
            return []

        labels = ["person", "email", "phone number", "address", "identification number"]
        label_map = {
            "person": "NAME",
            "email": "EMAIL",
            "phone number": "PHONE",
            "address": "ADDRESS",
            "identification number": "ID"
        }

        try:
            entities = self.model.predict_entities(text, labels, threshold=threshold)
            spans = []
            for ent in entities:
                raw_label = ent["label"].lower()
                cat = label_map.get(raw_label, "ID")
                spans.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    text=ent["text"],
                    category=cat,
                    start_char=ent["start"],
                    end_char=ent["end"],
                    page_num=page_num,
                    source="gliner",
                    confidence=float(ent["score"]),
                    accepted=True
                ))
            return spans
        except Exception:
            return []
