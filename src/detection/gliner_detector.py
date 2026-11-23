import os
import uuid
import re
from typing import List, Tuple
from src.detection.schemas import DetectedSpan

# Guarantee strictly local operation: zero outbound calls to Hugging Face Hub
os.environ["HF_HUB_OFFLINE"] = os.environ.get("HF_HUB_OFFLINE", "1")
os.environ["TRANSFORMERS_OFFLINE"] = os.environ.get("TRANSFORMERS_OFFLINE", "1")
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"

class GLiNERDetector:
    """
    Local entity extraction using GLiNER small PII model.
    Operates 100% locally with sliding-window chunking to prevent truncation
    on long documents (>384 words).
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

    def _chunk_text(self, text: str, chunk_chars: int = 1200, overlap_chars: int = 200) -> List[Tuple[str, int]]:
        """
        Splits text into sliding overlapping chunks along whitespace boundaries
        to preserve context across window boundaries.
        Returns list of (chunk_text, start_char_offset).
        """
        if len(text) <= chunk_chars:
            return [(text, 0)]

        chunks = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = min(start + chunk_chars, text_len)
            if end < text_len:
                # Snap to previous whitespace or punctuation to avoid cutting tokens in half
                space_idx = text.rfind(" ", start + chunk_chars // 2, end)
                nl_idx = text.rfind("\n", start + chunk_chars // 2, end)
                break_idx = max(space_idx, nl_idx)
                if break_idx > start:
                    end = break_idx + 1

            chunk_content = text[start:end]
            chunks.append((chunk_content, start))

            if end >= text_len:
                break
            start = max(start + 1, end - overlap_chars)

        return chunks

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
            chunks = self._chunk_text(text)
            candidate_spans = []

            for chunk_content, base_offset in chunks:
                entities = self.model.predict_entities(chunk_content, labels, threshold=threshold)
                for ent in entities:
                    raw_label = ent["label"].lower()
                    cat = label_map.get(raw_label, "ID")
                    abs_start = base_offset + ent["start"]
                    abs_end = base_offset + ent["end"]
                    candidate_spans.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        text=ent["text"],
                        category=cat,
                        start_char=abs_start,
                        end_char=abs_end,
                        page_num=page_num,
                        source="gliner",
                        confidence=float(ent["score"]),
                        accepted=True
                    ))

            # Deduplicate spans from overlapping chunk regions
            if not candidate_spans:
                return []

            candidate_spans.sort(key=lambda s: (s.start_char, -s.end_char))
            deduped: List[DetectedSpan] = []
            for s in candidate_spans:
                if not deduped:
                    deduped.append(s)
                    continue
                prev = deduped[-1]
                # If exact or nested overlap
                if s.start_char == prev.start_char and s.end_char == prev.end_char:
                    if s.confidence > prev.confidence:
                        deduped[-1] = s
                elif s.start_char < prev.end_char:
                    # Partial overlap in boundary
                    if s.confidence > prev.confidence and (s.end_char - s.start_char) >= (prev.end_char - prev.start_char):
                        deduped[-1] = s
                else:
                    deduped.append(s)

            return deduped
        except Exception:
            return []
