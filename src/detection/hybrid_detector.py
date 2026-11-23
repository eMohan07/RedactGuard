from typing import List
from src.detection.schemas import DetectedSpan
from src.detection.rules.regex_rules import detect_by_rules
from src.detection.slm.model_client import LocalSLMClient
from src.detection.learning_store import LearningStore
from src.detection.gliner_detector import GLiNERDetector

class HybridDetector:
    """
    Combines:
    1. Active Learning Store (remembered user redactions)
    2. GLiNER small PII model
    3. Presidio-style pattern recognizers
    4. Local Small Language Model (SLM via Ollama)
    """
    def __init__(
        self, 
        slm_client: LocalSLMClient | None = None, 
        learning_store: LearningStore | None = None,
        gliner_detector: GLiNERDetector | None = None
    ):
        self.slm_client = slm_client or LocalSLMClient()
        self.learning_store = learning_store or LearningStore()
        self.gliner_detector = gliner_detector or GLiNERDetector()

    def detect(self, text: str, page_num: int = 1, use_slm: bool = False) -> List[DetectedSpan]:
        # 1. Past learned feedback
        learned_spans = self.learning_store.get_learned_spans(text, page_num=page_num)

        # 2. GLiNER small PII model (if available)
        gliner_spans = self.gliner_detector.detect(text, page_num=page_num)

        # 3. Presidio-style pattern recognizers
        rule_spans = detect_by_rules(text, page_num=page_num)

        # 4. Local SLM (Ollama)
        slm_spans = []
        if use_slm:
            slm_spans = self.slm_client.detect_entities(text, page_num=page_num)

        # Merge in priority: Learned > GLiNER > Rules > SLM
        merged = self._merge_all([learned_spans, gliner_spans, rule_spans, slm_spans])

        # 5. Apply suppression for terms previously marked false positives
        for span in merged:
            if self.learning_store.is_suppressed(span.text):
                span.accepted = False
                span.confidence = min(span.confidence, 0.40)

        return merged

    def _merge_all(self, span_groups: List[List[DetectedSpan]]) -> List[DetectedSpan]:
        combined: List[DetectedSpan] = []
        for group in span_groups:
            for s in group:
                overlap = False
                for existing in combined:
                    if not (s.end_char <= existing.start_char or s.start_char >= existing.end_char):
                        overlap = True
                        break
                if not overlap:
                    combined.append(s)

        combined.sort(key=lambda x: x.start_char)
        return combined
