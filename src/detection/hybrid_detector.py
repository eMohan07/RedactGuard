from typing import List, Tuple
from src.detection.schemas import DetectedSpan
from src.detection.rules.regex_rules import detect_by_rules, is_valid_name
from src.detection.validators import is_likely_non_pii
from src.detection.slm.model_client import LocalSLMClient
from src.detection.learning_store import LearningStore
from src.detection.gliner_detector import GLiNERDetector

DETERMINISTIC_RULE_SOURCES = {
    "rule:AadhaarRecognizer",
    "rule:PanCardRecognizer",
    "rule:GstinRecognizer",
    "rule:IfscRecognizer",
    "rule:UanRecognizer",
    "rule:GenericIDRecognizer",
    "rule:EmployeeAndAccountRecognizer",
    "rule:EmailRecognizer",
    "rule:PhoneRecognizer",
    "rule:PinCodeAnchoredAddressRecognizer",
    "rule:AddressPrefixRecognizer",
    "rule:AddressPatternRecognizer"
}

class HybridDetector:
    """
    Intelligent Multi-Engine PII Detection & Fusion Pipeline:
    1. Active Learning Store (remembered user redactions & suppressions)
    2. Presidio-Style Deterministic Validators (Aadhaar, PAN, GSTIN, IFSC, UAN, Account/Generic IDs, Emails, Phones, Addresses)
    3. GLiNER Zero-Shot Small Neural Model (Named Entity Recognition)
    4. Optional Local Generative SLM (via Ollama)

    Span Fusion & Arbitration:
    - Never allows an unvalidated neural span to override a deterministic, checksum-validated rule span.
    - Resolves overlapping spans by selecting the most complete boundaries and highest-confidence domain evidence.
    - Suppresses non-PII terms (e.g. 'Machine Learning', corporate suffixes, document headings) regardless of origin.
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
        # 1. Past learned feedback (Human explicit input has top precedence)
        learned_spans = self.learning_store.get_learned_spans(text, page_num=page_num)

        # 2. Presidio-style pattern recognizers & algorithmic checksums
        rule_spans = detect_by_rules(text, page_num=page_num)

        # 3. GLiNER small PII model (if available)
        raw_gliner_spans = self.gliner_detector.detect(text, page_num=page_num)
        # Quality filter for GLiNER outputs: suppress non-PII false alarms
        gliner_spans = []
        for s in raw_gliner_spans:
            ctx_start = max(0, s.start_char - 40)
            ctx_end = min(len(text), s.end_char + 40)
            surrounding = text[ctx_start:ctx_end]
            if s.category == "NAME" and not is_valid_name(s.text):
                continue
            if is_likely_non_pii(s.text, surrounding):
                continue
            gliner_spans.append(s)

        # 4. Optional Local Generative SLM (Ollama)
        slm_spans = []
        if use_slm:
            raw_slm = self.slm_client.detect_entities(text, page_num=page_num)
            for s in raw_slm:
                ctx_start = max(0, s.start_char - 40)
                ctx_end = min(len(text), s.end_char + 40)
                surrounding = text[ctx_start:ctx_end]
                if s.category == "NAME" and not is_valid_name(s.text):
                    continue
                if is_likely_non_pii(s.text, surrounding):
                    continue
                slm_spans.append(s)

        # Intelligent Multi-Source Span Fusion
        merged = self._fuse_spans(learned_spans, rule_spans, gliner_spans, slm_spans)

        # 5. Borderline Candidate SLM Verification (Contextual disambiguation)
        if use_slm:
            for span in merged:
                if 0.40 <= span.confidence < 0.85:
                    ctx_start = max(0, span.start_char - 60)
                    ctx_end = min(len(text), span.end_char + 60)
                    context = text[ctx_start:ctx_end]
                    is_pii, adj_conf, _ = self.slm_client.verify_borderline_candidate(
                        span.text, context, span.category
                    )
                    if not is_pii:
                        span.accepted = False
                        span.confidence = min(span.confidence, adj_conf)
                    else:
                        span.confidence = max(span.confidence, adj_conf)

        # 6. Apply suppression for terms previously marked false positives
        for span in merged:
            if self.learning_store.is_suppressed(span.text):
                span.accepted = False
                span.confidence = min(span.confidence, 0.40)

        return merged

    def _fuse_spans(
        self,
        learned: List[DetectedSpan],
        rules: List[DetectedSpan],
        gliner: List[DetectedSpan],
        slm: List[DetectedSpan]
    ) -> List[DetectedSpan]:
        """
        Fuses candidate spans using domain-aware precedence and boundary completeness.
        """
        # Start with learned human corrections
        fused: List[DetectedSpan] = list(learned)

        # Add rules with high priority for deterministic recognizers
        for r_span in rules:
            self._insert_with_arbitration(fused, r_span, is_deterministic_rule=True)

        # Integrate GLiNER spans
        for g_span in gliner:
            self._insert_with_arbitration(fused, g_span, is_deterministic_rule=False)

        # Integrate SLM spans
        for s_span in slm:
            self._insert_with_arbitration(fused, s_span, is_deterministic_rule=False)

        fused.sort(key=lambda s: s.start_char)
        return fused

    def _insert_with_arbitration(self, target_list: List[DetectedSpan], candidate: DetectedSpan, is_deterministic_rule: bool):
        """
        Inserts candidate into target_list, resolving overlaps intelligently.
        """
        overlapping_indices = []
        for idx, existing in enumerate(target_list):
            if not (candidate.end_char <= existing.start_char or candidate.start_char >= existing.end_char):
                overlapping_indices.append(idx)

        if not overlapping_indices:
            target_list.append(candidate)
            return

        # Check each overlapping span
        should_add_candidate = True
        remove_indices = []

        for idx in overlapping_indices:
            existing = target_list[idx]

            # 1. Never replace explicit human learned spans
            if existing.source == "learned":
                should_add_candidate = False
                break

            # 2. Checksum-validated deterministic rules vs neural/statistical spans:
            existing_is_det = (existing.source in DETERMINISTIC_RULE_SOURCES)
            cand_is_det = (candidate.source in DETERMINISTIC_RULE_SOURCES)

            if existing_is_det and not cand_is_det:
                should_add_candidate = False
                break

            if cand_is_det and not existing_is_det:
                remove_indices.append(idx)
                continue

            # 3. Same category - boundary completeness resolution
            if existing.category == candidate.category:
                # If candidate is more complete (longer span encompassing existing)
                if len(candidate.text.strip()) > len(existing.text.strip()):
                    remove_indices.append(idx)
                elif len(existing.text.strip()) > len(candidate.text.strip()):
                    should_add_candidate = False
                    break
                else:
                    # Same length - keep higher confidence
                    if candidate.confidence > existing.confidence:
                        remove_indices.append(idx)
                    else:
                        should_add_candidate = False
                        break
                continue

            # 4. Cross-category conflict:
            # - ID (e.g. Account Number, Employee ID) takes priority over PHONE or NAME
            if candidate.category == "ID" and existing.category in ("PHONE", "NAME"):
                remove_indices.append(idx)
                continue
            elif existing.category == "ID" and candidate.category in ("PHONE", "NAME"):
                should_add_candidate = False
                break

            # - ADDRESS takes priority over partial NAME tokens if candidate is longer
            if candidate.category == "ADDRESS" and existing.category == "NAME":
                if len(candidate.text) > len(existing.text):
                    remove_indices.append(idx)
                    continue

            # - If confidence difference is high (> 0.15), prefer higher confidence
            if candidate.confidence > existing.confidence + 0.15:
                remove_indices.append(idx)
            else:
                should_add_candidate = False
                break

        if should_add_candidate:
            # Remove any demoted spans in reverse order
            for idx in sorted(remove_indices, reverse=True):
                target_list.pop(idx)
            target_list.append(candidate)
