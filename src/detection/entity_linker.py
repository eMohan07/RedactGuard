import re
from typing import Dict, List, Tuple
from src.detection.schemas import DetectedSpan

try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    import difflib
    HAS_RAPIDFUZZ = False

class ParsedName:
    def __init__(self, raw: str):
        self.raw = raw
        # Remove honorifics (with or without trailing dot)
        cleaned = re.sub(r"^(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+", "", raw.strip(), flags=re.IGNORECASE)
        tokens = [t.strip(".,") for t in re.split(r"\s+", cleaned) if t.strip(".,")]

        self.tokens = tokens
        self.first = tokens[0].lower() if tokens else ""
        self.middle = " ".join([t.lower() for t in tokens[1:-1]]) if len(tokens) > 2 else ""
        self.last = tokens[-1].lower() if len(tokens) > 1 else ""
        self.first_initial = self.first[0].upper() if self.first else ""
        self.is_single_token = len(tokens) == 1
        self.is_initial = len(self.first) == 1

class EntityLinker:
    """
    Advanced Name Entity Linking & Coreference Resolution:
    - Parses names into first, middle, and last tokens.
    - Links 'R. Sharma' to 'Richa Sharma' (initial match + surname match).
    - Links bare 'Richa' or 'Sharma' only if exactly one person in the document fits.
    - Flags ambiguous shared surnames (e.g. 'Rajiv Sharma' and 'Richa Sharma') for user decision.
    - Assigns unified entity IDs ([NAME_1], [NAME_2]).
    """

    @staticmethod
    def fuzzy_ratio(s1: str, s2: str) -> float:
        if HAS_RAPIDFUZZ:
            return float(fuzz.token_sort_ratio(s1, s2))
        else:
            import difflib
            return float(difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio() * 100.0)

    @classmethod
    def are_name_variants(cls, name1: str, name2: str) -> bool:
        p1 = ParsedName(name1)
        p2 = ParsedName(name2)
        return cls.are_compatible(p1, p2)

    @classmethod
    def are_compatible(cls, p1: ParsedName, p2: ParsedName) -> bool:
        # Same exact name
        if p1.raw.strip().lower() == p2.raw.strip().lower():
            return True

        # Surname match required if both have surnames
        if p1.last and p2.last:
            if cls.fuzzy_ratio(p1.last, p2.last) < 90.0:
                return False
            # If both have initials or one has initial
            if p1.first_initial == p2.first_initial:
                if p1.is_initial or p2.is_initial:
                    return True
                return cls.fuzzy_ratio(p1.first, p2.first) >= 80.0
            return False

        # One has no surname (e.g. bare "Richa", bare "Sharma", bare "Priya", bare "Nair")
        # Matches if the single token matches first, middle, or last name of the full name
        if p1.is_single_token and not p2.is_single_token:
            return p1.first == p2.first or p1.first == p2.last or (p2.middle and p1.first in p2.middle.split())
        if p2.is_single_token and not p1.is_single_token:
            return p2.first == p1.first or p2.first == p1.last or (p1.middle and p2.first in p1.middle.split())

        return False

    @classmethod
    def cluster_entities(cls, spans: List[DetectedSpan]) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
        """
        Clusters entities into [NAME_1], [NAME_2], [EMAIL_1], etc.
        Returns:
            tag_map: dict of span.id -> assigned tag (e.g. [NAME_1])
            ambiguity_flags: list of warnings for ambiguous unlinked names
        """
        span_tags: Dict[str, str] = {}
        ambiguity_flags: List[Dict[str, str]] = []

        name_spans = [s for s in spans if s.category == "NAME"]
        
        # 1. Separate full names (has first and last) from bare single tokens
        full_name_spans = []
        bare_spans = []

        for s in name_spans:
            p = ParsedName(s.text)
            if p.is_single_token:
                bare_spans.append((s, p))
            else:
                full_name_spans.append((s, p))

        # 2. Cluster full names and initial variants
        clusters: List[List[Tuple[DetectedSpan, ParsedName]]] = []

        for s, p in full_name_spans:
            matched_cluster = None
            for cluster in clusters:
                if all(cls.are_compatible(p, member_p) for _, member_p in cluster):
                    matched_cluster = cluster
                    break
            if matched_cluster is not None:
                matched_cluster.append((s, p))
            else:
                clusters.append([(s, p)])

        # 3. Handle bare tokens (e.g., bare "Richa" or bare "Sharma")
        for s, p in bare_spans:
            token = p.first  # lowercased single token
            matching_clusters = []

            for cluster_idx, cluster in enumerate(clusters):
                for _, member_p in cluster:
                    # Does token match first name, last name, or full name?
                    if token == member_p.first or token == member_p.last:
                        matching_clusters.append(cluster_idx)
                        break

            unique_matching_clusters = list(set(matching_clusters))

            # Exactly one person fits -> Auto-link!
            if len(unique_matching_clusters) == 1:
                clusters[unique_matching_clusters[0]].append((s, p))
            # Two or more people share surname -> Flag ambiguity and count as distinct entity!
            elif len(unique_matching_clusters) > 1:
                ambiguity_flags.append({
                    "span_id": s.id,
                    "text": s.text,
                    "reason": f"Ambiguous name '{s.text}' matches multiple individuals sharing a surname. Counted as separate entity."
                })
                clusters.append([(s, p)])
            else:
                # Independent single person
                clusters.append([(s, p)])

        # 4. Assign [NAME_1], [NAME_2], etc.
        for idx, cluster in enumerate(clusters, start=1):
            tag = f"[NAME_{idx}]"
            for s, _ in cluster:
                span_tags[s.id] = tag

        # 5. Assign all other categories (EMAIL_1, PHONE_1, ID_1, ORGANIZATION_1, etc.)
        other_categories = sorted(list(set(s.category for s in spans if s.category != "NAME")))
        for cat in other_categories:
            cat_spans = [s for s in spans if s.category == cat]
            unique_vals: Dict[str, str] = {}
            count = 0
            for s in cat_spans:
                key = s.text.strip().lower()
                if key not in unique_vals:
                    count += 1
                    unique_vals[key] = f"[{cat}_{count}]"
                span_tags[s.id] = unique_vals[key]

        return span_tags, ambiguity_flags
