import html
from typing import List, Optional, Dict
from src.detection.schemas import DetectedSpan
from src.detection.entity_linker import EntityLinker

def get_confidence_styles(confidence: float, accepted: bool = True) -> dict[str, str]:
    if not accepted:
        return {
            "bg": "#f3f4f6",
            "border": "#9ca3af",
            "text": "#6b7280",
            "badge_bg": "#6b7280",
            "tier": "Excluded",
            "extra_style": "text-decoration: line-through; opacity: 0.60;"
        }

    if confidence >= 0.85:
        return {
            "bg": "#ecfdf5",          # soft emerald
            "border": "#10b981",      # emerald
            "text": "#064e3b",
            "badge_bg": "#059669",
            "tier": "High",
            "extra_style": ""
        }
    elif confidence >= 0.60:
        return {
            "bg": "#fffbeb",          # soft amber
            "border": "#f59e0b",      # amber
            "text": "#78350f",
            "badge_bg": "#d97706",
            "tier": "Medium",
            "extra_style": ""
        }
    else:
        return {
            "bg": "#fef2f2",          # soft rose
            "border": "#ef4444",      # red
            "text": "#7f1d1d",
            "badge_bg": "#dc2626",
            "tier": "Low",
            "extra_style": ""
        }

def render_highlighted_document(
    full_text: str, 
    spans: List[DetectedSpan],
    tag_map: Optional[Dict[str, str]] = None
) -> str:
    """
    Transforms plain text into HTML with colored candidate highlights,
    labelled with indexed tags (e.g. NAME_1, EMAIL_1) and colored by confidence score.
    Linked name variants (e.g. 'R. Sharma' & 'Richa Sharma') share the same tag.
    """
    if not spans:
        escaped = html.escape(full_text).replace("\n", "<br>")
        body_content = f"<div style='font-family: monospace; white-space: pre-wrap; line-height: 1.6;'>{escaped}</div>"
    else:
        if tag_map is None:
            tag_map = EntityLinker.cluster_entities([s for s in spans if s.accepted])

        sorted_spans = sorted(spans, key=lambda s: s.start_char)
        output_html = []
        current_idx = 0

        for s in sorted_spans:
            start = max(0, s.start_char)
            end = min(len(full_text), s.end_char)

            if start < current_idx:
                continue

            # Preceding plain text
            pre_text = full_text[current_idx:start]
            output_html.append(html.escape(pre_text).replace("\n", "<br>"))

            # Highlighted span
            matched_text = full_text[start:end]
            styles = get_confidence_styles(s.confidence, accepted=s.accepted)
            conf_pct = int(round(s.confidence * 100))

            # Use assigned tag if available, else standard category
            assigned_tag = tag_map.get(s.id, f"[{s.category}]").strip("[]")
            badge_label = f"{assigned_tag} · {conf_pct}%"
            if not s.accepted:
                badge_label += " (EXCLUDED)"

            span_markup = (
                f'<span style="background-color: {styles["bg"]}; '
                f'border: 1.5px solid {styles["border"]}; '
                f'border-radius: 4px; padding: 2px 6px; margin: 0 2px; '
                f'display: inline-block; font-weight: 500; {styles["extra_style"]}">'
                f'<span style="color: {styles["text"]};">{html.escape(matched_text)}</span>'
                f'<span style="background-color: {styles["badge_bg"]}; color: #ffffff; '
                f'font-size: 0.72rem; font-weight: 700; padding: 1px 5px; '
                f'border-radius: 3px; margin-left: 6px; text-transform: uppercase; letter-spacing: 0.5px;">'
                f'{badge_label}</span>'
                f'</span>'
            )
            output_html.append(span_markup)
            current_idx = end

        if current_idx < len(full_text):
            output_html.append(html.escape(full_text[current_idx:]).replace("\n", "<br>"))

        body_content = "".join(output_html)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{
        margin: 0;
        padding: 16px;
        background-color: #ffffff;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 14.5px;
        line-height: 1.85;
        color: #1f2937;
    }}
</style>
</head>
<body>
{body_content}
</body>
</html>"""
