from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class DetectedSpan(BaseModel):
    id: str = Field(description="Unique identifier for span")
    text: str = Field(description="Extracted sensitive text value")
    category: str = Field(description="Entity category e.g. NAME, EMAIL, PHONE, ADDRESS, ID")
    start_char: int = Field(description="Start character index in text")
    end_char: int = Field(description="End character index in text")
    page_num: Optional[int] = Field(default=None, description="Page number for PDF (1-based)")
    bbox: Optional[List[float]] = Field(default=None, description="Primary bounding box [x0, y0, x1, y1]")
    bboxes: Optional[List[List[float]]] = Field(default=None, description="All word bounding boxes for multi-word span")
    source: str = Field(default="rule", description="rule, gliner, slm, or manual")
    confidence: float = Field(default=1.0, description="Detection confidence score")
    accepted: bool = Field(default=True, description="Whether user accepted this redaction")

class WordBox(BaseModel):
    text: str
    start_char: int
    end_char: int
    page_num: int
    bbox: List[float]  # [x0, y0, x1, y1]

class DocumentContent(BaseModel):
    filename: str
    file_type: str  # "txt" or "pdf"
    full_text: str
    pages: List[str] = Field(default_factory=list)
    word_boxes: List[WordBox] = Field(default_factory=list)
    spans: List[DetectedSpan] = Field(default_factory=list)
