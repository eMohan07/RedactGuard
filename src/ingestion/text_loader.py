from pathlib import Path
from src.detection.schemas import DocumentContent
from src.ingestion.pdf_loader import EmptyDocumentError

def load_text_file(file_path: Path | str) -> DocumentContent:
    """Loads a plaintext file and returns DocumentContent."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    if not text.strip():
        raise EmptyDocumentError("The uploaded TXT file is empty.")
        
    return DocumentContent(
        filename=path.name,
        file_type="txt",
        full_text=text,
        pages=[text]
    )
