from pathlib import Path
from dataclasses import dataclass, field

BASE_DIR = Path(__file__).resolve().parent

@dataclass
class Config:
    # Directory paths
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    OUTPUT_DIR: Path = BASE_DIR / "outputs"
    MODELS_DIR: Path = BASE_DIR / "models"
    
    # Redaction formatting
    # Modes: "TOKEN" (e.g. [REDACTED: EMAIL]), "BLOCK" (█████), or "HASH" ([REDACTED: a8b3])
    REDACTION_MODE: str = "TOKEN"
    
    # Local SLM backend settings
    # Defaulting to local Ollama service or lightweight offline server
    SLM_BACKEND: str = "ollama"  # options: "ollama", "mock", "llama_cpp"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:1b"  # or qwen2.5:1.5b, phi3:mini
    
    # Canonical categories as specified for review:
    TARGET_CATEGORIES: list[str] = field(default_factory=lambda: [
        "NAME",
        "EMAIL",
        "PHONE",
        "ADDRESS",
        "ID"
    ])

def ensure_directories():
    config = Config()
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    return config

if __name__ == "__main__":
    ensure_directories()
    print("Project directories verified.")
