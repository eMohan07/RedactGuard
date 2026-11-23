"""
Model Downloader & Offline Preparation Script
---------------------------------------------
Downloads and caches required neural models locally so that the system
can run completely air-gapped without an internet connection.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Enforce no telemetry
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "0"

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

def download_gliner_model(model_name: str = "urchade/gliner_small-v2.1"):
    print(f"\n=======================================================")
    print(f"📦 PREPARING OFFLINE MODEL: {model_name}")
    print(f"=======================================================\n")
    try:
        from gliner import GLiNER
        print(f"Downloading/verifying '{model_name}' cache...")
        model = GLiNER.from_pretrained(model_name)
        # Test sample inference
        entities = model.predict_entities("Anand Kulkarni lives in Pune", ["person", "location"])
        print(f"✅ Model verified successfully! Sample inference output: {entities}")
        print(f"Local model weights are cached and ready for offline use.")
    except ImportError:
        print("⚠️ GLiNER is not installed. To install for local neural PII detection, run:")
        print("   pip install gliner")
    except Exception as e:
        print(f"ℹ️ Model download note: {e}")
        print("   Rule-based pattern recognizers will function autonomously if offline.")

def check_ollama_status():
    print(f"\n=======================================================")
    print("🤖 CHECKING LOCAL SLM BACKEND (Ollama)")
    print("=======================================================\n")
    import requests
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=2.0)
        if resp.status_code == 200:
            models = [m.get("name") for m in resp.json().get("models", [])]
            print(f"✅ Ollama service detected running locally.")
            print(f"Available local models: {models}")
            if not any("llama3.2" in m or "qwen2.5" in m for m in models):
                print("\nRecommended models for local safe summarization:")
                print("   ollama pull llama3.2:1b")
                print("   ollama pull qwen2.5:1.5b")
        else:
            print("⚠️ Ollama returned non-200 status code.")
    except Exception:
        print("ℹ️ Local Ollama service is not running (optional).")
        print("   The tool functions completely with built-in heuristic summarization")
        print("   and hybrid PII detection without Ollama.")

if __name__ == "__main__":
    download_gliner_model()
    check_ollama_status()
    print("\n✅ Offline preparation complete. You may now disconnect network access.")
