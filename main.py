import os
import sys
import webbrowser
import threading
import time
from pathlib import Path

# Enforce strict offline privacy & telemetry suppression before third-party imports
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "0"
os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
os.environ["STREAMLIT_TELEMETRY_ENABLED"] = "false"

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from config import Config, ensure_directories
from src.detection.learning_store import LearningStore
from src.server.app import app

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    # Ensure directories and run automated TTL cleanup on old temporary files
    cfg = ensure_directories()
    deleted_temp = LearningStore.cleanup_old_files([cfg.UPLOAD_DIR, cfg.OUTPUT_DIR], max_age_seconds=1800)
    
    print("\n" + "=" * 60)
    print("🛡️  REDACTGUARD — OFFLINE DOCUMENT SANITIZER & REDACTOR (FastAPI + JS)")
    print("=" * 60)
    print("📍 URL: http://127.0.0.1:8000")
    print("🔒 100% Local Processing — Zero Cloud Telemetry")
    print(f"🧹 Temporary File Cleanup: Purged {deleted_temp} expired files")
    print("⌨️  Shortcuts: [A] Approve | [R] Reject | [S] Redact Similar | [J/K] Navigate")
    print("=" * 60 + "\n")

    # Open browser automatically in background
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn server
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
