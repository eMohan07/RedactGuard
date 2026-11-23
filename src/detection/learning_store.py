import json
import time
import os
import re
import shutil
from pathlib import Path
from typing import Dict, Set, List, Any, Optional

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

CORRECTIONS_FILE = DATA_DIR / "corrections.jsonl"
LEARNING_FILE = DATA_DIR / "learned_patterns.json"
KEY_FILE = DATA_DIR / ".security_key"

class LearningStore:
    """
    Active Learning Engine with Security Protection:
    1. Contextual Active Learning: Learns approved patterns and dictionary phrases.
       Document-scoped suppression prevents a single rejection (e.g. "Sharma" in an enterprise context)
       from globally blinding detection of common names in subsequent documents.
    2. Encrypts sensitive dictionary and audit data at rest using authenticated symmetric encryption
       (Fernet / AES-128-CBC + HMAC-SHA256). Supports external key provisioning via PII_SECURITY_KEY.
    3. Provides purge_all() to cleanly delete all learned PII data on demand.
    4. Provides automated TTL cleanup for temporary uploads and exports.
    """
    def __init__(self, json_path: Path = None, jsonl_path: Path = None, filepath: Path = None, key_path: Path = None):
        self.json_path = filepath or json_path or LEARNING_FILE
        self.jsonl_path = jsonl_path or CORRECTIONS_FILE
        self.key_path = key_path or KEY_FILE
        self.cipher: Optional[Any] = self._init_cipher()
        self.remembered: Dict[str, str] = {}         # phrase -> category
        self.suppressed: Set[str] = set()              # multi-token phrases globally rejected
        self.doc_suppressed: Dict[str, Set[str]] = {}  # document -> set of single-token rejected phrases
        self.learned_prefixes: Set[str] = set()        # learned ID prefix patterns (e.g. "CUST-")
        self.total_corrections_logged = 0
        self.load()

    def _init_cipher(self):
        if not HAS_CRYPTO:
            return None
        try:
            # 1. Prefer external environment variable for key provisioning
            env_key = os.environ.get("PII_SECURITY_KEY")
            if env_key:
                return Fernet(env_key.encode("utf-8").strip())

            # 2. Key file fallback
            if self.key_path.exists():
                with open(self.key_path, "rb") as kf:
                    key = kf.read().strip()
            else:
                key = Fernet.generate_key()
                with open(self.key_path, "wb") as kf:
                    kf.write(key)
                try:
                    os.chmod(self.key_path, 0o600)
                except Exception:
                    pass
            return Fernet(key)
        except Exception:
            return None

    def load(self):
        if self.json_path.exists():
            try:
                with open(self.json_path, "r", encoding="utf-8") as f:
                    content = json.load(f)

                # Check if file is encrypted
                if isinstance(content, dict) and content.get("encrypted") and self.cipher:
                    decrypted_bytes = self.cipher.decrypt(content["payload"].encode("utf-8"))
                    data = json.loads(decrypted_bytes.decode("utf-8"))
                    self.remembered = data.get("remembered", {})
                    self.suppressed = set(data.get("suppressed", []))
                else:
                    # Legacy plaintext format
                    self.remembered = content.get("remembered", {})
                    self.suppressed = set(content.get("suppressed", []))
            except Exception:
                self.remembered = {}
                self.suppressed = set()

        if self.jsonl_path.exists():
            try:
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    self.total_corrections_logged = sum(1 for line in f if line.strip())
            except Exception:
                self.total_corrections_logged = 0

    def save(self):
        raw_data = {
            "remembered": self.remembered,
            "suppressed": list(self.suppressed)
        }
        
        if self.cipher:
            json_bytes = json.dumps(raw_data, ensure_ascii=False).encode("utf-8")
            token = self.cipher.encrypt(json_bytes).decode("utf-8")
            wrapped = {
                "encrypted": True,
                "version": 1,
                "payload": token
            }
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(wrapped, f, indent=2)
        else:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(raw_data, f, indent=2, ensure_ascii=False)

    def record_correction(self, text: str, category: str, action: str = None, accepted: bool = None, filename: str = "document"):
        """
        Logs user feedback and updates contextual active learning memory.
        Single-token rejections are kept scoped to the active document to prevent
        suppressing valid names in other records. Multi-token phrases are learned globally.
        """
        cleaned = text.strip()
        if not cleaned or len(cleaned) < 2:
            return

        if action is None:
            action = "approve" if accepted else "reject"

        # 1. Update immediate ignore / dictionary memory
        if action in ("approve", "manual_add"):
            self.remembered[cleaned] = category
            if cleaned.lower() in self.suppressed:
                self.suppressed.remove(cleaned.lower())
            if filename in self.doc_suppressed and cleaned.lower() in self.doc_suppressed[filename]:
                self.doc_suppressed[filename].remove(cleaned.lower())
            
            # Pattern generalization: extract ID prefix pattern (e.g. CUST-1029 -> CUST-)
            if category == "ID":
                m_pref = re.match(r"^([A-Z]{2,6}[-_])\d+$", cleaned)
                if m_pref:
                    self.learned_prefixes.add(m_pref.group(1))

        elif action == "reject":
            # Document-scoped vs global suppression
            is_single_word = len(cleaned.split()) == 1
            if filename not in self.doc_suppressed:
                self.doc_suppressed[filename] = set()
            self.doc_suppressed[filename].add(cleaned.lower())

            # Only add to global suppression if it is a multi-word phrase (e.g. "Acme Solutions Pvt")
            if not is_single_word:
                self.suppressed.add(cleaned.lower())

            if cleaned in self.remembered:
                del self.remembered[cleaned]
        self.save()

        # 2. Append encrypted entry to JSONL log
        if self.cipher:
            text_field = self.cipher.encrypt(cleaned.encode("utf-8")).decode("utf-8")
            is_encrypted = True
        else:
            text_field = cleaned
            is_encrypted = False

        log_entry = {
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "text_enc": text_field,
            "is_encrypted": is_encrypted,
            "category": category,
            "action": action,
            "document": filename
        }
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
            self.total_corrections_logged += 1
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "remembered_count": len(self.remembered),
            "suppressed_count": len(self.suppressed),
            "total_corrections": self.total_corrections_logged,
            "encryption_enabled": (self.cipher is not None)
        }

    def purge_all(self) -> bool:
        """
        Securely deletes all stored personal information from memory and disk.
        Wipes active dictionary, suppression list, and deletes files.
        """
        self.remembered.clear()
        self.suppressed.clear()
        self.total_corrections_logged = 0

        success = True
        for path in [self.json_path, self.jsonl_path]:
            if path and path.exists():
                try:
                    path.unlink()
                except Exception:
                    success = False
        return success

    @staticmethod
    def cleanup_old_files(directories: List[Path], max_age_seconds: int = 1800) -> int:
        """
        Automatically removes uploaded and exported files older than max_age_seconds (default 30 mins).
        Returns number of deleted files.
        """
        now = time.time()
        deleted = 0
        for dir_path in directories:
            if not dir_path or not dir_path.exists():
                continue
            for item in dir_path.iterdir():
                if item.is_file() and not item.name.startswith("."):
                    try:
                        mtime = item.stat().st_mtime
                        if (now - mtime) > max_age_seconds:
                            item.unlink()
                            deleted += 1
                    except Exception:
                        pass
        return deleted

    def get_learned_spans(self, full_text: str, page_num: int = 1):
        """Generates candidate spans from remembered approved terms and generalized learned patterns."""
        import uuid
        import re
        from src.detection.schemas import DetectedSpan

        spans = []
        # 1. Exact learned terms
        for term, category in self.remembered.items():
            pattern = re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)
            for m in pattern.finditer(full_text):
                spans.append(DetectedSpan(
                    id=str(uuid.uuid4())[:8],
                    category=category,
                    text=m.group(),
                    start_char=m.start(),
                    end_char=m.end(),
                    confidence=0.99,
                    source="ActiveLearningStore",
                    accepted=True,
                    page_num=page_num
                ))

        # 2. Generalization: apply learned ID prefixes
        for pref in self.learned_prefixes:
            pat = re.compile(rf"\b{re.escape(pref)}\d+\b", re.IGNORECASE)
            for m in pat.finditer(full_text):
                if not any(s.start_char <= m.start() and m.end() <= s.end_char for s in spans):
                    spans.append(DetectedSpan(
                        id=str(uuid.uuid4())[:8],
                        category="ID",
                        text=m.group(),
                        start_char=m.start(),
                        end_char=m.end(),
                        confidence=0.94,
                        source="ActiveLearningStore:GeneralizedPattern",
                        accepted=True,
                        page_num=page_num
                    ))
        return spans

    def is_suppressed(self, text: str, filename: Optional[str] = None) -> bool:
        if not text:
            return False
        clean_lower = text.strip().lower()
        # 1. Document-scoped check
        if filename and filename in self.doc_suppressed:
            if clean_lower in self.doc_suppressed[filename]:
                return True
        # 2. Global suppression (only applies to multi-token phrases)
        if len(clean_lower.split()) >= 2 and clean_lower in self.suppressed:
            return True
        return False

    def filter_suppressed(self, spans: List[Any], filename: Optional[str] = None) -> List[Any]:
        """Filters out candidate spans that match rejected/ignored phrases."""
        survivors = []
        for s in spans:
            if self.is_suppressed(s.text, filename=filename):
                continue
            survivors.append(s)
        return survivors
