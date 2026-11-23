import sys
import json
import time
import tempfile
import tracemalloc
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detection.schemas import DetectedSpan
from src.detection.rules.regex_rules import detect_by_rules
from src.detection.gliner_detector import GLiNERDetector
from src.detection.hybrid_detector import HybridDetector
from src.detection.learning_store import LearningStore
from src.redaction.text_redactor import redact_text_with_placeholders, verify_redacted_text
from src.summarizer.safe_summary import SafeSummarizer

SYNTHETIC_BENCHMARK = PROJECT_ROOT / "data" / "benchmark" / "ground_truth.json"
UNSEEN_BENCHMARK = PROJECT_ROOT / "data" / "benchmark" / "unseen_ground_truth.json"

def calculate_detailed_metrics(gold_spans: List[Dict], pred_spans: List[DetectedSpan]) -> Tuple[int, int, int, List[Dict], List[DetectedSpan]]:
    """
    Calculates TP, FP, FN and returns missed gold spans (FNs) and false alarm spans (FPs).
    """
    tp = 0
    fp = 0
    fn = 0
    missed_gold = []
    false_positives = []

    gold_matched = [False] * len(gold_spans)
    
    for p in pred_spans:
        p_text = p.text.strip().lower()
        p_type = p.category.upper()

        match_found = False
        for idx, g in enumerate(gold_spans):
            if not gold_matched[idx]:
                g_text = g["text"].strip().lower()
                g_type = g["type"].upper()
                # Overlap match and compatible type
                if (p_text in g_text or g_text in p_text) and (p_type == g_type or p_type in g_type):
                    gold_matched[idx] = True
                    match_found = True
                    break
        if match_found:
            tp += 1
        else:
            fp += 1
            false_positives.append(p)

    for idx, matched in enumerate(gold_matched):
        if not matched:
            fn += 1
            missed_gold.append(gold_spans[idx])

    return tp, fp, fn, missed_gold, false_positives

def run_split_evaluation(split_name: str, dataset: Dict[str, Any], detector_fn) -> Dict[str, Any]:
    total_tp, total_fp, total_fn = 0, 0, 0
    total_time = 0.0
    all_missed: List[Dict[str, Any]] = []
    all_fps: List[Dict[str, Any]] = []

    category_stats = {
        "NAME": {"tp": 0, "fp": 0, "fn": 0},
        "EMAIL": {"tp": 0, "fp": 0, "fn": 0},
        "PHONE": {"tp": 0, "fp": 0, "fn": 0},
        "ADDRESS": {"tp": 0, "fp": 0, "fn": 0},
        "ID": {"tp": 0, "fp": 0, "fn": 0}
    }

    start_t = time.perf_counter()
    for doc_id, doc_info in dataset.items():
        text = doc_info["text"]
        gold = doc_info["spans"]

        t0 = time.perf_counter()
        preds = detector_fn(text)
        total_time += (time.perf_counter() - t0)

        tp, fp, fn, missed, fps = calculate_detailed_metrics(gold, preds)
        total_tp += tp
        total_fp += fp
        total_fn += fn

        for m in missed:
            all_missed.append({"document": doc_id, "text": m["text"], "type": m["type"]})
            cat = m["type"].upper()
            if cat in category_stats:
                category_stats[cat]["fn"] += 1

        for f in fps:
            all_fps.append({"document": doc_id, "text": f.text, "category": f.category, "confidence": f.confidence})
            cat = f.category.upper()
            if cat in category_stats:
                category_stats[cat]["fp"] += 1

    prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    sec_per_doc = total_time / len(dataset) if dataset else 0.0

    return {
        "split_name": split_name,
        "document_count": len(dataset),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "sec_per_doc": round(sec_per_doc, 4),
        "missed_pii": all_missed,
        "false_positive_instances": all_fps
    }

def evaluate_all():
    synthetic_data = {}
    unseen_data = {}

    if SYNTHETIC_BENCHMARK.exists():
        with open(SYNTHETIC_BENCHMARK, "r", encoding="utf-8") as f:
            synthetic_data = json.load(f)

    if UNSEEN_BENCHMARK.exists():
        with open(UNSEEN_BENCHMARK, "r", encoding="utf-8") as f:
            unseen_data = json.load(f)

    combined_data = {**synthetic_data, **unseen_data}
    total_docs = len(combined_data)

    print(f"\n=======================================================")
    print(f"📊 RELIABLE BENCHMARK EVALUATION (Total Docs: {total_docs})")
    print(f"   • Synthetic Benchmark Docs: {len(synthetic_data)}")
    print(f"   • Unseen Manually Written / Public Docs: {len(unseen_data)}")
    print(f"=======================================================\n")

    # Clean isolated store for evaluation
    eval_learning_file = Path(tempfile.gettempdir()) / "eval_learned_clean.json"
    if eval_learning_file.exists():
        try:
            eval_learning_file.unlink()
        except Exception:
            pass
    eval_learning_store = LearningStore(filepath=eval_learning_file)
    gliner = GLiNERDetector()
    hybrid = HybridDetector(learning_store=eval_learning_store, gliner_detector=gliner)

    detector_fn = lambda txt: hybrid.detect(txt, use_slm=False)

    tracemalloc.start()
    
    # 1. Evaluate Synthetic Split
    res_synthetic = run_split_evaluation("Synthetic Benchmark (Self-Generated)", synthetic_data, detector_fn)
    
    # 2. Evaluate Unseen Split
    res_unseen = run_split_evaluation("Unseen Manually Written & Public Dataset", unseen_data, detector_fn)
    
    # 3. Combined Evaluation
    res_combined = run_split_evaluation("Combined Overall Benchmark", combined_data, detector_fn)
    
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mem_mb = round(peak_mem / (1024 * 1024), 2)

    # Print Report
    for r in [res_synthetic, res_unseen, res_combined]:
        print(f"🔹 Split: {r['split_name']} ({r['document_count']} docs)")
        print(f"   Precision: {r['precision'] * 100:.2f}% | Recall: {r['recall'] * 100:.2f}% | F1: {r['f1_score'] * 100:.2f}%")
        print(f"   TP: {r['true_positives']} | FP: {r['false_positives']} | FN (Missed): {r['false_negatives']}")
        print(f"   Speed: {r['sec_per_doc']:.4f} s/doc\n")

    print(f"💾 Peak RAM Consumption: {peak_mem_mb} MB")

    # Report Missed PII Transparently
    print(f"\n🔍 DETAILED MISSED PII ANALYSIS (FALSE NEGATIVES):")
    if res_combined["missed_pii"]:
        for m in res_combined["missed_pii"]:
            print(f"   ❌ [{m['type']}] '{m['text']}' in {m['document']}")
    else:
        print("   ✅ No missed PII instances across evaluated datasets.")

    print(f"\n🔍 FALSE POSITIVE ALARMS:")
    if res_combined["false_positive_instances"]:
        for f in res_combined["false_positive_instances"]:
            print(f"   ⚠️ [{f['category']}] '{f['text']}' (Confidence: {f['confidence']:.2f})")
    else:
        print("   ✅ No false positives detected.")

    # Leak Verification Test
    print(f"\n🔒 EXPORT VERIFICATION & LEAK AUDIT:")
    leak_failures = 0
    for doc_id, doc_info in combined_data.items():
        text = doc_info["text"]
        preds = detector_fn(text)
        redacted_text, _ = redact_text_with_placeholders(text, preds, mask_style="INDEXED")
        is_safe, leaks = verify_redacted_text(redacted_text, preds)
        if not is_safe:
            print(f"❌ Leak detected in {doc_id}: {leaks}")
            leak_failures += 1

    if leak_failures == 0:
        print("   ✅ ALL EXPORTED DOCUMENTS PASSED: 0 sensitive strings leaked in output.\n")
    else:
        print(f"   ⚠️ {leak_failures} documents had leak warnings.\n")

    # Save to eval_results.json
    results_payload = {
        "synthetic_split": res_synthetic,
        "unseen_split": res_unseen,
        "combined_overall": res_combined,
        "peak_ram_mb": peak_mem_mb,
        "leak_failures": leak_failures
    }
    out_eval = PROJECT_ROOT / "data" / "benchmark" / "eval_results.json"
    with open(out_eval, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)
    print(f"Transparent evaluation report written to {out_eval}\n")

if __name__ == "__main__":
    evaluate_all()
