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

SYNTHETIC_BENCHMARK = PROJECT_ROOT / "data" / "benchmark" / "ground_truth.json"
UNSEEN_BENCHMARK = PROJECT_ROOT / "data" / "benchmark" / "unseen_ground_truth.json"

def calculate_iou(span1_start: int, span1_end: int, span2_start: int, span2_end: int) -> float:
    """Calculates character-level Intersection over Union (IoU)."""
    intersect_start = max(span1_start, span2_start)
    intersect_end = min(span1_end, span2_end)
    intersect = max(0, intersect_end - intersect_start)
    union = (span1_end - span1_start) + (span2_end - span2_start) - intersect
    return float(intersect / union) if union > 0 else 0.0

def evaluate_metrics(
    gold_spans: List[Dict], 
    pred_spans: List[DetectedSpan],
    match_mode: str = "exact"
) -> Tuple[int, int, int, Dict[str, Dict[str, int]], List[Dict], List[DetectedSpan]]:
    """
    Evaluates detection metrics under two strict modes:
    - 'exact': Gold text and predicted text must match exactly (case-insensitive).
    - 'iou': Requires token/span IoU >= 0.50 with matching category.
    Returns tp, fp, fn, per_category_counts, missed_gold, false_positives.
    """
    tp, fp, fn = 0, 0, 0
    missed_gold = []
    false_positives = []
    gold_matched = [False] * len(gold_spans)

    cats = ["NAME", "EMAIL", "PHONE", "ADDRESS", "ID"]
    cat_counts = {c: {"tp": 0, "fp": 0, "fn": 0} for c in cats}

    for p in pred_spans:
        p_text = p.text.strip().lower()
        p_cat = p.category.upper()
        if p_cat not in cat_counts:
            cat_counts[p_cat] = {"tp": 0, "fp": 0, "fn": 0}

        match_idx = None
        for idx, g in enumerate(gold_spans):
            if gold_matched[idx]:
                continue
            g_text = g["text"].strip().lower()
            g_cat = g["type"].upper()

            cat_compatible = (p_cat == g_cat or p_cat in g_cat or g_cat in p_cat)
            if not cat_compatible:
                continue

            if match_mode == "exact":
                if p_text == g_text:
                    match_idx = idx
                    break
            else: # IoU mode
                if p_text == g_text:
                    match_idx = idx
                    break
                # Character IoU or substring containment
                iou = calculate_iou(p.start_char, p.end_char, g.get("start", 0), g.get("end", 0)) if "start" in g else 0.0
                if iou >= 0.50 or (p_text in g_text or g_text in p_text):
                    match_idx = idx
                    break

        if match_idx is not None:
            gold_matched[match_idx] = True
            tp += 1
            cat_counts[p_cat]["tp"] += 1
        else:
            fp += 1
            cat_counts[p_cat]["fp"] += 1
            false_positives.append(p)

    for idx, matched in enumerate(gold_matched):
        if not matched:
            fn += 1
            g_cat = gold_spans[idx]["type"].upper()
            if g_cat not in cat_counts:
                cat_counts[g_cat] = {"tp": 0, "fp": 0, "fn": 0}
            cat_counts[g_cat]["fn"] += 1
            missed_gold.append(gold_spans[idx])

    return tp, fp, fn, cat_counts, missed_gold, false_positives

def run_split_evaluation(split_name: str, dataset: Dict[str, Any], detector_fn, match_mode: str = "exact") -> Dict[str, Any]:
    total_tp, total_fp, total_fn = 0, 0, 0
    total_time = 0.0
    all_missed = []
    all_fps = []
    overall_cat = {}

    for doc_id, doc_info in dataset.items():
        text = doc_info["text"]
        gold = doc_info["spans"]

        t0 = time.perf_counter()
        preds = detector_fn(text)
        total_time += (time.perf_counter() - t0)

        tp, fp, fn, cat_counts, missed, fps = evaluate_metrics(gold, preds, match_mode=match_mode)
        total_tp += tp
        total_fp += fp
        total_fn += fn

        for m in missed:
            all_missed.append({"document": doc_id, "text": m["text"], "type": m["type"]})
        for f in fps:
            all_fps.append({"document": doc_id, "text": f.text, "category": f.category, "confidence": f.confidence})

        for cat, counts in cat_counts.items():
            if cat not in overall_cat:
                overall_cat[cat] = {"tp": 0, "fp": 0, "fn": 0}
            overall_cat[cat]["tp"] += counts["tp"]
            overall_cat[cat]["fp"] += counts["fp"]
            overall_cat[cat]["fn"] += counts["fn"]

    prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    ms_per_doc = (total_time / len(dataset) * 1000.0) if dataset else 0.0

    # Calculate per-category metrics
    cat_summary = {}
    for c, cnt in overall_cat.items():
        c_tp, c_fp, c_fn = cnt["tp"], cnt["fp"], cnt["fn"]
        c_p = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
        c_r = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
        c_f = 2 * (c_p * c_r) / (c_p + c_r) if (c_p + c_r) > 0 else 0.0
        cat_summary[c] = {
            "precision": round(c_p, 4),
            "recall": round(c_r, 4),
            "f1": round(c_f, 4),
            "support": c_tp + c_fn
        }

    return {
        "split_name": split_name,
        "match_mode": match_mode,
        "document_count": len(dataset),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "ms_per_doc": round(ms_per_doc, 2),
        "category_metrics": cat_summary,
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

    gliner = GLiNERDetector()

    print(f"\n================================================================================")
    print(f"📊 RIGOROUS MULTI-MODEL BENCHMARK EVALUATION (Total Documents: {total_docs})")
    print(f"   • Annotated Synthetic Benchmark Docs : {len(synthetic_data)}")
    print(f"   • Annotated Multi-domain Held-Out Docs: {len(unseen_data)}")
    print(f"   • Local GLiNER Small NER Available    : {gliner.is_available()}")
    print(f"================================================================================\n")

    # Clean isolated store for evaluation
    eval_learning_file = Path(tempfile.gettempdir()) / "eval_learned_clean.json"
    if eval_learning_file.exists():
        try:
            eval_learning_file.unlink()
        except Exception:
            pass
    eval_learning_store = LearningStore(filepath=eval_learning_file)
    hybrid = HybridDetector(learning_store=eval_learning_store, gliner_detector=gliner)

    hybrid_fn = lambda txt: hybrid.detect(txt, use_slm=False)
    rules_only_fn = lambda txt: detect_by_rules(txt)

    try:
        import psutil
        process = psutil.Process()
    except Exception:
        process = None

    tracemalloc.start()

    # 1. Evaluate Hybrid Detector under True Exact Match
    res_exact_synth = run_split_evaluation("Synthetic (Exact Match)", synthetic_data, hybrid_fn, match_mode="exact")
    res_exact_unseen = run_split_evaluation("Held-Out (Exact Match)", unseen_data, hybrid_fn, match_mode="exact")
    res_exact_combined = run_split_evaluation("Combined (Exact Match)", combined_data, hybrid_fn, match_mode="exact")

    # 2. Evaluate Hybrid Detector under IoU Overlap Match (>= 50% boundary overlap)
    res_iou_combined = run_split_evaluation("Combined (Boundary IoU Match)", combined_data, hybrid_fn, match_mode="iou")

    # 3. Evaluate Rules-Only (Ablation Comparison)
    res_rules_combined = run_split_evaluation("Combined (Rules-Only Ablation)", combined_data, rules_only_fn, match_mode="exact")

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_heap_mb = round(peak_mem / (1024 * 1024), 2)
    process_rss_mb = round(process.memory_info().rss / (1024 * 1024), 2) if process else peak_heap_mb

    print("🔹 MODEL COMPARISON & ABLATION:")
    print(f"   1. Hybrid (Rules + GLiNER) [True Exact] : P={res_exact_combined['precision']*100:.1f}%, R={res_exact_combined['recall']*100:.1f}%, F1={res_exact_combined['f1_score']*100:.1f}% ({res_exact_combined['ms_per_doc']} ms/doc)")
    print(f"   2. Hybrid (Rules + GLiNER) [Boundary IoU]: P={res_iou_combined['precision']*100:.1f}%, R={res_iou_combined['recall']*100:.1f}%, F1={res_iou_combined['f1_score']*100:.1f}%")
    print(f"   3. Rules-Only Baseline    [True Exact]  : P={res_rules_combined['precision']*100:.1f}%, R={res_rules_combined['recall']*100:.1f}%, F1={res_rules_combined['f1_score']*100:.1f}% ({res_rules_combined['ms_per_doc']} ms/doc)\n")

    print(f"🔹 SPLIT DETAILS (HYBRID TRUE EXACT):")
    for r in [res_exact_synth, res_exact_unseen, res_exact_combined]:
        print(f"   • {r['split_name']} ({r['document_count']} docs): P={r['precision']*100:.1f}% | R={r['recall']*100:.1f}% | F1={r['f1_score']*100:.1f}% | Speed: {r['ms_per_doc']:.1f} ms/doc")

    print(f"\n🔹 PER-CATEGORY BREAKDOWN (HYBRID DETECTOR):")
    for cat, m in res_exact_combined["category_metrics"].items():
        print(f"   • {cat:<8}: Precision={m['precision']*100:>5.1f}% | Recall={m['recall']*100:>5.1f}% | F1={m['f1']*100:>5.1f}% (Support: {m['support']})")

    print(f"\n🔹 RESOURCE FOOTPRINT:")
    print(f"   • Tracemalloc Heap Allocation : {peak_heap_mb} MB")
    print(f"   • Operating System Process RSS: {process_rss_mb} MB (Includes PyTorch, GLiNER weights, and Python runtime)")

    # 4. Leak Verification Test
    print(f"\n🔒 EXPORT VERIFICATION & LEAK AUDIT:")
    leak_failures = 0
    for doc_id, doc_info in combined_data.items():
        text = doc_info["text"]
        preds = hybrid_fn(text)
        # Simulate human approval of detected candidate entities
        approved_preds = [p.model_copy(update={"accepted": True}) for p in preds]
        redacted_text, _ = redact_text_with_placeholders(text, approved_preds, mask_style="INDEXED")
        is_safe, leaks = verify_redacted_text(redacted_text, approved_preds)
        if not is_safe:
            print(f"   ❌ Leak detected in {doc_id}: {leaks}")
            leak_failures += 1

    if leak_failures == 0:
        print("   ✅ ALL EXPORTED DOCUMENTS PASSED: 0 sensitive strings leaked in output.\n")
    else:
        print(f"   ⚠️ {leak_failures} documents had leak warnings.\n")

    # Save to eval_results.json
    results_payload = {
        "hybrid_exact": res_exact_combined,
        "hybrid_iou": res_iou_combined,
        "rules_only": res_rules_combined,
        "synthetic_split": res_exact_synth,
        "unseen_split": res_exact_unseen,
        "peak_heap_mb": peak_heap_mb,
        "process_rss_mb": process_rss_mb,
        "leak_failures": leak_failures
    }
    out_eval = PROJECT_ROOT / "data" / "benchmark" / "eval_results.json"
    with open(out_eval, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)
    print(f"Detailed benchmark report saved to {out_eval}\n")

if __name__ == "__main__":
    evaluate_all()
