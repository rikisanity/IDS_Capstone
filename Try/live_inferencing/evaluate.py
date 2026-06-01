# evaluate.py
# IoT IDS Thesis — Model Evaluation Script
# EEE 196 / EEE 199 — Group Zero, UP Diliman

#usage 
# python3 live_inferencing/evaluate.py --data datasets/dataset_training_iot.csv
#usage 
# python3 live_inferencing/evaluate.py --data datasets/dataset_training_iot.csv --save reports/evaluation_report.txt


import argparse
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score, precision_recall_curve
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

def normalise_labels(series: pd.Series) -> pd.Series:
    s = series.copy()
    if pd.api.types.is_numeric_dtype(s):
        return s.map({0: "normal", 1: "attack"}).fillna("unknown")
    s = s.astype(str).str.strip().str.lower()
    s = s.replace({"benign": "normal", "0": "normal", "1": "attack"})
    return s

def compute_metrics(actual: pd.Series, predicted: pd.Series, probas: np.ndarray = None):
    cm = confusion_matrix(actual, predicted, labels=["normal", "attack"])
    tn, fp, fn, tp = cm.ravel()

    accuracy  = accuracy_score(actual, predicted)
    precision = precision_score(actual, predicted, pos_label="attack", zero_division=0)
    recall    = recall_score(actual, predicted, pos_label="attack", zero_division=0)
    f1        = f1_score(actual, predicted, pos_label="attack", zero_division=0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    auc = None
    if probas is not None:
        try:
            y_bin = (actual == "attack").astype(int)
            auc = roc_auc_score(y_bin, probas)
        except Exception: pass

    return dict(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
                accuracy=accuracy, precision=precision, recall=recall, 
                f1=f1, fpr=fpr, fnr=fnr, auc=auc, n_total=len(actual),
                n_attacks=(actual == "attack").sum(), n_normal=(actual == "normal").sum())

def build_report(m: dict, latency_ms: float = None, throughput: float = None) -> str:
    auc_str = f"{m['auc']:.4f}" if m['auc'] is not None else "N/A"
    lat_str = f"{latency_ms:.3f} ms/row" if latency_ms is not None else "N/A"
    thr_str = f"{throughput:.0f} rows/sec" if throughput is not None else "N/A"

    lines = [
        "=" * 50, "     IoT IDS — MODEL EVALUATION REPORT", "=" * 50,
        f"Total rows analyzed : {m['n_total']:,}",
        f"  Normal traffic    : {m['n_normal']:,}",
        f"  Attack traffic    : {m['n_attacks']:,}", "",
        "── Confusion Matrix ──────────────────────────",
        f"  True Normal  (normal  → normal) : {m['tn']:6,}",
        f"  False Alarm  (normal  → attack) : {m['fp']:6,}  ← false positive",
        f"  Missed Attack(attack  → normal) : {m['fn']:6,}  ← false negative",
        f"  True Attack  (attack  → attack) : {m['tp']:6,}", "",
        "── Performance Metrics ───────────────────────",
        f"  Accuracy         : {m['accuracy']*100:.2f}%",
        f"  Precision        : {m['precision']:.4f}",
        f"  Recall (Det.Rate): {m['recall']:.4f}",
        f"  F1 Score         : {m['f1']:.4f}",
        f"  False Positive Rate (FPR) : {m['fpr']:.4f}  ({m['fpr']*100:.2f}%)",
        f"  False Negative Rate (FNR) : {m['fnr']:.4f}  ({m['fnr']*100:.2f}%)",
        f"  AUC-ROC          : {auc_str}", "",
        "── Inference Performance ─────────────────────",
        f"  Mean latency     : {lat_str}",
        f"  Throughput       : {thr_str}", "",
        "── Per-Class Breakdown ───────────────────────",
    ]
    return "\n".join(lines)

def evaluate_single(data_path: str, save_path: str = None, save_threshold_curve: bool = True):
    try:
        from IDS_inferencing import TONIoTInferencer
    except ImportError:
        log.error("IDS_inferencing.py not found. Place it in the same folder.")
        sys.exit(1)

    log.info("Loading dataset from: %s", data_path)
    df = pd.read_csv(data_path, low_memory=False)
    log.info("Loaded %d rows × %d columns", *df.shape)

    if "label" in df.columns:
        actual = normalise_labels(df["label"])
    else:
        actual = df["type"].astype(str).str.lower().apply(lambda x: "normal" if x == "normal" else "attack")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    available_model_paths = {}
    for name, fname in [("xgb", "xgb_final_model.pkl"), ("dt", "dt_final_model.pkl"), ("rf", "rf_final_model.pkl")]:
        path = os.path.join(BASE_DIR, fname)
        if os.path.exists(path): available_model_paths[name] = path

    if not available_model_paths:
        log.error("No model .pkl files found in %s.", BASE_DIR)
        sys.exit(1)

    active_model = os.environ.get("MODEL_NAME", "xgb")
    if active_model not in available_model_paths:
        active_model = next(iter(available_model_paths))

    log.info("Running IDS_inferencing model (%s)...", active_model)
    inferencer = TONIoTInferencer(
        model_paths=available_model_paths,
        feature_names_path=os.path.join(BASE_DIR, "selected_feature_names.pkl"),
        label_encoder_path=os.path.join(BASE_DIR, "label_encoder.pkl")
    )

    t_start = time.perf_counter()
    result   = inferencer.predict(df, model=active_model)
    t_end    = time.perf_counter()

    elapsed_s    = t_end - t_start
    latency_ms   = (elapsed_s / len(df)) * 1000
    throughput   = len(df) / elapsed_s

    log.info("Inference complete: %.2fs total | %.3f ms/row | %.0f rows/sec", elapsed_s, latency_ms, throughput)

    probas    = result["prob_attack"].values if "prob_attack" in result.columns else None
    
    # --- DYNAMIC THRESHOLD OVERRIDE ---
    # Look for MED_CONF in the terminal; default to 0.50 if it's not there
    threshold_str = os.environ.get("MED_CONF", "0.50")
    try:
        custom_threshold = float(threshold_str)
    except ValueError:
        custom_threshold = 0.50 # Safety fallback
        
    if probas is not None:
        predicted_raw = np.where(probas >= custom_threshold, "attack", "normal")
        predicted = pd.Series(predicted_raw, index=actual.index)
    else:
        predicted = normalise_labels(result["label"])
    # ---------------------------------

    m = compute_metrics(actual, predicted, probas)
    report_lines = build_report(m, latency_ms, throughput)
    clf_report = classification_report(actual, predicted, labels=["normal", "attack"])

    full_report = report_lines + "\n" + clf_report + "\n" + "=" * 50
    print(full_report)

    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        Path(save_path).write_text(full_report)
        log.info("Report saved to %s", save_path)

    # --- RESTORED THRESHOLD CURVE GENERATOR ---
    if save_threshold_curve and probas is not None:
        y_bin = (actual == "attack").astype(int)
        prec_arr, rec_arr, thresh_arr = precision_recall_curve(y_bin, probas)
        f1_arr = np.where(
            (prec_arr + rec_arr) > 0,
            2 * prec_arr * rec_arr / (prec_arr + rec_arr), 0
        )
        curve_df = pd.DataFrame({
            "threshold": list(thresh_arr) + [1.0],
            "precision": prec_arr,
            "recall":    rec_arr,
            "f1":        f1_arr,
            "fpr":       [m["fpr"]] * len(prec_arr),
        })
        curve_path = Path(save_path).parent / "threshold_curve.csv" if save_path else Path("threshold_curve.csv")
        curve_df.to_csv(curve_path, index=False)
        best_idx   = np.argmax(f1_arr[:-1])
        best_thresh = thresh_arr[best_idx]
        
        log.info("Threshold curve saved to %s", curve_path)
        print(f"\n[!] OPTIMAL DECISION THRESHOLD: {best_thresh:.3f}  (Expected F1: {f1_arr[best_idx]:.4f})")
        print(f"-> Plug this threshold into your docker-compose.live.yml as MED_CONF/HIGH_CONF")

def evaluate_two_csvs(actual_path: str, predicted_path: str, save_path: str = None):
    df_actual = pd.read_csv(actual_path)
    df_predicted = pd.read_csv(predicted_path)
    actual = normalise_labels(df_actual["label"])
    pred_col = "label" if "label" in df_predicted.columns else "prediction"
    predicted = normalise_labels(df_predicted[pred_col])
    probas = df_predicted.get("prob_attack", df_predicted.get("attack_prob")).values if "prob_attack" in df_predicted.columns or "attack_prob" in df_predicted.columns else None
    
    m = compute_metrics(actual, predicted, probas)
    full_report = build_report(m) + "\n" + classification_report(actual, predicted, labels=["normal", "attack"]) + "\n" + "="*50
    print(full_report)
    
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        Path(save_path).write_text(full_report)

def main():
    parser = argparse.ArgumentParser(description="IoT IDS Model Evaluator")
    parser.add_argument("--data", type=str, help="Single labeled CSV")
    parser.add_argument("--save", type=str, help="Save report to this file path")
    parser.add_argument("--no-curve", action="store_true", help="Skip threshold curve CSV")
    parser.add_argument("positional", nargs="*", help="legacy mode")
    args = parser.parse_args()

    if args.data:
        evaluate_single(data_path=args.data, save_path=args.save, save_threshold_curve=not args.no_curve)
    elif len(args.positional) >= 2:
        evaluate_two_csvs(args.positional[0], args.positional[1], args.positional[2] if len(args.positional) >= 3 else args.save)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()