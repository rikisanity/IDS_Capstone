"""
infer_live.py — Live inference for the XGBoost IoT intrusion-detection model
=============================================================================
The model is loaded ONCE at startup. You are then prompted to enter CSV file
paths one at a time. Type 'exit' or press Ctrl-C to quit.

Usage
-----
  python infer_live.py

Requirements
------------
  pip install pandas scikit-learn xgboost joblib
"""

import json
from pathlib import Path

import joblib
import pandas as pd

# ── Paths (edit if your files live elsewhere) ─────────────────────────────────
MODEL_PATH   = Path("xgb_final.pkl")
COLUMNS_PATH = Path("model_columns.json")

# ── Columns dropped during training (meta / identity columns) ─────────────────
DROP_COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "label", "type", "source"]

# ── Binary columns: presence/absence encoding (1 if NOT 'n/a', else 0) ────────
BINARY_COLUMNS = [
    "dns_query",
    "ssl_version", "ssl_cipher", "ssl_subject", "ssl_issuer",
    "http_uri", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "weird_name", "history", "mqtt_topic", "mqtt_qos",
]

# ── Categorical columns one-hot-encoded during training ───────────────────────
CATEGORICAL_COLUMNS = [
    "conn_state", "dns_AA", "dns_RA", "dns_RD", "dns_qclass", "dns_qtype",
    "dns_rcode", "dns_rejected", "http_method", "http_request_body_len",
    "http_response_body_len", "http_trans_depth", "http_version",
    "mqtt_from_client", "mqtt_operation", "mqtt_payload_len", "mqtt_retain",
    "mqtt_status", "mqtt_topic_len", "proto", "service",
    "ssl_established", "ssl_resumed", "weird_addl", "weird_notice",
]


# ─────────────────────────────────────────────────────────────────────────────
def load_artifacts():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
    if not COLUMNS_PATH.exists():
        raise FileNotFoundError(f"Column list not found: {COLUMNS_PATH}")

    model = joblib.load(MODEL_PATH)
    with open(COLUMNS_PATH) as f:
        model_columns = json.load(f)

    print(f"[✓] Model loaded from {MODEL_PATH}  ({len(model_columns)} features)")
    return model, model_columns


def preprocess(df: pd.DataFrame, model_columns: list) -> pd.DataFrame:
    df = df.copy()
    df.replace("-", "n/a", inplace=True)
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    for col in CATEGORICAL_COLUMNS:
        if col in df.columns:
            df[col] = df[col].astype("category")
    df = pd.get_dummies(df, columns=[c for c in CATEGORICAL_COLUMNS if c in df.columns], sparse=False)

    for col in BINARY_COLUMNS:
        if col in df.columns:
            df[col] = (df[col] != "n/a").astype(int)
        else:
            df[col] = 0

    missing = [c for c in model_columns if c not in df.columns]
    if missing:
        df = pd.concat([df, pd.DataFrame(0, index=df.index, columns=missing)], axis=1)

    return df[model_columns]


def score(df_raw: pd.DataFrame, model, model_columns: list) -> pd.DataFrame:
    X      = preprocess(df_raw, model_columns)
    preds  = model.predict(X)
    probas = model.predict_proba(X)[:, 1]

    result = df_raw.copy()
    result["prediction"]  = ["Attack" if p == 1 else "Benign" for p in preds]
    result["attack_prob"] = probas.round(4)
    return result


def run_once(input_path: Path, model, model_columns: list):
    df_raw  = pd.read_csv(input_path)
    print(f"[→] Loaded {len(df_raw):,} rows")

    results = score(df_raw, model, model_columns)

    attacks = (results["prediction"] == "Attack").sum()
    benign  = (results["prediction"] == "Benign").sum()
    print(f"[✓] {attacks:,} Attacks | {benign:,} Benign  (total {len(results):,})")

    # Ask where to save
    out = input("    Save output to (press Enter to skip): ").strip()
    if out:
        output_path = Path(out)
        save_cols = (
            ["label", "prediction", "attack_prob"]
            if "label" in results.columns
            else ["prediction", "attack_prob"]
        )
        results[save_cols].to_csv(output_path, index=False)
        print(f"[✓] Saved to {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    model, model_columns = load_artifacts()
    print("\nType a CSV path to score it, or 'exit' to quit.\n")

    while True:
        try:
            raw = input("CSV path: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[✗] Exiting.")
            break

        if raw.lower() in ("exit", "quit", "q"):
            print("[✗] Exiting.")
            break

        if not raw:
            continue

        input_path = Path(raw)
        if not input_path.exists():
            print(f"[!] File not found: {input_path}")
            continue

        try:
            run_once(input_path, model, model_columns)
        except Exception as e:
            print(f"[!] Error: {e}")

        print()


if __name__ == "__main__":
    main()