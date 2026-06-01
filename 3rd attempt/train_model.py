"""
train_model.py — IoT IDS Thesis Model Trainer
EEE 196 / EEE 199 — Group Zero, UP Diliman

Trains XGBoost, Decision Tree, and Random Forest models on a merged
dataset composed of:
  • Your IoT testbed captures  (dataset_training_iot.csv)
  • TON-IoT network dataset    (train_test_network.csv)

Both datasets share a Zeek-style schema but have non-overlapping columns:
  - Testbed-only : MQTT fields (mqtt_topic, mqtt_qos, …), history
  - TON-IoT-only : ssl_subject, ssl_issuer, http_user_agent,
                   http_orig_mime_types, http_resp_mime_types,
                   http_trans_depth, http_version,
                   http_request_body_len, http_response_body_len

Missing columns in either source are filled with "n/a" so the merged
feature space is the union of both schemas.

OUTPUT FILES:
  xgb_final_model.pkl          — XGBoost binary classifier
  dt_final_model.pkl           — Decision Tree classifier
  rf_final_model.pkl           — Random Forest classifier
  selected_feature_names.pkl   — ordered feature list for inference
  feature_importance.txt       — Section 5.2 reference
  training_report.txt          — metrics for Section 4.4

USAGE:
  python3 train_model.py
  python3 train_model.py --trials 50 --no-smote
  python3 train_model.py \\
      --testbed datasets/dataset_training_iot.csv \\
      --toniot  datasets/train_test_network.csv   \\
      --trials 50 --out live_inferencing/
"""

import argparse
import os
import sys
import time
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("[WARN] imbalanced-learn not installed — SMOTE disabled. "
          "Install with: pip install imbalanced-learn --break-system-packages")

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False
    print("[WARN] optuna not installed — using default hyperparameters. "
          "Install with: pip install optuna --break-system-packages")

from xgboost import XGBClassifier


# ── Args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--testbed",  default="datasets/dataset_training_iot.csv",
                    help="Path to your IoT testbed CSV")
parser.add_argument("--toniot",   default="datasets/train_test_network.csv",
                    help="Path to the TON-IoT network CSV")
parser.add_argument("--trials",   type=int, default=50,
                    help="Optuna HPO trials for XGBoost")
parser.add_argument("--no-smote", action="store_true",
                    help="Skip SMOTE; use sample_weight='balanced' instead")
parser.add_argument("--out",      default="live_inferencing",
                    help="Output directory for model/artifact files")
args = parser.parse_args()

USE_SMOTE = HAS_SMOTE and not args.no_smote
os.makedirs(args.out, exist_ok=True)

def out(fname):
    return os.path.join(args.out, fname)


# ── Schema constants ──────────────────────────────────────────────────────────

# Columns dropped before training (identifiers, not features)
BASE_DROP = ["src_ip", "dst_ip", "src_port", "dst_port"]

# We will populate the final DROP_COLS after loading the data to catch all dns_*

# Columns binarised to 1 (field present / non-null) vs 0 (field absent / "n/a")
BINARY_COLS = [
    # Shared
    "ssl_version", "ssl_cipher", "ssl_subject", "ssl_issuer",
    "http_uri", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "weird_name",
    # Testbed-only
    "history", "mqtt_topic", "mqtt_qos",
]

# Columns that exist only in the testbed dataset; filled with "n/a" for TON-IoT
TESTBED_ONLY_COLS = [
    "history",
    "mqtt_topic", "mqtt_topic_len", "mqtt_payload_len", "mqtt_qos",
    "mqtt_retain", "mqtt_from_client", "mqtt_status",
]

# Columns that exist only in TON-IoT; filled with "n/a" for testbed rows
TONIOT_ONLY_COLS = [
    "ssl_subject", "ssl_issuer",
    "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "http_trans_depth", "http_version",
    "http_request_body_len", "http_response_body_len",
]

# Per-source row caps (applied before merge to prevent either source dominating)
# Testbed caps
TESTBED_MAX_NORMAL = 60_000   # healthy ESP32 traffic baseline
TESTBED_MAX_ATTACK = 30_000   # per attack type

# TON-IoT caps  (dataset is already pre-balanced at ~20k/class,
#                but we cap normal to stay proportional with testbed)
TONIOT_MAX_NORMAL  = 20_000
TONIOT_MAX_ATTACK  = 5_000   # per attack type


# ════════════════════════════════════════════════════════════════════════════════
# STEP 1 — Load & harmonise both datasets
# ════════════════════════════════════════════════════════════════════════════════
print("\n[1/5] Loading datasets...")

for path, name in [(args.testbed, "Testbed"), (args.toniot, "TON-IoT")]:
    if not os.path.exists(path):
        print(f"[ERROR] {name} dataset not found: {path}")
        sys.exit(1)

df_testbed = pd.read_csv(args.testbed, low_memory=False)
df_toniot  = pd.read_csv(args.toniot,  low_memory=False)

raw_testbed_len = len(df_testbed)
raw_toniot_len  = len(df_toniot)

print(f"      Testbed raw rows : {raw_testbed_len:,}")
print(f"      TON-IoT raw rows : {raw_toniot_len:,}")
print(f"      Testbed columns  : {df_testbed.columns.tolist()}")
print(f"      TON-IoT columns  : {df_toniot.columns.tolist()}")

# ── 1a. Tag source so we can report provenance ────────────────────────────────
df_testbed["_source"] = "testbed"
df_toniot["_source"]  = "toniot"

# ── 1b. Normalise "-" sentinel to "n/a" in both before anything else ─────────
df_testbed.replace("-", "n/a", inplace=True)
df_toniot.replace("-",  "n/a", inplace=True)

# ── 1c. Fill schema gaps with "n/a" so union merge is clean ──────────────────
for col in TESTBED_ONLY_COLS:
    if col not in df_toniot.columns:
        df_toniot[col] = "n/a"

for col in TONIOT_ONLY_COLS:
    if col not in df_testbed.columns:
        df_testbed[col] = "n/a"

# ── 1d. Per-source row capping ────────────────────────────────────────────────
def cap_by_type(df, max_normal, max_attack, label="dataset"):
    if "type" not in df.columns:
        print(f"      [WARN] 'type' column missing in {label} — skipping cap")
        return df

    def _cap(group):
        limit = max_normal if group.name == "normal" else max_attack
        return group.sample(min(len(group), limit), random_state=42)

    print(f"      Capping {label}: normal≤{max_normal:,}, each attack≤{max_attack:,}")
    before = len(df)
    df = df.groupby("type", group_keys=False).apply(_cap)
    print(f"      {label}: {before:,} → {len(df):,} rows")
    return df

df_testbed = cap_by_type(df_testbed, TESTBED_MAX_NORMAL, TESTBED_MAX_ATTACK, "Testbed")
df_toniot  = cap_by_type(df_toniot,  TONIOT_MAX_NORMAL,  TONIOT_MAX_ATTACK,  "TON-IoT")

# ── 1e. Merge ─────────────────────────────────────────────────────────────────
df = pd.concat([df_testbed, df_toniot], ignore_index=True, sort=False)

print(f"\n      Combined rows: {len(df):,}  "
      f"(testbed {len(df_testbed):,} + TON-IoT {len(df_toniot):,})")
print(f"      Attack type distribution after merge:")
print(df["type"].value_counts().to_string(header=False))

# ── 1f. Drop non-feature columns, service, and ALL DNS features ───────────────
# Dynamically find all DNS-related columns 
dns_cols = [c for c in df.columns if c.startswith('dns_')]

# Define the full list of columns to be purged 
purge_list = BASE_DROP + dns_cols + ['service', 'type', '_source']

print(f"      [*] Purging {len(dns_cols)} DNS features and 'service' column...")
df.drop(columns=[c for c in purge_list if c in df.columns], inplace=True)

# ── 1g. Coerce *_len columns to numeric ───────────────────────────────────────
# When a _len col exists in one source but is filled with "n/a" strings in the
# other, pandas infers dtype=object after concat, which causes them to be
# incorrectly one-hot encoded. We force them back to int64 with "n/a" → 0.
len_cols = [c for c in df.columns if c.endswith("_len")]
for col in len_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(np.int64)
if len_cols:
    print(f"\n      Coerced {len(len_cols)} *_len column(s) to int64: {len_cols}")


# ════════════════════════════════════════════════════════════════════════════════
# STEP 2 — Encode Features
# ════════════════════════════════════════════════════════════════════════════════
print("\n[2/5] Encoding categorical and binary features...")

# Any string column that is NOT in BINARY_COLS and is not the label → one-hot
# Note: *_len columns are already numeric after step 1g and are excluded here.
cat_cols = [
    c for c in df.columns
    if df[c].dtype == "object"
    and c not in BINARY_COLS
    and c != "label"
]

print(f"      Categorical cols to one-hot : {len(cat_cols)}")
print(f"      Binary cols to binarise     : {len([c for c in BINARY_COLS if c in df.columns])}")

# One-hot encode categoricals
for col in cat_cols:
    df[col] = df[col].astype("category")
df = pd.get_dummies(df, columns=cat_cols, sparse=False)

# Binarise: 1 if the field is NOT "n/a", else 0
for col in BINARY_COLS:
    if col in df.columns:
        df[col] = (df[col].astype(str).str.strip() != "n/a").astype(int)

# Drop rows that still contain NaNs (should be minimal after fill above)
missing_before = df.isnull().any(axis=1).sum()
df.dropna(inplace=True)
if missing_before:
    print(f"      Dropped {missing_before:,} rows with remaining NaNs")

print(f"      Post-encoding shape: {df.shape}")


# ════════════════════════════════════════════════════════════════════════════════
# STEP 3 — Split and Balance
# ════════════════════════════════════════════════════════════════════════════════
print("\n[3/5] Splitting data and balancing classes...")

X_raw = df.drop(columns=["label"])
y_raw = df["label"].astype(int)
feature_cols = X_raw.columns.tolist()

# 80 / 20 stratified split
X_train_raw, X_test_raw, y_train_raw, y_test_raw = train_test_split(
    X_raw, y_raw, test_size=0.20, random_state=42, stratify=y_raw
)

print(f"      Feature columns : {len(feature_cols)}")
print(f"      Train  — normal: {(y_train_raw == 0).sum():,}  attack: {(y_train_raw == 1).sum():,}")
print(f"      Test   — normal: {(y_test_raw  == 0).sum():,}  attack: {(y_test_raw  == 1).sum():,}")

if USE_SMOTE:
    print("      Applying SMOTE to training set...")
    smote = SMOTE(random_state=42)
    X_bal, y_bal = smote.fit_resample(X_train_raw, y_train_raw)
    print(f"      After SMOTE — normal: {(y_bal == 0).sum():,}  attack: {(y_bal == 1).sum():,}")
else:
    print("      SMOTE skipped — using compute_sample_weight('balanced') instead")
    X_bal, y_bal = X_train_raw.values, y_train_raw.values

X_bal  = np.array(X_bal,  dtype=np.float32)
y_bal  = np.array(y_bal,  dtype=np.int32)
X_test = np.array(X_test_raw, dtype=np.float32)
y_test = np.array(y_test_raw, dtype=np.int32)

# Internal validation split (used during XGBoost HPO and early-stopping)
X_tr, X_val, y_tr, y_val = train_test_split(
    X_bal, y_bal, test_size=0.20, random_state=42, stratify=y_bal
)
sample_weights = compute_sample_weight("balanced", y_tr)


# ════════════════════════════════════════════════════════════════════════════════
# STEP 4 — Train Models
# ════════════════════════════════════════════════════════════════════════════════
print("\n[4/5] Training models...")

report_lines = []
report_lines.append("=" * 60)
report_lines.append("  IoT IDS — Training Report")
report_lines.append(f"  Testbed dataset : {args.testbed}  ({raw_testbed_len:,} raw rows)")
report_lines.append(f"  TON-IoT dataset : {args.toniot}  ({raw_toniot_len:,} raw rows)")
report_lines.append(f"  Combined after cap: {len(df) + len(df) * 0:.0f} rows (see logs)")
report_lines.append(f"  Training rows   : {X_tr.shape[0]:,}")
report_lines.append(f"  Holdout rows    : {X_test.shape[0]:,}")
report_lines.append(f"  Features        : {len(feature_cols)}")
report_lines.append("=" * 60)


def evaluate(name, model, X_eval, y_eval):
    t0     = time.perf_counter()
    y_pred = model.predict(X_eval)
    t1     = time.perf_counter()
    y_proba = (
        model.predict_proba(X_eval)[:, 1]
        if hasattr(model, "predict_proba")
        else y_pred.astype(float)
    )
    lat_ms = (t1 - t0) / len(X_eval) * 1000

    acc  = accuracy_score(y_eval, y_pred)
    prec = precision_score(y_eval, y_pred, zero_division=0)
    rec  = recall_score(y_eval, y_pred, zero_division=0)
    f1   = f1_score(y_eval, y_pred, zero_division=0)
    auc  = roc_auc_score(y_eval, y_proba)
    cm   = confusion_matrix(y_eval, y_pred)

    lines = [
        f"\n--- {name} ---",
        f"Accuracy  : {acc:.4f}",
        f"Precision : {prec:.4f}",
        f"Recall    : {rec:.4f}",
        f"F1        : {f1:.4f}",
        f"AUC-ROC   : {auc:.4f}",
        f"Latency   : {lat_ms:.6f} ms/row",
        f"Confusion Matrix:\n{cm}",
        classification_report(y_eval, y_pred, target_names=["normal", "attack"]),
    ]
    for line in lines:
        print(line)
    report_lines.extend(lines)
    return f1


# ── XGBoost ───────────────────────────────────────────────────────────────────
print("\n  [XGBoost]")

if HAS_OPTUNA:
    def xgb_objective(trial):
        p = {
            "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.3),
            "max_depth":        trial.suggest_int("max_depth", 5, 20),
            "subsample":        trial.suggest_float("subsample", 0.6, 1.0),
            "min_child_weight": trial.suggest_float("min_child_weight", 0.5, 2.0),
            "n_estimators":     trial.suggest_int("n_estimators", 100, 300),
            "max_leaves":       trial.suggest_int("max_leaves", 1, 9),
            "objective":        "binary:logistic",
            "eval_metric":      "logloss",
            "tree_method":      "hist",
            "device":           "cpu",
            "random_state":     42,
            "n_jobs":           -1,
        }
        sw = sample_weights if not USE_SMOTE else None
        m  = XGBClassifier(**p)
        m.fit(X_tr, y_tr, sample_weight=sw, verbose=False)
        return f1_score(y_val, m.predict(X_val))

    study = optuna.create_study(direction="maximize")
    study.optimize(xgb_objective, n_trials=args.trials, show_progress_bar=True)
    xgb_params = study.best_params
else:
    xgb_params = {
        "learning_rate": 0.1, "max_depth": 7,
        "n_estimators": 200, "subsample": 0.8,
    }

xgb_params.update({
    "objective": "binary:logistic", "eval_metric": "logloss",
    "tree_method": "hist", "device": "cpu", "random_state": 42, "n_jobs": -1,
})
xgb_model = XGBClassifier(**xgb_params)
sw = sample_weights if not USE_SMOTE else None
xgb_model.fit(X_tr, y_tr, sample_weight=sw, eval_set=[(X_val, y_val)], verbose=False)

joblib.dump(xgb_model, out("xgb_final_model.pkl"))
print("  Saved: xgb_final_model.pkl")
evaluate("XGBoost — Holdout Test", xgb_model, X_test, y_test)

# Feature importance (written for Section 5.2)
fi_sorted = sorted(
    zip(feature_cols, xgb_model.feature_importances_),
    key=lambda x: x[1], reverse=True,
)
with open(out("feature_importance.txt"), "w") as f:
    f.write("rank\tfeature\timportance\n")
    for rank, (feat, imp) in enumerate(fi_sorted, 1):
        f.write(f"{rank}\t{feat}\t{imp:.6f}\n")


# ── Decision Tree ─────────────────────────────────────────────────────────────
print("\n  [Decision Tree]")
dt_params = {
    "max_depth": 10, "min_samples_split": 5,
    "criterion": "gini", "random_state": 42,
}
dt_model = DecisionTreeClassifier(**dt_params)
dt_model.fit(X_tr, y_tr, sample_weight=sw)
joblib.dump(dt_model, out("dt_final_model.pkl"))
print("  Saved: dt_final_model.pkl")
evaluate("Decision Tree — Holdout Test", dt_model, X_test, y_test)


# ── Random Forest ─────────────────────────────────────────────────────────────
print("\n  [Random Forest]")
rf_params = {
    "n_estimators": 100, "max_depth": 15,
    "random_state": 42, "n_jobs": -1,
}
rf_model = RandomForestClassifier(**rf_params)
rf_model.fit(X_tr, y_tr, sample_weight=sw)
joblib.dump(rf_model, out("rf_final_model.pkl"))
print("  Saved: rf_final_model.pkl")
evaluate("Random Forest — Holdout Test", rf_model, X_test, y_test)


# ════════════════════════════════════════════════════════════════════════════════
# STEP 5 — Save Inference Artifacts
# ════════════════════════════════════════════════════════════════════════════════
print("\n[5/5] Saving inference artifacts...")

joblib.dump(feature_cols, out("selected_feature_names.pkl"))
print(f"  Saved: selected_feature_names.pkl  ({len(feature_cols)} features)")

report_lines.append("\n" + "=" * 60)
report_lines.append(f"  Features saved : {len(feature_cols)}")
report_lines.append("  Models saved   : xgb, dt, rf")
report_lines.append("=" * 60)

with open(out("training_report.txt"), "w") as f:
    f.write("\n".join(report_lines))
print("  Saved: training_report.txt")

print("\n Training complete.")