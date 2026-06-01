# IDS_inferencing.py
# Preprocessing, feature selection, and model inference pipeline.
# EEE 196 / EEE 199 — Group Zero, UP Diliman

import json
import logging
import os
import sys
import warnings
from pathlib import Path

import joblib
import pandas as pd

# Mute the pandas downcasting warning globally
warnings.simplefilter(action='ignore', category=FutureWarning)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

class TONIoTPreprocessor:
    """
    Applies the exact same cleaning and encoding steps used in train_model_v2.py.
    Crucially omits drop_duplicates() so no live traffic is ignored!
    """
    BINARY_COLS = [
        "dns_query", "ssl_version", "ssl_cipher", "ssl_subject", "ssl_issuer",
        "http_uri", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
        "weird_name", "history", "mqtt_topic", "mqtt_qos",
    ]
    DROP_COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "type", "label", "source"]

    def __init__(self, feature_names):
        self.feature_names = feature_names

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # Save IP columns for alerting
        saved_ips = {}
        for col in ("src_ip", "dst_ip"):
            if col in df.columns:
                saved_ips[col] = df[col].values

        # Drop non-feature identifiers
        df.drop(columns=[c for c in self.DROP_COLS if c in df.columns], inplace=True)

        # Normalise missing values safely (Pandas 2.2.3 compliant)
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].fillna("n/a")
                df[col] = df[col].replace(["-", "(empty)"], "n/a")

        # Binarize specific fields gracefully
        binary_updates = {}
        for col in self.BINARY_COLS:
            if col in df.columns:
                is_missing = df[col].astype(str).str.lower().isin(["nan", "n/a", "-", "(empty)", ""])
                binary_updates[col] = (~is_missing).astype(int)
            else:
                binary_updates[col] = pd.Series(0, index=df.index)
        df = df.assign(**binary_updates)

        # One-hot encode remaining categorical columns
        cat_cols = [c for c in df.columns if df[c].dtype == "object" and c not in self.BINARY_COLS]
        for col in cat_cols:
            df[col] = df[col].astype(str)
        df = pd.get_dummies(df, columns=cat_cols, sparse=False)

        # Align EXACTLY to the features the model was trained on
        missing_cols = {col: pd.Series(0.0, index=df.index) for col in self.feature_names if col not in df.columns}
        if missing_cols:
            df = pd.concat([df, pd.DataFrame(missing_cols)], axis=1)

        # Enforce column order and float type
        df = df[self.feature_names].apply(pd.to_numeric, errors="coerce").fillna(0).astype("float32")

        # Re-attach IP columns
        for col in ("src_ip", "dst_ip"):
            if col in saved_ips:
                df.insert(0, col, saved_ips[col])

        return df


class TONIoTInferencer:
    """End-to-end inference using Group Zero's newly trained models."""
    BENIGN_CLASS = "normal"

    def __init__(self, model_paths, feature_names_path, label_encoder_path=None):
        self.models = {}
        for name, path in model_paths.items():
            if os.path.exists(path):
                self.models[name] = joblib.load(path)
        
        if not self.models:
            raise FileNotFoundError(f"No models found in {model_paths}")

        # Load feature names
        if str(feature_names_path).endswith(".json"):
            with open(feature_names_path) as f:
                self.feature_names = json.load(f)
        else:
            self.feature_names = joblib.load(feature_names_path)
        
        self.preprocessor = TONIoTPreprocessor(self.feature_names)

        # THE FIX: Hardcode the classes to match the 0/1 integers from training exactly.
        # We completely ignore label_encoder.pkl because it sorts alphabetically to ['attack', 'normal'].
        self.classes = ["normal", "attack"]
        
        log.info("Loaded Group Models: %s", list(self.models.keys()))

    def prepare(self, raw_df):
        return self.preprocessor.transform(raw_df)

    def predict(self, raw_df, model="xgb"):
        if model not in self.models:
            model = next(iter(self.models))
        
        X = self.prepare(raw_df)
        
        # Pull IPs out before predicting
        ip_cols = {}
        for col in ("src_ip", "dst_ip"):
            if col in X.columns:
                ip_cols[col] = X.pop(col).values

        clf = self.models[model]
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            preds = clf.predict(X)
            probs = clf.predict_proba(X)
        
        labels = [self.classes[p] if p < len(self.classes) else f"class_{p}" for p in preds]

        result = pd.DataFrame({
            "prediction": preds,
            "label": labels,
            "is_attack": [lbl != self.BENIGN_CLASS for lbl in labels],
            "confidence": probs.max(axis=1).round(4),
        })

        for i, cls_name in enumerate(self.classes):
            if i < probs.shape[1]:
                result[f"prob_{cls_name}"] = probs[:, i].round(4)

        for col in ("src_ip", "dst_ip"):
            if col in ip_cols:
                result.insert(0, col, ip_cols[col])

        return result

if __name__ == "__main__":
    pass