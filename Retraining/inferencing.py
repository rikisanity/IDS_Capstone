import os
import sys
import joblib
import warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

class Preprocessor:
    
    one_hot_columns = [
        "proto", "service", "conn_state",
        "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
        "ssl_resumed", "ssl_established",
        "http_trans_depth", "http_method", "http_version",
        "weird_addl", "weird_notice",
    ]
    binary_columns = [
        "dns_query",
        "ssl_version", "ssl_cipher", "ssl_subject", "ssl_issuer",
        "http_uri", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
        "weird_name",
    ]
    # Removed src_ip and dst_ip from drop_columns so they are preserved
    drop_columns = ["src_ip", "dst_ip", "src_port", "dst_port", "label", "type"]

    categorical_columns = one_hot_columns + binary_columns

    def __init__(self, encoders: dict):
        """
        Parameters
        ----------
        encoders : dict
            Dictionary of {column_name: fitted LabelEncoder}
            loaded from encoders_retrained.pkl
        """
        self.encoders = encoders
    
    def transform(self, df: pd.DataFrame):
        """
        Preprocess raw input DataFrame.
 
        Returns
        -------
        X : pd.DataFrame
            Feature matrix ready for model inference
        y_true : pd.Series or None
            Ground truth labels if 'label' column was present, else None
        """
        df = df.copy()
        df.replace("-", "n/a", inplace=True)
        df.drop(columns=self.drop_columns, errors='ignore', inplace=True)

        if "label" in df.columns:
            df = df.drop(columns=["label"])

        df.drop(columns=[c for c in self.drop_columns if c in df.columns],
                inplace=True, errors="ignore")

        unseen_warnings = []
        for col in self.categorical_columns:
            if col not in df.columns or col not in self.encoders:
                continue
 
            le      = self.encoders[col]
            col_str = df[col].astype(str)
            known   = set(le.classes_)
            unseen  = ~col_str.isin(known)
 
            if unseen.any():
                unseen_warnings.append((col, col_str[unseen].unique().tolist()))
                col_str[unseen] = le.classes_[0]  # safe fallback
 
            df[col] = le.transform(col_str)
        
        if unseen_warnings:
            print("[WARN] Unseen categories mapped to fallback:")
            for col, vals in unseen_warnings:
                print(f"       {col}: {vals}")
 
        # ── 5. Cast everything to float (Cell 12 numeric cast) ────────────────
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(float)
 
        return df
    
class Inferencer:

    LABEL_MAP = {0: "benign", 1: "attack"}

    def __init__(self, model_path: str, encoders_path: str):
        """
        Parameters
        ----------
        model_path    : str — path to xgb_retrained.pkl
        encoders_path : str — path to encoders_retrained.pkl
        """
        self.encoders     = self._load_encoders(encoders_path)
        self.preprocessor = Preprocessor(self.encoders)
        self.model        = self._load_model(model_path)
        print(f"[OK] Encoders loaded : {encoders_path} ({len(self.encoders)} columns)")
        print(f"[OK] Model loaded    : {model_path}")

    def _load_encoders(self, path: str) -> dict:
        if not os.path.exists(path):
            print(f"[ERROR] Encoders file not found: {path}")
            sys.exit(1)
        return joblib.load(path)
    
    def _load_model(self, path: str):
        if not os.path.exists(path):
            print(f"[ERROR] Model file not found: {path}")
            sys.exit(1)
        return joblib.load(path)
    
    def _run_pipeline(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess raw DataFrame and return feature matrix X."""
        return self.preprocessor.transform(raw_df)
    
    def predict(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """
        Run inference on a raw traffic DataFrame.
 
        Parameters
        ----------
        raw_df : pd.DataFrame
            Raw network traffic (unprocessed, as collected from the testbed)
 
        Returns
        -------
        pd.DataFrame with columns:
            prediction  — 0 (benign) or 1 (attack)
            label       — 'benign' or 'attack'
            confidence  — max class probability
            prob_benign — probability of class 0
            prob_attack — probability of class 1
        """
        X             = self._run_pipeline(raw_df)
        predictions   = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
 
        return pd.DataFrame({
            "prediction" : predictions,
            "label"      : [self.LABEL_MAP[p] for p in predictions],
            "confidence" : probabilities.max(axis=1).round(4),
            "prob_benign": probabilities[:, 0].round(4),
            "prob_attack": probabilities[:, 1].round(4),
        })
    
    def save_predictions(self, raw_df: pd.DataFrame,
                         results_df: pd.DataFrame,
                         output_path: str):
        """
        Append prediction columns to the original DataFrame and save as CSV.
 
        Parameters
        ----------
        raw_df      : original input DataFrame (before preprocessing)
        results_df  : output of predict()
        output_path : path to write the output CSV
        """
        output = results_df[["prediction", "confidence"]].reset_index(drop=True)
        output.to_csv(output_path, index=False)
        print(f"[OK] Predictions saved to: {output_path}")

    def get_model_params(self):
        """Return hyperparameters of the loaded XGBoost model."""
        return self.model.get_params()
    
if __name__ == "__main__":
 
    # ── Load model and encoders once ─────────────────────────────────────────
    inferencer = Inferencer(
        model_path    = "xgb_retrained.pkl",
        encoders_path = "encoders_retrained.pkl"
    )
 
    print("\n" + "=" * 55)
    print("  IDS Inference — ready")
    print("  Type the path to a CSV file to run inference.")
    print("  Type 'exit' or 'quit' to stop.")
    print("=" * 55)
 
    # ── Continuous input loop ─────────────────────────────────────────────────
    while True:
        try:
            input_path = input("\nEnter CSV path: ").strip()
 
            if input_path.lower() in ("exit", "quit"):
                print("Exiting.")
                break
 
            if not input_path:
                continue
 
            if not os.path.exists(input_path):
                print(f"[ERROR] File not found: {input_path}")
                continue
 
            if not input_path.endswith(".csv"):
                print("[ERROR] Only CSV files are supported.")
                continue
 
            # Load input
            raw_data = pd.read_csv(input_path)
            print(f"[OK] Loaded {raw_data.shape[0]} rows from {input_path}")
 
            # Run inference
            results = inferencer.predict(raw_data)
 
            # Print summary
            total   = len(results)
            attacks = int((results["prediction"] == 1).sum())
            benign  = total - attacks
            print(f"     Predicted benign : {benign}  ({benign/total:.1%})")
            print(f"     Predicted attack : {attacks} ({attacks/total:.1%})")
 
            # Auto-generate output path next to the input file
            base        = os.path.splitext(input_path)[0]
            output_path = f"{base}_predictions.csv"
            inferencer.save_predictions(raw_data, results, output_path)
 
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            continue
