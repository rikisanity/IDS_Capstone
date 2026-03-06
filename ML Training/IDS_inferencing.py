import pandas as pd
import numpy as np
import joblib
import json


class TONIoTPreprocessor:
    """Handles all preprocessing steps from dataset_preprocessing.ipynb"""

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
    drop_columns = ["src_ip", "src_port", "dst_ip", "dst_port", "label", "type"]

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df.replace("-", "n/a", inplace=True)
        df.drop_duplicates(inplace=True)
        df.drop(columns=self.drop_columns, errors='ignore', inplace=True)

        for col in self.one_hot_columns + self.binary_columns:
            if col in df.columns:
                df[col] = df[col].astype('category')

        df = pd.get_dummies(df, columns=[c for c in self.one_hot_columns if c in df.columns], sparse=False)

        for col in self.binary_columns:
            if col in df.columns:
                df[col] = (df[col] != 'n/a').astype(int)

        return df


class TONIoTFeatureSelector:
    """Handles feature selection from feature_selection.ipynb"""

    def __init__(self, feature_names_path: str):
        self.feature_names = self._load(feature_names_path)

    def _load(self, path: str):
        if path.endswith('.json'):
            with open(path) as f:
                return json.load(f)
        return joblib.load(path)  # .pkl

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        # Add any missing columns as 0, then select only the trained features
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        return df[self.feature_names].astype(float)


class TONIoTInferencer:

    LABEL_MAP = {0: 'benign', 1: 'attack'}

    def __init__(self, model_paths: dict, feature_names_path: str):
        self.preprocessor = TONIoTPreprocessor()
        self.selector = TONIoTFeatureSelector(feature_names_path)
        self.models = self._load_models(model_paths)
        print(f"✔ Loaded models: {list(self.models.keys())}")

    def _load_models(self, model_paths: dict) -> dict:
        return {name: joblib.load(path) for name, path in model_paths.items()}

    def _run_pipeline(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        processed = self.preprocessor.transform(raw_df)
        return self.selector.transform(processed)

    def predict(self, raw_df: pd.DataFrame, model: str = 'xgb') -> pd.DataFrame:
        if model not in self.models:
            raise ValueError(f"Model '{model}' not found. Available: {list(self.models.keys())}")

        X = self._run_pipeline(raw_df)
        clf = self.models[model]

        predictions   = clf.predict(X)
        probabilities = clf.predict_proba(X)

        return pd.DataFrame({
            'prediction':  predictions,
            'label':       [self.LABEL_MAP[p] for p in predictions],
            'confidence':  probabilities.max(axis=1).round(4),
            'prob_benign': probabilities[:, 0].round(4),
            'prob_attack': probabilities[:, 1].round(4),
        })

    def predict_all(self, raw_df: pd.DataFrame) -> dict:
        """Run inference on all loaded models and return a dict of results."""
        return {name: self.predict(raw_df, model=name) for name in self.models}

    def get_model_params(self, model: str = None):
        """View hyperparameters of one or all models."""
        if model:
            return self.models[model].get_params()
        return {name: clf.get_params() for name, clf in self.models.items()}
    
if __name__ == "__main__":
    # ── Initialize ────────────────────────────────────────────────────────────────
    inferencer = TONIoTInferencer(
        model_paths={
            'xgb': 'xgb_final_model.pkl',
            'dt':  'dt_final_model.pkl',
            'rf':  'rf_final_model.pkl',
        },
        feature_names_path='selected_feature_names.pkl'
    )

    # ── Load new raw traffic data ─────────────────────────────────────────────────
    new_data = pd.read_csv('train_test_network.csv')

    # # ── Single model prediction ───────────────────────────────────────────────────
    # results = inferencer.predict(new_data, model='xgb')
    # print(results.head())

    # ── Run all models at once ────────────────────────────────────────────────────
    all_results = inferencer.predict_all(new_data)
    for model_name, df in all_results.items():
        print(f"\n── {model_name.upper()} ──")
        print(df.head())

    # ── View hyperparameters ──────────────────────────────────────────────────────
    # print(inferencer.get_model_params('xgb'))   # single model
    # print(inferencer.get_model_params())        # all models