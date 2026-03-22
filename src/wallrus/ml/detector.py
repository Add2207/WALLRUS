"""
WALLRUS - ML Anomaly Detector (Phase 2 Stub)
=============================================
This module is the integration point for the ML-based anomaly detection engine.

Phase 2 plan:
  - Dataset:   Pre-labelled HTTP request dataset (CSIC 2010, ISCX, or custom)
  - Features:  Extracted by RequestFeatureExtractor (see below)
  - Model:     LightGBM / scikit-learn IsolationForest / RandomForest
  - Training:  train.py script in scripts/
  - Inference: AnomalyDetector.predict() used inside engine.AnomalyEngine

Current state:
  All classes are fully implemented stubs — they return placeholder values
  so the DetectionPipeline in engine.py works end-to-end. Replace the
  `predict` method body once your model is trained.

Feature engineering ideas (implement in RequestFeatureExtractor):
  - Request length (url, query, body)
  - Character entropy of query/body
  - Count of special chars (%,',",<,>,;,|,&)
  - Presence of encoded sequences (%xx)
  - HTTP method encoded as int
  - Number of query parameters
  - Body-to-header size ratio
  - TF-IDF on tokenised request parts (Phase 2 advanced)
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Optional imports — only required when model is trained & loaded
try:
    import joblib  # for loading sklearn / lgbm models
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False


# ── Feature Extractor ─────────────────────────────────────────────────────────
class RequestFeatureExtractor:
    """
    Converts an HTTPRequest into a flat numeric feature vector.
    
    Extend this class in Phase 2 with richer features.
    The feature names list MUST stay in sync with the training script.
    """

    FEATURE_NAMES: List[str] = [
        "url_length",
        "query_length",
        "body_length",
        "header_count",
        "query_param_count",
        "url_entropy",
        "query_entropy",
        "body_entropy",
        "special_char_count_query",
        "special_char_count_body",
        "encoded_sequences_query",
        "encoded_sequences_body",
        "has_sql_keywords",       # soft numeric feature (0/1)
        "has_script_tag",
        "method_encoded",         # GET=0 POST=1 PUT=2 etc.
    ]

    METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}
    SPECIAL    = set("'\"<>;&|(){}[]%\\")
    SQL_KW     = {"select", "union", "insert", "drop", "delete", "sleep", "or", "and"}

    def extract(self, request) -> np.ndarray:
        """
        Return a 1-D numpy array of float features for a single request.
        `request` is a wallrus.core.parser.HTTPRequest instance.
        """
        q = request.query_string or ""
        b = request.body or ""
        u = request.path or ""

        features = [
            len(u),
            len(q),
            len(b),
            len(request.headers),
            len(request.query_params),
            self._entropy(u),
            self._entropy(q),
            self._entropy(b),
            self._special_count(q),
            self._special_count(b),
            self._encoded_count(q),
            self._encoded_count(b),
            self._has_sql_kw(q + " " + b),
            1 if "<script" in (q + b).lower() else 0,
            self.METHOD_MAP.get(request.method.value, 5),
        ]
        return np.array(features, dtype=float)

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def _special_count(self, s: str) -> int:
        return sum(1 for c in s if c in self.SPECIAL)

    @staticmethod
    def _encoded_count(s: str) -> int:
        return s.count("%")

    def _has_sql_kw(self, s: str) -> int:
        tokens = set(s.lower().split())
        return 1 if tokens & self.SQL_KW else 0


# ── Anomaly Detector ──────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Phase 2 ML inference interface.

    Usage (after training):
        detector = AnomalyDetector.load("data/models/waf_model.joblib")
        result   = detector.predict(request)

    Current state:
        The `predict` method returns a null result until a model is trained.
        Run `python scripts/train.py` to train and save a model.
    """

    def __init__(self, model=None, extractor: Optional[RequestFeatureExtractor] = None):
        self.model     = model
        self.extractor = extractor or RequestFeatureExtractor()

    @classmethod
    def load(cls, model_path: str | Path) -> "AnomalyDetector":
        """Load a pre-trained joblib model."""
        if not JOBLIB_AVAILABLE:
            raise ImportError("joblib is required to load a model: pip install joblib")
        model = joblib.load(model_path)
        return cls(model=model)

    def predict(self, request) -> Tuple[float, List[str]]:
        """
        Returns (anomaly_score: float 0–1, flags: List[str]).

        anomaly_score = 0.0 → definitely benign
        anomaly_score = 1.0 → highly anomalous

        TODO Phase 2 — replace this stub with real inference:
            features = self.extractor.extract(request).reshape(1, -1)
            proba    = self.model.predict_proba(features)[0][1]  # P(malicious)
            flags    = self._flag_reasons(features[0], proba)
            return proba, flags
        """
        if self.model is None:
            return 0.0, []

        # ── Real inference (uncomment after training) ──────────────────────
        # features = self.extractor.extract(request).reshape(1, -1)
        # proba    = float(self.model.predict_proba(features)[0][1])
        # flags    = self._flag_reasons(features[0], proba)
        # return proba, flags

        return 0.0, []

    def _flag_reasons(self, feature_vec: np.ndarray, score: float) -> List[str]:
        """
        Return human-readable strings explaining why the model flagged the request.
        Uses simple threshold heuristics on raw features.
        Upgrade to SHAP values in Phase 2 advanced.
        """
        flags = []
        names = RequestFeatureExtractor.FEATURE_NAMES
        for name, val in zip(names, feature_vec):
            if name == "query_entropy" and val > 4.5:
                flags.append(f"High query entropy ({val:.2f}) — possible encoding")
            if name == "special_char_count_query" and val > 8:
                flags.append(f"High special char count in query ({int(val)})")
            if name == "encoded_sequences_query" and val > 5:
                flags.append(f"Many URL-encoded sequences ({int(val)})")
            if name == "has_sql_keywords" and val:
                flags.append("SQL keywords detected in request body")
        return flags


# ── Training script template ───────────────────────────────────────────────────
# See scripts/train.py for the full training pipeline.
# Outline:
#
#   1. Load data/processed/labelled_requests.csv
#   2. Instantiate RequestFeatureExtractor, extract features for all rows
#   3. Split train/test
#   4. Train LightGBMClassifier (or IsolationForest for unsupervised)
#   5. Evaluate: precision, recall, F1, ROC-AUC
#   6. joblib.dump(model, "data/models/waf_model.joblib")
#   7. Save feature_names and scaler alongside the model
