"""
SecureMailScope — Anomaly Detection Module

Uses Isolation Forest to detect statistically anomalous TLS sessions
that deviate from the baseline of "normal" email traffic patterns.

Anomalies include:
- Unexpected protocol downgrades
- Unusual cipher suite selections
- Sudden appearance of self-signed certificates
- Abnormal key lengths or signature algorithms
- Deviation from established communication patterns
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_engineering import NUMERICAL_FEATURES, get_feature_matrix


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for TLS session metadata.

    Learns the "normal" distribution of cryptographic parameters from
    the dataset and flags sessions that are statistically unusual.
    """

    def __init__(self, contamination: float = 0.1, n_estimators: int = 100, random_state: int = 42):
        """
        Initialize the anomaly detector.

        Args:
            contamination: Expected proportion of anomalies in the data (0.0 to 0.5).
            n_estimators: Number of isolation trees.
            random_state: Random seed for reproducibility.
        """
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fit the model on the dataset and predict anomalies.

        For hackathon purposes, we fit and predict on the same data
        since we don't have a separate "known good" baseline.
        In production, you'd fit on verified-clean traffic first.

        Args:
            df: DataFrame with numerical features from feature_engineering.

        Returns:
            DataFrame with added anomaly columns.
        """
        X = get_feature_matrix(df)

        if len(X) < 2:
            # Not enough data for meaningful anomaly detection
            df = df.copy()
            df["anomaly_score"] = 0.0
            df["is_anomalous"] = False
            df["anomaly_label"] = "NORMAL"
            return df

        # Scale features for better Isolation Forest performance
        X_scaled = self.scaler.fit_transform(X)

        # Fit and predict
        self.model.fit(X_scaled)
        predictions = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        scores = self.model.decision_function(X_scaled)  # Lower = more anomalous

        self.is_fitted = True

        # Add results to DataFrame
        df = df.copy()

        # Normalize anomaly score to 0.0 (normal) to 1.0 (most anomalous)
        min_score = scores.min()
        max_score = scores.max()
        if max_score > min_score:
            normalized = 1.0 - (scores - min_score) / (max_score - min_score)
        else:
            normalized = np.zeros_like(scores)

        df["anomaly_score"] = np.round(normalized, 4)
        df["is_anomalous"] = predictions == -1
        df["anomaly_label"] = df["is_anomalous"].map({True: "ANOMALOUS", False: "NORMAL"})

        return df

    def get_anomaly_explanations(self, df: pd.DataFrame) -> list[dict]:
        """
        Generate human-readable explanations for detected anomalies.

        Identifies which features contributed most to the anomaly classification
        by comparing anomalous sessions to the dataset mean.
        """
        explanations = []

        if "is_anomalous" not in df.columns:
            return explanations

        anomalous = df[df["is_anomalous"] == True]
        if anomalous.empty:
            return explanations

        # Get available numerical columns
        available_cols = [c for c in NUMERICAL_FEATURES if c in df.columns]
        if not available_cols:
            return explanations

        # Calculate dataset statistics
        means = df[available_cols].mean()
        stds = df[available_cols].std().replace(0, 1)  # Avoid div by zero

        feature_descriptions = {
            "tls_version_score": "TLS version",
            "cipher_strength_score": "cipher strength",
            "has_forward_secrecy": "forward secrecy",
            "key_exchange_score": "key exchange strength",
            "compression_enabled": "TLS compression",
            "cert_key_length_score": "certificate key length",
            "cert_sig_algo_score": "signature algorithm strength",
            "cert_is_self_signed": "self-signed certificate",
            "cert_is_expired": "expired certificate",
            "cert_is_weak_key": "weak certificate key",
            "cert_is_weak_signature": "weak signature algorithm",
            "cert_days_until_expiry": "certificate expiry timeline",
            "weak_ciphers_offered_ratio": "weak cipher offering ratio",
        }

        for idx, row in anomalous.iterrows():
            session_id = row.get("session_id", str(idx))
            deviations = []

            for col in available_cols:
                val = row[col]
                z_score = abs((val - means[col]) / stds[col])

                if z_score > 1.5:  # Significant deviation
                    desc = feature_descriptions.get(col, col)
                    direction = "unusually low" if val < means[col] else "unusually high"
                    deviations.append({
                        "feature": col,
                        "description": f"{desc} is {direction}",
                        "value": float(val),
                        "mean": float(means[col]),
                        "z_score": round(float(z_score), 2),
                    })

            # Sort by z-score (most significant deviations first)
            deviations.sort(key=lambda x: x["z_score"], reverse=True)

            explanations.append({
                "session_id": session_id,
                "anomaly_score": float(row.get("anomaly_score", 0)),
                "top_deviations": deviations[:5],  # Top 5 contributing factors
                "summary": _generate_anomaly_summary(deviations),
            })

        return explanations


def _generate_anomaly_summary(deviations: list[dict]) -> str:
    """Generate a one-line human-readable summary of an anomaly."""
    if not deviations:
        return "Anomalous session detected with no clear single factor."

    top = deviations[0]
    return f"Primarily anomalous due to {top['description']} (z-score: {top['z_score']})."


def detect_anomalies(df: pd.DataFrame, contamination: float = 0.1) -> tuple[pd.DataFrame, list[dict]]:
    """
    Convenience function: run anomaly detection on a feature DataFrame.

    Returns:
        Tuple of (updated DataFrame, list of anomaly explanations)
    """
    detector = AnomalyDetector(contamination=contamination)
    df = detector.fit_predict(df)
    explanations = detector.get_anomaly_explanations(df)
    return df, explanations
