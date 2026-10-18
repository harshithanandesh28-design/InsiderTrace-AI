"""Insider Threat Anomaly Detection and Explainable Risk Scoring Engine.

Combines scikit-learn's Isolation Forest with a rule-based deterministic scoring engine
to produce calibrated risk scores (0–100), transparent risk factors, and actionable explanations.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class RiskEvaluation:
    """Detailed risk assessment for a single activity event."""
    risk_score: float
    risk_level: str
    is_anomaly: bool
    ml_score: float
    rule_score: float
    risk_factors: List[str]
    explanation: str
    soc_recommendation: str


def calculate_rule_risk(row: pd.Series) -> Tuple[float, List[str]]:
    """Evaluate deterministic cyber rules and return (rule_score, risk_factors)."""
    score = 0.0
    factors: List[str] = []

    download_mb = float(row.get("download_mb", 0.0))
    is_after_hours = bool(row.get("is_after_hours", False))
    is_sensitive = bool(row.get("is_sensitive", False))
    location = str(row.get("location", ""))
    device_type = str(row.get("device_type", ""))
    action = str(row.get("action", ""))
    file_cat = str(row.get("file_category", ""))
    hour = int(row.get("activity_hour", 12))

    # Rule 1: Massive Volume
    if download_mb >= 5000.0:
        score += 40.0
        factors.append(f"Critical data volume exfiltration ({download_mb:,.1f} MB exceeds 5,000 MB baseline)")
    elif download_mb >= 1500.0:
        score += 25.0
        factors.append(f"High data volume transfer ({download_mb:,.1f} MB exceeds 1,500 MB baseline)")
    elif download_mb >= 500.0:
        score += 12.0
        factors.append(f"Elevated download volume ({download_mb:,.1f} MB)")

    # Rule 2: After-Hours Access
    if is_after_hours:
        if hour in [0, 1, 2, 3, 4, 5]:
            score += 22.0
            factors.append(f"Unusual graveyard shift activity detected at {hour:02d}:00")
        else:
            score += 14.0
            factors.append(f"Off-hours access recorded outside normal 07:00-19:00 shift")

    # Rule 3: Sensitive File Access
    if is_sensitive:
        score += 18.0
        factors.append(f"Access to confidential or sensitive classified asset ({file_cat})")

    # High Correlation: After-Hours + Sensitive
    if is_after_hours and is_sensitive:
        score += 20.0
        factors.append("Compound threat: Sensitive classified data accessed outside business hours")

    # Rule 4: Suspicious Location / Infrastructure
    suspicious_keywords = ["tor", "proxy", "bulletproof", "unrecognized", "coffee shop", "foreign"]
    if any(k in location.lower() for k in suspicious_keywords):
        score += 25.0
        factors.append(f"Anomalous network egress point detected: '{location}'")

    # Rule 5: Unmanaged / BYOD Device
    if any(d in device_type.lower() for d in ["personal", "byod", "unknown"]):
        score += 15.0
        factors.append(f"Unmanaged corporate endpoint: '{device_type}'")

    # Rule 6: High Risk Action
    if action == "EXTERNAL_SHARE":
        score += 20.0
        factors.append("External cloud/direct sharing permission invoked")
    elif action == "FILE_DOWNLOAD" and is_sensitive:
        score += 10.0
        factors.append("Direct local export of sensitive file")

    # Rule 7: High-Value Asset Category
    if file_cat in ["Infrastructure", "Intellectual Property"]:
        score += 12.0
        factors.append(f"Target is crown-jewel asset: {file_cat}")

    # Cap rule score to 100
    rule_score = min(100.0, score)
    return rule_score, factors


def generate_event_explanation(
    emp_name: str,
    risk_level: str,
    risk_score: float,
    factors: List[str],
    is_anomaly: bool,
    action: str,
    file_name: str
) -> Tuple[str, str]:
    """Generate human-readable SOC triage narrative and recommendation."""
    if not factors and not is_anomaly:
        explanation = (
            f"Routine operational activity by {emp_name}. {action} on '{file_name}' conforms to "
            f"standard organizational patterns with no behavioral deviation."
        )
        recommendation = "No intervention necessary. Maintain standard audit logging."
        return explanation, recommendation

    factor_text = "; ".join(factors) if factors else "Statistical behavioral anomaly identified by Isolation Forest."
    
    explanation = (
        f"Event for {emp_name} triggered an elevated risk score of {risk_score:.0f}/100 [{risk_level}]. "
        f"Key behavioral signals: {factor_text}."
    )

    if risk_level == "CRITICAL":
        rec = (
            "CRITICAL: Immediate SOC Analyst triage recommended. Contact employee's direct manager, "
            "verify HR offboarding or performance status, and evaluate temporary DLP credential isolation."
        )
    elif risk_level == "HIGH":
        rec = (
            "HIGH: SOC Tier-2 escalation. Validate whether this activity corresponds to an approved Jira change ticket "
            "or legitimate backup maintenance. Cross-check VPN authentication logs."
        )
    elif risk_level == "MEDIUM":
        rec = (
            "MEDIUM: Low-urgency review. Log for automated correlation in the employee's 30-day behavioral trend. "
            "Flag for weekly supervisor digest."
        )
    else:
        rec = "LOW: Benign variance. Review only if part of repeated alert clusters."

    return explanation, rec


class AnomalyDetectionEngine:
    """Encapsulates Isolation Forest training and composite risk evaluation."""

    def __init__(self, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_columns = [
            "download_mb",
            "activity_hour",
            "is_after_hours_num",
            "is_sensitive_num",
            "is_suspicious_net",
            "is_unmanaged_dev"
        ]

    def _prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer numerical features for the Isolation Forest."""
        feats = pd.DataFrame(index=df.index)
        feats["download_mb"] = pd.to_numeric(df["download_mb"], errors="coerce").fillna(0.0)
        feats["activity_hour"] = pd.to_numeric(df["activity_hour"], errors="coerce").fillna(12.0)
        feats["is_after_hours_num"] = df["is_after_hours"].astype(int)
        feats["is_sensitive_num"] = df["is_sensitive"].astype(int)
        
        suspicious_net_keys = ["tor", "proxy", "bulletproof", "unrecognized", "foreign", "open wi-fi"]
        feats["is_suspicious_net"] = df["location"].astype(str).str.lower().apply(
            lambda loc: 1 if any(k in loc for k in suspicious_net_keys) else 0
        )
        
        feats["is_unmanaged_dev"] = df["device_type"].astype(str).str.lower().apply(
            lambda dev: 1 if any(k in dev for k in ["personal", "byod", "unknown"]) else 0
        )
        return feats[self.feature_columns]

    def fit_and_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit Isolation Forest on the dataset, compute ML and rule scores, and return enriched DataFrame."""
        if df.empty:
            return df.copy()

        df_out = df.copy()
        features = self._prepare_features(df_out)

        # Scale features
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.is_fitted = True

        # -1 = anomaly, 1 = normal
        raw_preds = self.model.predict(scaled)
        # raw decision score: lower values indicate more abnormal instances
        dec_scores = self.model.decision_function(scaled)

        # Normalize decision function to 0–100 ML anomaly score
        # dec_scores typically range from -0.3 to +0.2
        min_dec = np.percentile(dec_scores, 1)
        max_dec = np.percentile(dec_scores, 99)
        if max_dec == min_dec:
            norm_ml_scores = np.zeros(len(df_out))
        else:
            # Invert so that more negative decision score -> higher anomaly score
            norm_ml_scores = 100.0 * (max_dec - dec_scores) / (max_dec - min_dec + 1e-6)
            norm_ml_scores = np.clip(norm_ml_scores, 0.0, 100.0)

        is_anomalies = (raw_preds == -1)

        # Compute Rule scores & composite scores
        composite_scores = []
        rule_scores = []
        ml_scores = []
        risk_levels = []
        risk_factors_list = []
        explanations = []
        recommendations = []
        flagged_flags = []

        for idx, row in df_out.iterrows():
            r_score, factors = calculate_rule_risk(row)
            m_score = float(norm_ml_scores[idx])

            if is_anomalies[idx]:
                factors.append(f"Isolation Forest flagged behavioral anomaly (ML intensity: {m_score:.0f}/100)")

            # Composite weight: 40% ML Anomaly + 60% Rule-based
            composite = 0.40 * m_score + 0.60 * r_score
            
            # Critical threshold booster for extreme compound violations
            if r_score >= 70:
                composite = max(composite, r_score)
            if r_score >= 80:
                composite = min(100.0, composite + 10.0)

            final_score = round(min(100.0, max(0.0, composite)), 1)

            # Determine Risk Level
            if final_score >= 85.0:
                level = "CRITICAL"
            elif final_score >= 70.0:
                level = "HIGH"
            elif final_score >= 40.0:
                level = "MEDIUM"
            else:
                level = "LOW"

            exp, rec = generate_event_explanation(
                emp_name=str(row.get("employee_name", "Employee")),
                risk_level=level,
                risk_score=final_score,
                factors=factors,
                is_anomaly=bool(is_anomalies[idx]),
                action=str(row.get("action", "Action")),
                file_name=str(row.get("file_name", "File"))
            )

            is_flagged = bool(final_score >= 45.0 or is_anomalies[idx])

            composite_scores.append(final_score)
            rule_scores.append(round(r_score, 1))
            ml_scores.append(round(m_score, 1))
            risk_levels.append(level)
            risk_factors_list.append(factors)
            explanations.append(exp)
            recommendations.append(rec)
            flagged_flags.append(is_flagged)

        df_out["is_anomaly"] = is_anomalies
        df_out["ml_score"] = ml_scores
        df_out["rule_score"] = rule_scores
        df_out["risk_score"] = composite_scores
        df_out["risk_level"] = risk_levels
        df_out["risk_factors"] = risk_factors_list
        df_out["risk_factors_str"] = ["; ".join(f) if f else "None (Normal)" for f in risk_factors_list]
        df_out["explanation"] = explanations
        df_out["soc_recommendation"] = recommendations
        df_out["is_flagged"] = flagged_flags

        return df_out
