"""Unit tests for Isolation Forest anomaly detection and explainable risk scoring."""

import pytest
import pandas as pd
from src.detection_engine import AnomalyDetectionEngine, calculate_rule_risk
from src.data_generator import generate_synthetic_dataset


def test_calculate_rule_risk_baseline():
    """Verify standard benign activity produces a low rule risk score."""
    normal_row = pd.Series({
        "download_mb": 15.0,
        "is_after_hours": False,
        "is_sensitive": False,
        "location": "HQ - New York",
        "device_type": "Corporate Laptop (Managed)",
        "action": "FILE_ACCESS",
        "file_category": "Standard",
        "activity_hour": 14
    })
    score, factors = calculate_rule_risk(normal_row)
    assert score < 20.0
    assert len(factors) == 0


def test_calculate_rule_risk_extreme_attack():
    """Verify massive off-hours exfiltration from Tor generates a high rule score."""
    attack_row = pd.Series({
        "download_mb": 8500.0,
        "is_after_hours": True,
        "is_sensitive": True,
        "location": "Tor Exit Node (Relay #442)",
        "device_type": "Personal Device (BYOD)",
        "action": "FILE_DOWNLOAD",
        "file_category": "Intellectual Property",
        "activity_hour": 2
    })
    score, factors = calculate_rule_risk(attack_row)
    assert score >= 80.0
    assert len(factors) >= 4
    assert any("5,000 MB" in f for f in factors)
    assert any("Tor" in f or "egress" in f for f in factors)


def test_detection_engine_scoring_bounds():
    """Verify Isolation Forest + Rule composite scores are strictly within 0–100."""
    df = generate_synthetic_dataset(n_records=80, include_anomalies=True, seed=42)
    engine = AnomalyDetectionEngine(contamination=0.10)
    scored = engine.fit_and_score(df)
    
    assert "risk_score" in scored.columns
    assert "risk_level" in scored.columns
    assert "is_anomaly" in scored.columns
    assert "explanation" in scored.columns
    assert "soc_recommendation" in scored.columns
    
    # Check bounds
    assert (scored["risk_score"] >= 0.0).all()
    assert (scored["risk_score"] <= 100.0).all()
    
    # Check valid risk levels
    valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert set(scored["risk_level"].unique()).issubset(valid_levels)
    
    # Explanations and recommendations are non-empty strings
    for exp, rec in zip(scored["explanation"], scored["soc_recommendation"]):
        assert isinstance(exp, str) and len(exp) > 10
        assert isinstance(rec, str) and len(rec) > 10


def test_detection_engine_identifies_bulk_threat():
    """Verify engine flags known bulk exfiltration attacks as Critical or High."""
    df = generate_synthetic_dataset(n_records=100, include_anomalies=True, seed=42)
    engine = AnomalyDetectionEngine(contamination=0.10)
    scored = engine.fit_and_score(df)
    
    # Elena Rostova's bulk attack records
    elena_attacks = scored[scored["scenario_tag"] == "Scenario: Bulk Exfiltration"]
    assert len(elena_attacks) > 0
    assert (elena_attacks["risk_score"] >= 70.0).all()
    assert (elena_attacks["risk_level"].isin(["HIGH", "CRITICAL"])).all()
