"""Unit tests for synthetic data generation and attack scenarios."""

import pytest
import pandas as pd
from src.data_generator import (
    generate_normal_event,
    generate_bulk_download_attack,
    generate_after_hours_privilege_abuse,
    generate_slow_burn_exfiltration,
    generate_synthetic_dataset,
    FICTIONAL_EMPLOYEES
)


def test_generate_normal_event():
    """Verify single baseline event structure and fields."""
    event = generate_normal_event()
    assert isinstance(event, dict)
    
    required_keys = [
        "timestamp", "employee_id", "employee_name", "department",
        "action", "file_name", "download_mb", "activity_hour",
        "is_after_hours", "location"
    ]
    for key in required_keys:
        assert key in event, f"Missing key '{key}' in event"
        
    assert event["download_mb"] >= 0.0
    assert 0 <= event["activity_hour"] <= 23
    assert event["scenario_tag"] == "Benign Baseline"


def test_bulk_download_scenario():
    """Verify bulk exfiltration scenario exhibits high data volumes and sensitive files."""
    events = generate_bulk_download_attack("EMP-1035")
    assert len(events) >= 3
    
    total_vol = sum(e["download_mb"] for e in events)
    assert total_vol > 5000.0, f"Expected > 5000 MB, got {total_vol}"
    
    for e in events:
        assert e["employee_id"] == "EMP-1035"
        assert e["is_sensitive"] is True
        assert e["is_after_hours"] is True
        assert e["scenario_tag"] == "Scenario: Bulk Exfiltration"


def test_after_hours_scenario():
    """Verify off-hours privilege scenario flags off-hours and suspicious network."""
    events = generate_after_hours_privilege_abuse("EMP-1024")
    assert len(events) >= 3
    for e in events:
        assert e["activity_hour"] in [0, 1, 2, 3, 4, 5]
        assert e["is_after_hours"] is True
        assert "Tor" in e["location"] or "Relay" in e["location"]


def test_full_dataset_generation():
    """Verify generated dataset is a sorted DataFrame with expected columns."""
    df = generate_synthetic_dataset(n_records=50, include_anomalies=True, seed=123)
    assert isinstance(df, pd.DataFrame)
    assert len(df) >= 50
    assert "timestamp" in df.columns
    assert "download_mb" in df.columns
    
    # Check chronological ordering
    ts_list = pd.to_datetime(df["timestamp"]).tolist()
    assert ts_list == sorted(ts_list)
