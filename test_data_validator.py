"""Unit tests for CSV schema validation and cleaning."""

import pytest
import pandas as pd
from src.data_validator import validate_and_prepare_logs, generate_sample_csv_template


def test_validate_valid_dataset():
    """Verify clean dataset passes validation without errors."""
    data = {
        "timestamp": ["2026-10-17 14:00:00", "2026-10-17 15:30:00"],
        "employee_id": ["EMP-101", "EMP-102"],
        "employee_name": ["Alice Smith", "Bob Jones"],
        "department": ["Engineering", "Finance"],
        "action": ["FILE_ACCESS", "FILE_DOWNLOAD"],
        "file_name": ["project_plan.docx", "budget_draft.xlsx"],
        "download_mb": [12.5, 45.0]
    }
    df = pd.DataFrame(data)
    result = validate_and_prepare_logs(df)
    
    assert result.is_valid is True
    assert len(result.errors) == 0
    assert result.cleaned_df is not None
    assert len(result.cleaned_df) == 2
    assert "activity_hour" in result.cleaned_df.columns
    assert "is_after_hours" in result.cleaned_df.columns
    assert "is_sensitive" in result.cleaned_df.columns


def test_missing_required_columns():
    """Verify validation fails gracefully when required columns are absent."""
    data = {
        "timestamp": ["2026-10-17 14:00:00"],
        "employee_name": ["Alice Smith"]
    }
    df = pd.DataFrame(data)
    result = validate_and_prepare_logs(df)
    
    assert result.is_valid is False
    assert len(result.errors) > 0
    assert any("Missing required column" in err for err in result.errors)


def test_negative_download_mb_cleaning():
    """Verify negative download sizes are automatically sanitized to 0.0 with a warning."""
    data = {
        "timestamp": ["2026-10-17 14:00:00"],
        "employee_id": ["EMP-101"],
        "employee_name": ["Alice Smith"],
        "department": ["Engineering"],
        "action": ["FILE_ACCESS"],
        "file_name": ["code.py"],
        "download_mb": [-50.0]
    }
    df = pd.DataFrame(data)
    result = validate_and_prepare_logs(df)
    
    assert result.is_valid is True
    assert result.cleaned_df.iloc[0]["download_mb"] == 0.0
    assert any("negative download_mb" in w for w in result.warnings)


def test_auto_derive_sensitive_keywords():
    """Verify sensitive files are detected from keyword heuristics."""
    data = {
        "timestamp": ["2026-10-17 14:00:00", "2026-10-17 15:00:00"],
        "employee_id": ["EMP-101", "EMP-102"],
        "employee_name": ["Alice", "Bob"],
        "department": ["HR", "Engineering"],
        "action": ["FILE_DOWNLOAD", "FILE_ACCESS"],
        "file_name": ["employee_salary_dump.csv", "meeting_notes.docx"],
        "download_mb": [10.0, 5.0]
    }
    df = pd.DataFrame(data)
    result = validate_and_prepare_logs(df)
    
    assert result.is_valid is True
    assert result.cleaned_df.iloc[0]["is_sensitive"] == True
    assert result.cleaned_df.iloc[1]["is_sensitive"] == False


def test_sample_csv_template():
    """Verify sample CSV template has valid CSV format and non-empty content."""
    csv_str = generate_sample_csv_template()
    assert "timestamp" in csv_str
    assert "download_mb" in csv_str
    assert len(csv_str.splitlines()) >= 2
