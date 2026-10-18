"""Data Validation and Schema Verification for InsiderTrace AI.

Ensures uploaded or synthetic CSV logs conform to expected schemas, handles auto-derivation
of missing features, and delivers clear, user-friendly error and warning messages.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np

REQUIRED_COLUMNS = [
    "timestamp",
    "employee_id",
    "employee_name",
    "department",
    "action",
    "file_name",
    "download_mb"
]

RECOMMENDED_COLUMNS = [
    "is_sensitive",
    "activity_hour",
    "is_after_hours",
    "file_category",
    "location",
    "ip_address",
    "device_type"
]

SENSITIVE_KEYWORD_PATTERNS = [
    "confidential", "secret", "vault", "dump", "credentials", "password",
    "pii", "ssn", "salary", "compensation", "tax", "earnings", "acquisition",
    "patent", "key", "token", "source_archive", "restricted"
]


@dataclass
class ValidationResult:
    """Holds the outcome of data validation."""
    is_valid: bool
    cleaned_df: Optional[pd.DataFrame] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


def validate_and_prepare_logs(df: pd.DataFrame) -> ValidationResult:
    """Validate and clean incoming employee log DataFrame.
    
    Returns a ValidationResult object with validation status, sanitized DataFrame,
    and diagnostic messages.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if df is None or not isinstance(df, pd.DataFrame):
        return ValidationResult(is_valid=False, errors=["Input is not a valid tabular DataFrame."])

    if df.empty:
        return ValidationResult(is_valid=False, errors=["The uploaded file contains no data rows."])

    # Standardize column names (strip whitespace and lower/case-match)
    df = df.copy()
    col_mapping = {c: c.strip() for c in df.columns}
    df.rename(columns=col_mapping, inplace=True)
    
    # Case-insensitive column matching for required columns
    lower_map = {c.lower(): c for c in df.columns}
    matched_cols = {}
    missing_required = []
    for req in REQUIRED_COLUMNS:
        if req.lower() in lower_map:
            matched_cols[lower_map[req.lower()]] = req
        else:
            missing_required.append(req)

    if missing_required:
        errors.append(
            f"Missing required column(s): {', '.join(missing_required)}. "
            f"Please ensure your CSV includes all required fields."
        )
        return ValidationResult(is_valid=False, errors=errors)

    df.rename(columns=matched_cols, inplace=True)

    # Validate and parse timestamp
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        null_ts_count = df["timestamp"].isna().sum()
        if null_ts_count > 0:
            if null_ts_count == len(df):
                errors.append("All timestamp values failed to parse. Expected format: YYYY-MM-DD HH:MM:SS.")
                return ValidationResult(is_valid=False, errors=errors)
            else:
                warnings.append(f"Dropped {null_ts_count} row(s) with unparseable timestamps.")
                df = df.dropna(subset=["timestamp"])
    except Exception as e:
        errors.append(f"Timestamp parsing error: {str(e)}")
        return ValidationResult(is_valid=False, errors=errors)

    # Validate and clean download_mb
    df["download_mb"] = pd.to_numeric(df["download_mb"], errors="coerce").fillna(0.0)
    neg_count = (df["download_mb"] < 0).sum()
    if neg_count > 0:
        warnings.append(f"Found {neg_count} record(s) with negative download_mb. Replaced with 0.0.")
        df["download_mb"] = df["download_mb"].clip(lower=0.0)

    # Clean text columns
    text_cols = ["employee_id", "employee_name", "department", "action", "file_name"]
    for col in text_cols:
        df[col] = df[col].astype(str).str.strip()
        df[col] = df[col].replace(["nan", "None", ""], "Unknown")

    # Auto-derive activity_hour if absent
    if "activity_hour" not in df.columns:
        df["activity_hour"] = df["timestamp"].dt.hour
        warnings.append("Auto-derived 'activity_hour' from the 'timestamp' column.")
    else:
        df["activity_hour"] = pd.to_numeric(df["activity_hour"], errors="coerce")
        # Fill any missing with timestamp hour
        df["activity_hour"] = df["activity_hour"].fillna(df["timestamp"].dt.hour).astype(int)

    # Auto-derive is_after_hours if absent
    if "is_after_hours" not in df.columns:
        df["is_after_hours"] = df["activity_hour"].apply(lambda h: bool(h < 7 or h >= 19))
        warnings.append("Auto-derived 'is_after_hours' (defined as < 07:00 or >= 19:00).")
    else:
        df["is_after_hours"] = df["is_after_hours"].astype(bool)

    # Auto-derive is_sensitive if absent
    if "is_sensitive" not in df.columns:
        pattern = "|".join(SENSITIVE_KEYWORD_PATTERNS)
        df["is_sensitive"] = df["file_name"].str.lower().str.contains(pattern, regex=True, na=False)
        warnings.append("Auto-inferred 'is_sensitive' from file names containing sensitive keywords.")
    else:
        df["is_sensitive"] = df["is_sensitive"].astype(bool)

    # Ensure optional columns exist
    if "file_category" not in df.columns:
        df["file_category"] = df["is_sensitive"].apply(lambda s: "Confidential" if s else "Standard")
    if "location" not in df.columns:
        df["location"] = "Corporate Office / VPN"
    if "ip_address" not in df.columns:
        df["ip_address"] = "10.0.0.1"
    if "device_type" not in df.columns:
        df["device_type"] = "Corporate Managed"
    if "role" not in df.columns:
        df["role"] = df["department"] + " Specialist"

    # Sort chronologically
    df = df.sort_values("timestamp", ascending=True).reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Check volume
    if len(df) < 10:
        warnings.append("Fewer than 10 events provided. Anomaly detection accuracy is optimal with larger datasets.")

    summary = {
        "total_rows": len(df),
        "unique_employees": df["employee_id"].nunique(),
        "date_range": f"{df['timestamp'].min()} to {df['timestamp'].max()}",
        "total_download_gb": round(df["download_mb"].sum() / 1024.0, 2),
        "after_hours_count": int(df["is_after_hours"].sum()),
        "sensitive_file_count": int(df["is_sensitive"].sum())
    }

    return ValidationResult(
        is_valid=True,
        cleaned_df=df,
        errors=errors,
        warnings=warnings,
        summary=summary
    )


def generate_sample_csv_template() -> str:
    """Returns a CSV string representing a standard upload template."""
    headers = [
        "timestamp", "employee_id", "employee_name", "department", "role",
        "action", "file_name", "file_category", "is_sensitive", "download_mb",
        "activity_hour", "is_after_hours", "location", "device_type", "ip_address"
    ]
    sample_row = [
        "2026-10-17 14:32:00", "EMP-2045", "Jane Doe", "Finance", "Senior Analyst",
        "FILE_DOWNLOAD", "q3_financial_projection.xlsx", "Financial", "True", "45.2",
        "14", "False", "HQ - New York", "Corporate Laptop (Managed)", "10.142.12.55"
    ]
    return f"{','.join(headers)}\n{','.join(sample_row)}\n"
