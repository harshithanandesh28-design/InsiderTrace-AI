"""Synthetic Data Generator for Insider Threat Detection.

Generates realistic, strictly fictional employee activity logs for normal activities
and cybersecurity demo attack scenarios (bulk downloads, after-hours access, data exfiltration).
"""

from __future__ import annotations
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd

# Fictional Employee Directory
FICTIONAL_EMPLOYEES = [
    {"id": "EMP-1011", "name": "Sarah Connor", "dept": "Engineering", "role": "Principal Architect"},
    {"id": "EMP-1024", "name": "Marcus Vance", "dept": "IT Operations", "role": "Systems Administrator"},
    {"id": "EMP-1035", "name": "Elena Rostova", "dept": "Engineering", "role": "Senior Backend Dev"},
    {"id": "EMP-1042", "name": "Derek Chen", "dept": "Sales", "role": "Enterprise Account Exec"},
    {"id": "EMP-1057", "name": "Amira Al-Mansoor", "dept": "Finance", "role": "Senior Financial Controller"},
    {"id": "EMP-1063", "name": "Liam Gallagher", "dept": "Human Resources", "role": "People Operations Lead"},
    {"id": "EMP-1078", "name": "Zoe Washington", "dept": "Legal & Compliance", "role": "Corporate Counsel"},
    {"id": "EMP-1089", "name": "Kavita Patel", "dept": "Engineering", "role": "Data Scientist"},
    {"id": "EMP-1092", "name": "Julian Mercer", "dept": "Finance", "role": "Budget Analyst"},
    {"id": "EMP-1104", "name": "Chloe Dupont", "dept": "Marketing", "role": "Growth Director"},
    {"id": "EMP-1115", "name": "Nathaniel Drake", "dept": "Product", "role": "Group Product Manager"},
    {"id": "EMP-1128", "name": "Sophia Morales", "dept": "Customer Success", "role": "Support Team Lead"},
]

STANDARD_FILES = [
    ("weekly_sync_notes.docx", "Standard", False, (1, 15)),
    ("q3_roadmap_presentation.pptx", "Standard", False, (5, 45)),
    ("team_lunch_poll.xlsx", "Standard", False, (1, 5)),
    ("customer_feedback_summary.pdf", "Standard", False, (2, 25)),
    ("feature_specs_v2.md", "Standard", False, (1, 8)),
    ("employee_handbook_2026.pdf", "Standard", False, (3, 18)),
    ("onboarding_guide.pdf", "Standard", False, (4, 12)),
    ("marketing_assets_bundle.zip", "Standard", False, (20, 180)),
    ("vendor_invoice_oct.pdf", "Standard", False, (1, 10)),
    ("daily_standup_archive.json", "Standard", False, (2, 20)),
]

SENSITIVE_FILES = [
    ("q3_preliminary_earnings_confidential.xlsx", "Financial", True, (40, 250)),
    ("master_customer_pii_vault.parquet", "Confidential", True, (800, 7500)),
    ("enterprise_user_credentials_dump.sql", "Infrastructure", True, (500, 4800)),
    ("core_algorithm_source_archive.tar.gz", "Intellectual Property", True, (1200, 9500)),
    ("executive_compensation_2026.xlsx", "Confidential", True, (25, 120)),
    ("m_and_a_target_acquisition_brief.docx", "Confidential", True, (15, 80)),
    ("patent_submission_drafts_internal.pdf", "Intellectual Property", True, (50, 350)),
    ("database_encryption_keys_backup.pem", "Infrastructure", True, (2, 20)),
    ("board_meeting_minutes_unreleased.pdf", "Confidential", True, (10, 65)),
    ("global_employee_ssn_tax_records.csv", "Confidential", True, (350, 4200)),
]

LOCATIONS_NORMAL = ["HQ - New York (VPN)", "Remote - US East", "Remote - US West", "London Branch Office", "Zurich Tech Hub"]
LOCATIONS_SUSPICIOUS = ["Unrecognized GeoIP - Anonymous Proxy", "Tor Exit Node (Relay #442)", "Offshore Cloud IP Range (Bulletproof)", "Public Coffee Shop Open Wi-Fi"]

ACTIONS = ["FILE_DOWNLOAD", "FILE_ACCESS", "DATABASE_QUERY", "EXTERNAL_SHARE", "REMOTE_LOGIN"]


def _random_timestamp_within(days_back: int = 14, hour: Optional[int] = None) -> datetime:
    """Generate a realistic random timestamp within the last N days."""
    now = datetime(2026, 10, 17, 12, 0, 0)
    delta_days = random.randint(0, days_back)
    target_date = now - timedelta(days=delta_days)
    
    if hour is not None:
        target_hour = hour
    else:
        # Standard corporate bell curve: mostly between 8am and 6pm
        if random.random() < 0.85:
            target_hour = random.randint(8, 18)
        else:
            target_hour = random.choice([0, 1, 2, 3, 4, 5, 6, 20, 21, 22, 23])
            
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return target_date.replace(hour=target_hour, minute=minute, second=second)


def generate_normal_event(emp: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Generate a single benign baseline activity log."""
    if emp is None:
        emp = random.choice(FICTIONAL_EMPLOYEES)
        
    file_info = random.choice(STANDARD_FILES)
    fname, cat, is_sens, size_range = file_info
    
    # 90% normal working hours (8am - 6pm)
    hour = random.randint(8, 18) if random.random() < 0.92 else random.choice([7, 19, 20])
    dt = _random_timestamp_within(days_back=10, hour=hour)
    size_mb = round(random.uniform(size_range[0], size_range[1]), 2)
    
    return {
        "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
        "employee_id": emp["id"],
        "employee_name": emp["name"],
        "department": emp["dept"],
        "role": emp["role"],
        "action": random.choice(["FILE_ACCESS", "FILE_DOWNLOAD", "DATABASE_QUERY"]),
        "file_name": fname,
        "file_category": cat,
        "is_sensitive": is_sens,
        "download_mb": size_mb,
        "activity_hour": hour,
        "is_after_hours": bool(hour < 7 or hour >= 19),
        "location": random.choice(LOCATIONS_NORMAL),
        "device_type": "Corporate Laptop (Managed)",
        "ip_address": f"10.142.{random.randint(10, 80)}.{random.randint(2, 250)}",
        "scenario_tag": "Benign Baseline"
    }


def generate_bulk_download_attack(emp_id: str = "EMP-1035") -> List[Dict[str, Any]]:
    """Scenario: Bulk Data Exfiltration by a departing engineer."""
    emp = next(e for e in FICTIONAL_EMPLOYEES if e["id"] == emp_id)
    events = []
    
    base_time = datetime(2026, 10, 15, 23, 14, 0)
    massive_targets = [
        ("master_customer_pii_vault.parquet", "Confidential", True, 7840.50),
        ("enterprise_user_credentials_dump.sql", "Infrastructure", True, 4210.20),
        ("core_algorithm_source_archive.tar.gz", "Intellectual Property", True, 9480.00),
        ("global_employee_ssn_tax_records.csv", "Confidential", True, 3890.10),
    ]
    
    for i, (fname, cat, is_sens, size_mb) in enumerate(massive_targets):
        ts = base_time + timedelta(minutes=i * 14 + random.randint(1, 5))
        hour = ts.hour
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": "FILE_DOWNLOAD",
            "file_name": fname,
            "file_category": cat,
            "is_sensitive": is_sens,
            "download_mb": size_mb,
            "activity_hour": hour,
            "is_after_hours": True,
            "location": "Remote - US East",
            "device_type": "Personal Device (BYOD)",
            "ip_address": f"198.51.100.{random.randint(10, 99)}",
            "scenario_tag": "Scenario: Bulk Exfiltration"
        })
    return events


def generate_after_hours_privilege_abuse(emp_id: str = "EMP-1024") -> List[Dict[str, Any]]:
    """Scenario: 2:00 AM privilege abuse & sensitive file harvesting from suspicious IP."""
    emp = next(e for e in FICTIONAL_EMPLOYEES if e["id"] == emp_id)
    events = []
    
    base_time = datetime(2026, 10, 16, 2, 22, 0)
    targets = [
        ("database_encryption_keys_backup.pem", "Infrastructure", True, 18.4),
        ("m_and_a_target_acquisition_brief.docx", "Confidential", True, 68.2),
        ("executive_compensation_2026.xlsx", "Confidential", True, 94.6),
        ("q3_preliminary_earnings_confidential.xlsx", "Financial", True, 210.0),
    ]
    
    for i, (fname, cat, is_sens, size_mb) in enumerate(targets):
        ts = base_time + timedelta(minutes=i * 8 + random.randint(1, 4))
        hour = ts.hour
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": "FILE_DOWNLOAD" if i % 2 == 0 else "FILE_ACCESS",
            "file_name": fname,
            "file_category": cat,
            "is_sensitive": is_sens,
            "download_mb": size_mb,
            "activity_hour": hour,
            "is_after_hours": True,
            "location": "Tor Exit Node (Relay #442)",
            "device_type": "Unknown Terminal",
            "ip_address": f"185.220.101.{random.randint(5, 250)}",
            "scenario_tag": "Scenario: After-Hours Credential Abuse"
        })
    return events


def generate_slow_burn_exfiltration(emp_id: str = "EMP-1042") -> List[Dict[str, Any]]:
    """Scenario: Low-and-slow exfiltration across multiple days by sales rep."""
    emp = next(e for e in FICTIONAL_EMPLOYEES if e["id"] == emp_id)
    events = []
    
    start_date = datetime(2026, 10, 11, 20, 15, 0)
    for day in range(5):
        ts = start_date + timedelta(days=day, hours=random.choice([21, 22, 23]))
        hour = ts.hour
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": "EXTERNAL_SHARE",
            "file_name": f"client_portfolio_confidential_part_{day+1}.xlsx",
            "file_category": "Confidential",
            "is_sensitive": True,
            "download_mb": round(random.uniform(450.0, 950.0), 2),
            "activity_hour": hour,
            "is_after_hours": True,
            "location": "Public Coffee Shop Open Wi-Fi",
            "device_type": "Corporate Laptop (Managed)",
            "ip_address": f"203.0.113.{random.randint(20, 180)}",
            "scenario_tag": "Scenario: Low & Slow Sharing"
        })
    return events


def generate_synthetic_dataset(
    n_records: int = 500,
    include_anomalies: bool = True,
    seed: int = 42
) -> pd.DataFrame:
    """Generate a full synthetic activity dataset combining baseline and anomalous logs."""
    random.seed(seed)
    np.random.seed(seed)
    
    records: List[Dict[str, Any]] = []
    
    # Baseline normal records
    base_count = n_records if not include_anomalies else int(n_records * 0.90)
    for _ in range(base_count):
        records.append(generate_normal_event())
        
    if include_anomalies:
        # Add labelled scenarios
        records.extend(generate_bulk_download_attack("EMP-1035"))
        records.extend(generate_after_hours_privilege_abuse("EMP-1024"))
        records.extend(generate_slow_burn_exfiltration("EMP-1042"))
        
        # Add a few random after-hours spikes
        for _ in range(max(2, int(n_records * 0.04))):
            emp = random.choice(FICTIONAL_EMPLOYEES)
            file_info = random.choice(SENSITIVE_FILES)
            hour = random.choice([1, 2, 3, 23])
            dt = _random_timestamp_within(days_back=7, hour=hour)
            records.append({
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "employee_id": emp["id"],
                "employee_name": emp["name"],
                "department": emp["dept"],
                "role": emp["role"],
                "action": "FILE_DOWNLOAD",
                "file_name": file_info[0],
                "file_category": file_info[1],
                "is_sensitive": file_info[2],
                "download_mb": round(random.uniform(1500.0, 5200.0), 2),
                "activity_hour": hour,
                "is_after_hours": True,
                "location": random.choice(LOCATIONS_SUSPICIOUS),
                "device_type": "Personal Device (BYOD)",
                "ip_address": f"192.0.2.{random.randint(10, 200)}",
                "scenario_tag": "Anomalous Spike"
            })
            
    df = pd.DataFrame(records)
    # Sort chronologically
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp", ascending=True).reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def generate_live_stream_event(inject_threat: bool = False) -> Dict[str, Any]:
    """Generate a single real-time simulated telemetry event with current timestamp."""
    now = datetime.now()
    emp = random.choice(FICTIONAL_EMPLOYEES)
    
    if not inject_threat:
        file_info = random.choice(STANDARD_FILES)
        return {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": random.choice(["FILE_ACCESS", "FILE_DOWNLOAD", "DATABASE_QUERY"]),
            "file_name": file_info[0],
            "file_category": file_info[1],
            "is_sensitive": file_info[2],
            "download_mb": round(random.uniform(file_info[3][0], file_info[3][1]), 2),
            "activity_hour": now.hour,
            "is_after_hours": bool(now.hour < 7 or now.hour >= 19),
            "location": random.choice(LOCATIONS_NORMAL),
            "device_type": "Corporate Laptop (Managed)",
            "ip_address": f"10.142.{random.randint(10, 80)}.{random.randint(2, 250)}",
            "scenario_tag": "Live Stream Normal"
        }
    else:
        file_info = random.choice(SENSITIVE_FILES)
        threat_type = random.choice(["bulk", "tor", "share"])
        if threat_type == "bulk":
            dl_mb = round(random.uniform(4500.0, 9800.0), 2)
            loc = "Remote - US East"
            dev = "Personal Device (BYOD)"
            act = "FILE_DOWNLOAD"
        elif threat_type == "tor":
            dl_mb = round(random.uniform(80.0, 450.0), 2)
            loc = "Tor Exit Node (Relay #442)"
            dev = "Unknown Terminal"
            act = "FILE_DOWNLOAD"
        else:
            dl_mb = round(random.uniform(1200.0, 3500.0), 2)
            loc = "Public Coffee Shop Open Wi-Fi"
            dev = "Personal Device (BYOD)"
            act = "EXTERNAL_SHARE"
            
        return {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": act,
            "file_name": file_info[0],
            "file_category": file_info[1],
            "is_sensitive": file_info[2],
            "download_mb": dl_mb,
            "activity_hour": now.hour,
            "is_after_hours": True,
            "location": loc,
            "device_type": dev,
            "ip_address": f"185.220.{random.randint(10, 99)}.{random.randint(2, 250)}",
            "scenario_tag": "Live Injected Threat"
        }
