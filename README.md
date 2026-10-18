> **AI-Powered Insider Threat Detection** — Autonomous behavioral intelligence combining **scikit-learn Isolation Forest** with **explainable rule-based risk scoring (0–100)** to surface insider threat anomalies before exfiltration occurs.

---

## ⚡ Executive Summary

Traditional Data Loss Prevention (DLP) tools rely on brittle static thresholds that drown security operations teams in false alarms. **InsiderTrace AI** delivers a modern, hybrid behavioral analytics platform:
1. **Unsupervised Anomaly Detection:** Utilizes `IsolationForest` to identify multidimensional behavioral outliers (unusual timestamps, transfer volume velocity, unmanaged devices).
2. **Explainable Deterministic Scoring:** Evaluates transparent cybersecurity heuristics to output a calibrated threat score from **0 to 100** with human-readable risk factors.
3. **Forensic Investigation Workspace:** Deep-dive timeline view for analysts with actionable SOC triage recommendations and analyst hypothesis logging.
4. **Human-in-the-Loop Ethics:** Built on the core principle that **an anomaly is a signal for human investigation, not proof of misconduct**.

---

## 💻 Tech Stack

- **Frontend & App Framework:** [Streamlit](https://streamlit.io/)
- **Machine Learning:** [scikit-learn](https://scikit-learn.org/) (`IsolationForest`, `StandardScaler`)
- **Data Engineering:** [Pandas](https://pandas.pydata.org/), [NumPy](https://numpy.org/)
- **Interactive Visualizations:** [Plotly](https://plotly.com/python/) (`plotly.express`, `plotly.graph_objects`)
- **Testing Suite:** [pytest](https://pytest.org/)

---

## 🚀 Exact Windows Setup & Run Guide

Follow these exact steps in **Windows PowerShell**:

### 1. Open Windows PowerShell and navigate to the project directory
```powershell
cd C:\Users\smrit\.gemini\antigravity\scratch\insidertrace-ai
```

### 2. Create and Activate a Python Virtual Environment
```powershell
# Create virtual environment
py -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell execution policy restricts scripts, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### 3. Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Run Automated Test Suite
Verify that all unit tests for anomaly detection, risk scoring, data validation, and scenarios pass:
```powershell
pytest -v
```

### 5. Launch the Dashboard
```powershell
streamlit run app.py
```

The dashboard will open automatically in your browser at:
👉 **`http://localhost:8501`**

---

## 🎯 Key Capabilities & Features

### 1. 📊 Executive Threat Dashboard
- **Real-Time KPI Cards:** Total Events Logged, Flagged Threats, High/Critical Incidents, High-Risk Exfiltration Volume (GB), Peak Threat Score.
- **Plotly Visualizations:**
  - Threat Incidents Over Time
  - Risk Tier Composition (Donut chart)
  - Data Volume vs. Activity Hour (with highlighted off-hours zones)
  - Top Riskiest Personnel Ranking (Bar chart)
  - Risk Score Distribution (0–100 histogram)
- **Flagged Incidents Forensic Table:** Sortable and searchable grid of suspicious events.
- **Export Flagged Events:** 1-click CSV download for offline SOC reporting.

### 2. 🔍 Employee Forensic Investigation Page
- Deep-dive into specific employee telemetry across all log events.
- **Chronological Activity Timeline:** Visual event cards color-coded by severity (Critical=Red, High=Orange, Medium=Yellow, Low=Green).
- **Explainable Signals:** Itemized breakdown of why each event was flagged (e.g. *"Critical data volume exfiltration (7,840.5 MB)"*, *"Compound threat: Sensitive classified data accessed outside business hours"*).
- **Interactive Triage:** Set status (*Under Investigation*, *Escalated to Tier-2*, *False Positive*, *Privilege Restricted*) and record analyst notes.

### 3. 🧪 Pre-Configured Fictional Demo Attack Scenarios
Test the engine in 1 click against realistic synthetic attack vectors:
- **Scenario 1: Bulk Exfiltration Before Resignation** (`EMP-1035` downloading 12+ GB of customer PII and code archives on a Sunday night).
- **Scenario 2: Unusual After-Hours Credential Abuse** (`EMP-1024` accessing database keys at 2:22 AM via a Tor exit node).
- **Scenario 3: Low & Slow Document Scraping** (`EMP-1042` stealthily transferring confidential client lists over 5 days).
- **Scenario 4: Benign Baseline Operations** (Clean corporate telemetry with zero attacks).

### 4. 📂 Custom CSV Log Ingestion & Schema Validation
- Upload custom organizational activity CSV logs.
- Automatic schema validation verifying required columns: `timestamp`, `employee_id`, `employee_name`, `department`, `action`, `file_name`, `download_mb`.
- **Auto-Derivation:** Automatically derives `activity_hour`, `is_after_hours`, and infers `is_sensitive` based on file classification keywords if absent.
- Downloadable sample CSV template provided directly in the UI.

---

## ⚖️ Ethics & Human-in-the-Loop Governance Notice

> [!IMPORTANT]
> **ANOMALIES ARE SIGNALS FOR HUMAN INVESTIGATION, NOT PROOF OF MISCONDUCT.**
> 
> Behavioral anomaly models detect statistical variance, not moral intent. In real-world enterprise environments:
> - A DevOps engineer resolving an emergency P0 production outage at 3:00 AM generates identical statistical patterns to an adversary.
> - A data engineer migrating a customer database to an analytics lake will legitimately transfer gigabytes of data.
> - **False positives are expected and natural.**
> 
> **Standard Operating Procedure:**
> 1. No punitive action or automated termination of access should occur solely from an algorithm's output.
> 2. SOC Tier-1 analysts must cross-reference Jira change tickets, on-call schedules, and manager approvals prior to escalation.
> 3. Privacy is preserved: InsiderTrace AI analyzes file access metadata, not invasive screen recordings or keystrokes.

---

## 📐 Detection Engine Architecture

```
                                  [Raw Employee Telemetry]
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
          [Feature Engineering]                          [Deterministic Rule Engine]
     - download_mb                                   - Volume > 5GB (+40 pts)
     - activity_hour (0-23)                          - Graveyard shift 0-5am (+22 pts)
     - is_after_hours (0/1)                          - Untrusted network/Tor (+25 pts)
     - is_sensitive (0/1)                            - BYOD/Unmanaged endpoint (+15 pts)
     - is_suspicious_net (0/1)                       - External share action (+20 pts)
     - is_unmanaged_dev (0/1)                        - Crown-jewel asset (+12 pts)
                      │                                               │
                      ▼                                               ▼
      [Isolation Forest Anomaly Model]                       [Rule Threat Score]
       Percentile Calibration (0-100)                                (0-100)
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              ▼
                                 [Composite Risk Score]
                      Min(100, 0.40 × ML_Score + 0.60 × Rule_Score)
                                              │
                                              ▼
                          [Risk Tier Classification & Explainability]
                         CRITICAL (85-100) | HIGH (70-84) | MED (40-69) | LOW (0-39)
```

---

## 📁 Repository Structure

```
insidertrace-ai/
├── .streamlit/
│   └── config.toml               # Dark navy cybersecurity theme config
├── data/
│   ├── sample_activity_logs.csv # Pre-generated sample dataset
│   └── clean_baseline_logs.csv  # Clean benign baseline dataset
├── src/
│   ├── __init__.py
│   ├── data_generator.py         # Fictional synthetic log and scenario generator
│   ├── data_validator.py         # CSV schema validator and auto-deriver
│   ├── detection_engine.py       # Isolation Forest + Rule-based scoring engine
│   ├── ui_components.py          # Plotly charts, KPI widgets, and investigation cards
│   └── styles.py                 # Cyber dark theme CSS and badge HTML
├── tests/
│   ├── __init__.py
│   ├── test_data_generator.py    # Unit tests for data generation
│   ├── test_data_validator.py    # Unit tests for schema validation
│   └── test_detection_engine.py  # Unit tests for ML & rule risk scoring
├── app.py                        # Streamlit main application entrypoint
├── requirements.txt              # Production dependencies
└── README.md                     # Comprehensive documentation
```

---

## 🛡️ License

Built for demonstration and educational purposes as a Hackathon MVP. All employee identities, IP addresses, and file names are strictly fictional.
