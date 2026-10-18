"""InsiderTrace AI — AI-Powered Insider Threat Detection.

Streamlit Cybersecurity Dashboard MVP.
Features Isolation Forest anomaly detection, explainable rule-based scoring (0-100),
fictional demo attack scenarios, employee forensic investigation, and CSV upload validation.
"""

from __future__ import annotations
import os
import io
import time
import random
from datetime import datetime
import pandas as pd
import streamlit as st

from src.styles import CYBER_THEME_CSS, get_risk_badge_html
from src.data_generator import (
    generate_synthetic_dataset,
    generate_bulk_download_attack,
    generate_after_hours_privilege_abuse,
    generate_slow_burn_exfiltration,
    generate_normal_event,
    generate_live_stream_event,
    FICTIONAL_EMPLOYEES
)
from src.data_validator import validate_and_prepare_logs, generate_sample_csv_template
from src.detection_engine import AnomalyDetectionEngine
from src.ui_components import (
    render_kpi_summary,
    render_risk_distribution_chart,
    render_risk_donut_chart,
    render_download_vs_hour_chart,
    render_top_risky_employees_chart,
    render_threat_timeline_chart,
    render_event_investigation_card
)

# Page Configuration
st.set_page_config(
    page_title="InsiderTrace AI — Insider Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Custom Cyber Theme CSS
st.markdown(CYBER_THEME_CSS, unsafe_allow_html=True)


# Initialize Session State
def init_session_state():
    if "raw_df" not in st.session_state:
        # Default with pre-generated synthetic dataset
        st.session_state.raw_df = generate_synthetic_dataset(n_records=450, include_anomalies=True, seed=42)
    if "contamination" not in st.session_state:
        st.session_state.contamination = 0.08
    if "scored_df" not in st.session_state:
        engine = AnomalyDetectionEngine(contamination=st.session_state.contamination)
        st.session_state.scored_df = engine.fit_and_score(st.session_state.raw_df)
    if "triage_notes" not in st.session_state:
        st.session_state.triage_notes = {}
    if "active_scenario" not in st.session_state:
        st.session_state.active_scenario = "Comprehensive Multi-Threat Dataset"
    if "live_stream_events" not in st.session_state:
        st.session_state.live_stream_events = []

init_session_state()


def rerun_detection():
    """Rerun anomaly detection and scoring on current raw dataset."""
    engine = AnomalyDetectionEngine(contamination=st.session_state.contamination)
    st.session_state.scored_df = engine.fit_and_score(st.session_state.raw_df)


# App Header Banner
st.markdown(
    """
    <div class="cyber-header">
        <div class="cyber-title">
            <span>🛡️ InsiderTrace AI</span>
            <span style="font-size: 0.85rem; font-weight: 500; background: rgba(0, 173, 181, 0.15); 
                  color: #38BDF8; padding: 3px 12px; border-radius: 12px; border: 1px solid rgba(0, 173, 181, 0.3);">
                Threat Detection
            </span>
        </div>
        <p class="cyber-subtitle">
            AI-Powered Behavioral Anomaly Detection & Risk Scoring (0–100)
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# Friendly Guidance Notice
st.markdown(
    """
    <div class="soc-ethics-banner">
        <span style="font-size: 1.25rem;">💡</span>
        <div>
            <strong>Analyst Note:</strong> An anomaly is a signal for human investigation, not proof of misconduct.
            Unusual hours or large file transfers can be normal authorized work.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# Sidebar Filters and Configuration
with st.sidebar:
    st.markdown("### 🎛️ Filters & Options")
    
    st.markdown(f"**Dataset:** `{st.session_state.active_scenario}`")
    st.markdown(f"**Records:** `{len(st.session_state.scored_df):,}`")

    st.markdown("---")
    st.markdown("#### 🔍 Filter Logs")

    scored_df = st.session_state.scored_df

    # Employee Filter
    all_employees = sorted(scored_df["employee_name"].unique().tolist())
    selected_employees = st.multiselect(
        "Filter by Employee",
        options=all_employees,
        default=[],
        placeholder="All Employees (Default)"
    )

    # Risk Level Filter
    available_risk_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    selected_levels = st.multiselect(
        "Risk Level",
        options=available_risk_levels,
        default=available_risk_levels,
        placeholder="Select risk tiers"
    )

    # Minimum Risk Score Slider
    min_score = st.slider(
        "Minimum Risk Score",
        min_value=0,
        max_value=100,
        value=0,
        step=5,
        help="Display only events with a risk score greater than or equal to this threshold"
    )

    # Anomaly Only Toggle
    only_anomalies = st.checkbox(
        "Show Flagged Anomalies Only",
        value=False,
        help="Restricts results to records flagged as anomalies or high threat"
    )

    with st.expander("⚙️ Advanced Model Settings"):
        new_contamination = st.slider(
            "Isolation Forest Contamination",
            min_value=0.01,
            max_value=0.25,
            value=float(st.session_state.contamination),
            step=0.01,
            help="Estimated proportion of anomalies in the dataset"
        )
        if new_contamination != st.session_state.contamination:
            st.session_state.contamination = new_contamination
            rerun_detection()
            st.rerun()

    st.markdown("---")
    st.caption("InsiderTrace AI • Behavioral Risk Detection")


# Apply Filters
filtered_df = scored_df.copy()

if selected_employees:
    filtered_df = filtered_df[filtered_df["employee_name"].isin(selected_employees)]

if selected_levels:
    filtered_df = filtered_df[filtered_df["risk_level"].isin(selected_levels)]

if min_score > 0:
    filtered_df = filtered_df[filtered_df["risk_score"] >= min_score]

if only_anomalies:
    filtered_df = filtered_df[filtered_df["is_flagged"]]


# Main Navigation Tabs
tab_overview, tab_stream, tab_investigate, tab_scenarios, tab_upload, tab_methodology = st.tabs([
    "📊 Overview",
    "📡 Live Stream Simulation",
    "🔍 Employee Investigation",
    "🧪 Demo Scenarios",
    "📂 Upload Data",
    "ℹ️ How It Works"
])


# ==============================================================================
# TAB 1: OVERVIEW DASHBOARD
# ==============================================================================
with tab_overview:
    # KPI Cards
    render_kpi_summary(filtered_df)

    st.markdown("### 📈 Activity & Threat Analytics")
    
    # Visualizations Grid
    row1_col1, row1_col2 = st.columns([3, 2])
    with row1_col1:
        st.plotly_chart(render_threat_timeline_chart(filtered_df), use_container_width=True)
    with row1_col2:
        st.plotly_chart(render_risk_donut_chart(filtered_df), use_container_width=True)

    row2_col1, row2_col2 = st.columns([1, 1])
    with row2_col1:
        st.plotly_chart(render_download_vs_hour_chart(filtered_df), use_container_width=True)
    with row2_col2:
        st.plotly_chart(render_top_risky_employees_chart(filtered_df), use_container_width=True)

    st.plotly_chart(render_risk_distribution_chart(filtered_df), use_container_width=True)

    st.markdown("---")
    
    # Flagged Incidents Forensic Table
    st.markdown("### 🚨 Flagged Threat Logs & Incident Export")
    
    flagged_table = filtered_df[filtered_df["is_flagged"]].sort_values("risk_score", ascending=False)
    
    table_display_cols = [
        "timestamp", "employee_name", "department", "action", "file_name",
        "download_mb", "activity_hour", "risk_score", "risk_level", "risk_factors_str"
    ]
    
    # Download Button for Flagged Events CSV
    csv_buffer = io.StringIO()
    flagged_table.to_csv(csv_buffer, index=False)
    csv_bytes = csv_buffer.getvalue().encode("utf-8")
    
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        st.write(f"Displaying **{len(flagged_table):,}** flagged incident(s) requiring attention.")
    with col_t2:
        st.download_button(
            label="📥 Export Flagged CSV",
            data=csv_bytes,
            file_name=f"insidertrace_flagged_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            help="Export all currently flagged events to CSV"
        )

    if not flagged_table.empty:
        st.dataframe(
            flagged_table[table_display_cols].rename(columns={
                "timestamp": "Timestamp",
                "employee_name": "Employee",
                "department": "Department",
                "action": "Action",
                "file_name": "Target File",
                "download_mb": "Size (MB)",
                "activity_hour": "Hour",
                "risk_score": "Risk Score",
                "risk_level": "Tier",
                "risk_factors_str": "Triggered Signals"
            }),
            use_container_width=True,
            height=320
        )
    else:
        st.success("✅ No threat incidents match the current filter criteria.")


# ==============================================================================
# TAB: LIVE STREAM SIMULATION
# ==============================================================================
with tab_stream:
    st.markdown("### 📡 Real-Time Telemetry Stream Simulation")
    st.markdown(
        "Simulates a live enterprise event pipeline (e.g. Apache Kafka / SIEM log forwarder). "
        "Watch as incoming employee actions are scored and flagged by the detection engine in real time."
    )
    
    st.markdown(
        """
        <div style="margin-bottom: 16px;">
            <span class="live-indicator">
                <span class="live-dot"></span> SIMULATED EVENT PIPELINE READY
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    c_st1, c_st2, c_st3 = st.columns(3)
    with c_st1:
        stream_count = st.slider("Events to Stream in Run", min_value=5, max_value=30, value=12, step=1)
    with c_st2:
        stream_speed = st.slider("Stream Interval (seconds)", min_value=0.5, max_value=3.0, value=1.0, step=0.5)
    with c_st3:
        threat_rate = st.slider("Threat Injection Probability (%)", min_value=10, max_value=60, value=30, step=5)

    btn_c1, btn_c2 = st.columns([1, 3])
    with btn_c1:
        start_stream_btn = st.button("▶️ Launch Live Stream", type="primary")
    with btn_c2:
        if st.button("🧹 Clear Streamed Events"):
            st.session_state.live_stream_events = []
            st.success("Cleared live stream buffer.")
            st.rerun()

    status_placeholder = st.empty()
    alert_placeholder = st.empty()
    kpi_placeholder = st.empty()
    feed_placeholder = st.empty()

    if start_stream_btn:
        engine = AnomalyDetectionEngine(contamination=st.session_state.contamination)
        progress_bar = st.progress(0)

        for step in range(stream_count):
            is_threat = (random.random() * 100 < threat_rate)
            raw_event = generate_live_stream_event(inject_threat=is_threat)
            
            single_df = pd.DataFrame([raw_event])
            val = validate_and_prepare_logs(single_df)
            if val.is_valid and val.cleaned_df is not None:
                single_df = val.cleaned_df

            # Evaluate with model context from recent data
            context_df = pd.concat([st.session_state.raw_df.tail(60), single_df], ignore_index=True)
            scored_batch = engine.fit_and_score(context_df)
            scored_single = scored_batch.iloc[-1]

            event_dict = scored_single.to_dict()
            st.session_state.live_stream_events.insert(0, event_dict)
            st.session_state.live_stream_events = st.session_state.live_stream_events[:50]

            # Also add to global scored DataFrame so other tabs update
            st.session_state.scored_df = pd.concat([st.session_state.scored_df, pd.DataFrame([scored_single])], ignore_index=True)

            progress_bar.progress((step + 1) / stream_count)
            status_placeholder.markdown(f"**Ingesting event {step + 1} of {stream_count}...** (Timestamp: `{event_dict['timestamp']}`)")

            lvl = event_dict.get("risk_level", "LOW")
            score = float(event_dict.get("risk_score", 0.0))
            emp = event_dict.get("employee_name", "Employee")
            act = event_dict.get("action", "Action")
            fn = event_dict.get("file_name", "File")
            mb = float(event_dict.get("download_mb", 0.0))
            sig = event_dict.get("risk_factors_str", "")

            if lvl in ["CRITICAL", "HIGH"]:
                alert_placeholder.markdown(
                    f"""
                    <div class="live-alert-box">
                        <strong style="color: #F87171; font-size: 1.05rem;">🚨 [{lvl} ALERT] Threat Score: {score:.0f}/100</strong><br>
                        <strong>{emp}</strong> initiated <code>{act}</code> on <code>{fn}</code> ({mb:,.1f} MB).<br>
                        <span style="font-size: 0.85rem; color: #FCA5A5;">⚠️ Signals: {sig}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                alert_placeholder.markdown(
                    f"""
                    <div class="live-normal-box">
                        <strong style="color: #34D399;">🟢 [NORMAL] Score: {score:.0f}/100</strong> — 
                        {emp} performed {act} on <code>{fn}</code> ({mb:,.1f} MB).
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            live_crit = sum(1 for e in st.session_state.live_stream_events if e.get("risk_level") in ["CRITICAL", "HIGH"])
            with kpi_placeholder.container():
                mk1, mk2, mk3, mk4 = st.columns(4)
                mk1.metric("Live Events Received", f"{len(st.session_state.live_stream_events)}")
                mk2.metric("Threat Alerts Detected", f"{live_crit}", delta=f"{live_crit} High/Crit", delta_color="inverse")
                mk3.metric("Latest Event Score", f"{score:.0f} / 100")
                mk4.metric("Pipeline State", "Active 🟢")

            feed_df = pd.DataFrame(st.session_state.live_stream_events)
            if not feed_df.empty:
                display_cols = ["timestamp", "employee_name", "department", "action", "file_name", "download_mb", "risk_score", "risk_level", "risk_factors_str"]
                feed_placeholder.dataframe(
                    feed_df[display_cols].rename(columns={
                        "timestamp": "Time",
                        "employee_name": "Employee",
                        "department": "Department",
                        "action": "Action",
                        "file_name": "Target File",
                        "download_mb": "MB",
                        "risk_score": "Risk Score",
                        "risk_level": "Tier",
                        "risk_factors_str": "Detected Signals"
                    }),
                    use_container_width=True,
                    height=280
                )

            time.sleep(stream_speed)

        status_placeholder.success(f"✅ Live simulation finished! Processed {stream_count} events. Check the 'Overview' tab to see updated global metrics.")

    elif st.session_state.live_stream_events:
        live_crit = sum(1 for e in st.session_state.live_stream_events if e.get("risk_level") in ["CRITICAL", "HIGH"])
        mk1, mk2, mk3, mk4 = st.columns(4)
        mk1.metric("Live Events Ingested", f"{len(st.session_state.live_stream_events)}")
        mk2.metric("Threat Alerts Detected", f"{live_crit}")
        mk3.metric("Last Event Score", f"{st.session_state.live_stream_events[0].get('risk_score', 0):.0f} / 100")
        mk4.metric("Pipeline State", "Idle ⏸️")

        st.markdown("#### 📜 Live Telemetry Ingestion Log")
        feed_df = pd.DataFrame(st.session_state.live_stream_events)
        display_cols = ["timestamp", "employee_name", "department", "action", "file_name", "download_mb", "risk_score", "risk_level", "risk_factors_str"]
        st.dataframe(
            feed_df[display_cols].rename(columns={
                "timestamp": "Time",
                "employee_name": "Employee",
                "department": "Department",
                "action": "Action",
                "file_name": "Target File",
                "download_mb": "MB",
                "risk_score": "Risk Score",
                "risk_level": "Tier",
                "risk_factors_str": "Detected Signals"
            }),
            use_container_width=True,
            height=300
        )
    else:
        st.info("💡 Click **'▶️ Launch Live Stream'** above to simulate real-time employee telemetry streaming into the dashboard.")


# ==============================================================================
# TAB 3: EMPLOYEE INVESTIGATION
# ==============================================================================
with tab_investigate:
    st.markdown("### 🔍 Employee Activity & Alerts")
    
    # Employee Selector
    emp_ids = sorted(scored_df["employee_id"].unique())
    emp_labels = {}
    for eid in emp_ids:
        sub = scored_df[scored_df["employee_id"] == eid].iloc[0]
        max_s = scored_df[scored_df["employee_id"] == eid]["risk_score"].max()
        emp_labels[eid] = f"{sub['employee_name']} ({eid}) - Max Risk: {max_s:.0f} pts [{sub['department']}]"

    selected_emp_id = st.selectbox(
        "Select Employee to Investigate:",
        options=emp_ids,
        format_func=lambda x: emp_labels[x],
        index=0
    )

    emp_records = scored_df[scored_df["employee_id"] == selected_emp_id].sort_values("timestamp", ascending=False)
    emp_meta = emp_records.iloc[0]

    # Employee Summary Card
    p_col1, p_col2, p_col3, p_col4, p_col5 = st.columns(5)
    with p_col1:
        st.metric("Employee Name", emp_meta["employee_name"])
    with p_col2:
        st.metric("Department", emp_meta["department"])
    with p_col3:
        st.metric("Assigned Role", emp_meta.get("role", "Staff Member"))
    with p_col4:
        st.metric("Peak Risk Score", f"{emp_records['risk_score'].max():.0f} / 100")
    with p_col5:
        st.metric("Flagged Events", f"{emp_records['is_flagged'].sum()} of {len(emp_records)}")

    # Interactive Notes Log for Employee
    st.markdown("#### 📝 Investigation Notes")
    curr_triage = st.session_state.triage_notes.get(selected_emp_id, {"status": "Under Investigation", "note": ""})
    
    n_col1, n_col2 = st.columns([1, 3])
    with n_col1:
        triage_status = st.selectbox(
            "Status",
            ["Under Investigation", "Escalated for Review", "Resolved / False Positive", "Privilege Restricted"],
            index=["Under Investigation", "Escalated for Review", "Resolved / False Positive", "Privilege Restricted"].index(curr_triage.get("status", "Under Investigation") if curr_triage.get("status") in ["Under Investigation", "Escalated for Review", "Resolved / False Positive", "Privilege Restricted"] else "Under Investigation")
        )
    with n_col2:
        triage_text = st.text_input(
            "Investigation Note / Comment",
            value=curr_triage["note"],
            placeholder="e.g. Activity verified with employee manager; legitimate database backup."
        )

    if st.button("💾 Save Note"):
        st.session_state.triage_notes[selected_emp_id] = {"status": triage_status, "note": triage_text}
        st.success(f"Saved note for {emp_meta['employee_name']}.")

    st.markdown("---")
    st.markdown("#### ⏱️ Activity Stream & Alerts")

    st.write(f"Showing **{len(emp_records)}** event(s) recorded for **{emp_meta['employee_name']}**:")

    for idx, (_, row) in enumerate(emp_records.iterrows()):
        render_event_investigation_card(row, idx)


# ==============================================================================
# TAB 3: DEMO SCENARIOS
# ==============================================================================
with tab_scenarios:
    st.markdown("### 🧪 Interactive Demo Scenarios")
    st.markdown(
        "Click any scenario below to see how InsiderTrace AI detects different behavioral patterns:"
    )

    s_col1, s_col2 = st.columns(2)

    with s_col1:
        st.markdown(
            """
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(239, 68, 68, 0.4); 
                        border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h4 style="color: #F87171; margin-top: 0;">⚡ Scenario 1: Bulk Exfiltration Before Resignation</h4>
                <p style="font-size: 0.88rem; color: #CBD5E1;">
                    A senior engineer downloading 12+ GB of customer PII vaults, source code repositories, and
                    credential dumps late on a Sunday evening from an unmanaged personal device.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("🚀 Load Scenario 1 (Bulk Exfiltration)"):
            base = [generate_normal_event() for _ in range(250)]
            attacks = generate_bulk_download_attack("EMP-1035")
            combined = pd.DataFrame(base + attacks)
            st.session_state.raw_df = combined
            st.session_state.active_scenario = "Scenario: Bulk Exfiltration (Elena Rostova)"
            rerun_detection()
            st.success("Loaded Bulk Exfiltration Scenario! Navigating to dashboard...")
            st.rerun()

        st.markdown(
            """
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(249, 115, 22, 0.4); 
                        border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h4 style="color: #FB923C; margin-top: 0;">🌙 Scenario 2: Unusual After-Hours Credential Abuse</h4>
                <p style="font-size: 0.88rem; color: #CBD5E1;">
                    A systems administrator harvesting encryption keys, executive compensation files, and M&A briefs
                    at 2:22 AM originating through a suspicious Tor exit node.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("🚀 Load Scenario 2 (After-Hours Privilege Abuse)"):
            base = [generate_normal_event() for _ in range(250)]
            attacks = generate_after_hours_privilege_abuse("EMP-1024")
            combined = pd.DataFrame(base + attacks)
            st.session_state.raw_df = combined
            st.session_state.active_scenario = "Scenario: After-Hours Credential Abuse (Marcus Vance)"
            rerun_detection()
            st.success("Loaded After-Hours Abuse Scenario! Navigating to dashboard...")
            st.rerun()

    with s_col2:
        st.markdown(
            """
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(234, 179, 8, 0.4); 
                        border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h4 style="color: #FACC15; margin-top: 0;">🕵️ Scenario 3: Low & Slow Document Scraping</h4>
                <p style="font-size: 0.88rem; color: #CBD5E1;">
                    A sales representative incrementally sharing confidential client portfolios and pricing
                    secrets over 5 consecutive days from public coffee shop Wi-Fi networks.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("🚀 Load Scenario 3 (Low & Slow Scraping)"):
            base = [generate_normal_event() for _ in range(250)]
            attacks = generate_slow_burn_exfiltration("EMP-1042")
            combined = pd.DataFrame(base + attacks)
            st.session_state.raw_df = combined
            st.session_state.active_scenario = "Scenario: Low & Slow Scraping (Derek Chen)"
            rerun_detection()
            st.success("Loaded Low & Slow Scraping Scenario! Navigating to dashboard...")
            st.rerun()

        st.markdown(
            """
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(16, 185, 129, 0.4); 
                        border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h4 style="color: #34D399; margin-top: 0;">🟢 Scenario 4: Benign Baseline Operations</h4>
                <p style="font-size: 0.88rem; color: #CBD5E1;">
                    Strictly routine corporate baseline operations during regular business hours (8am-6pm) with
                    standard non-sensitive documents and legitimate corporate VPN access.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("🚀 Load Scenario 4 (Clean Baseline)"):
            base = [generate_normal_event() for _ in range(300)]
            combined = pd.DataFrame(base)
            st.session_state.raw_df = combined
            st.session_state.active_scenario = "Clean Baseline (Zero Attacks)"
            rerun_detection()
            st.success("Loaded Clean Baseline! All activities should register Low risk.")
            st.rerun()

    st.markdown("---")
    if st.button("🔄 Reset to Default Multi-Scenario Dataset"):
        st.session_state.raw_df = generate_synthetic_dataset(n_records=450, include_anomalies=True, seed=42)
        st.session_state.active_scenario = "Comprehensive Multi-Threat Dataset"
        rerun_detection()
        st.success("Reset to default dataset!")
        st.rerun()


# ==============================================================================
# TAB 4: DATA INGESTION & CSV UPLOAD
# ==============================================================================
with tab_upload:
    st.markdown("### 📂 Custom CSV Log Ingestion & Schema Validation")
    st.markdown(
        "Upload your organization's anonymized employee activity logs. "
        "The validator will inspect schemas, verify data ranges, and auto-derive missing fields."
    )

    up_col1, up_col2 = st.columns([2, 1])

    with up_col1:
        uploaded_file = st.file_uploader(
            "Upload Employee Activity CSV",
            type=["csv"],
            help="Upload a CSV with columns: timestamp, employee_id, employee_name, department, action, file_name, download_mb"
        )

    with up_col2:
        st.markdown("#### 📄 Schema Template")
        template_csv = generate_sample_csv_template()
        st.download_button(
            label="📥 Download Sample CSV Template",
            data=template_csv,
            file_name="insidertrace_sample_template.csv",
            mime="text/csv",
            help="Download a properly formatted sample CSV file with standard headers"
        )

    if uploaded_file is not None:
        try:
            input_df = pd.read_csv(uploaded_file)
            validation = validate_and_prepare_logs(input_df)

            if validation.is_valid:
                st.success(f"✅ CSV successfully validated! Ingested **{validation.summary['total_rows']:,}** records.")
                
                # Show summary chips
                s1, s2, s3, s4 = st.columns(4)
                s1.metric("Total Events", f"{validation.summary['total_rows']:,}")
                s2.metric("Unique Personnel", f"{validation.summary['unique_employees']}")
                s3.metric("Data Volume", f"{validation.summary['total_download_gb']} GB")
                s4.metric("Off-Hours Events", f"{validation.summary['after_hours_count']}")

                if validation.warnings:
                    with st.expander("⚠️ Validator Warnings & Auto-Derivations", expanded=True):
                        for w in validation.warnings:
                            st.warning(w)

                if st.button("🚀 Process & Analyze Uploaded Dataset"):
                    st.session_state.raw_df = validation.cleaned_df
                    st.session_state.active_scenario = f"Uploaded CSV ({uploaded_file.name})"
                    rerun_detection()
                    st.success("Analysis complete! Check the Executive Threat Dashboard.")
                    st.rerun()
            else:
                st.error("❌ CSV Validation Failed:")
                for err in validation.errors:
                    st.markdown(f"- 🔴 {err}")
        except Exception as e:
            st.error(f"Failed to read CSV file: {str(e)}")

    st.markdown("---")
    st.markdown("#### 🧪 Generate Custom Synthetic Dataset")
    c_s1, c_s2 = st.columns(2)
    with c_s1:
        custom_n = st.slider("Number of Activity Records", 50, 2000, 500, step=50)
    with c_s2:
        include_anom = st.checkbox("Inject Anomaly Scenarios", value=True)

    if st.button("⚡ Generate Fresh Random Dataset"):
        st.session_state.raw_df = generate_synthetic_dataset(n_records=custom_n, include_anomalies=include_anom)
        st.session_state.active_scenario = f"Custom Synthetic ({custom_n} events)"
        rerun_detection()
        st.success(f"Generated {custom_n} activity events!")
        st.rerun()


# ==============================================================================
# TAB 5: ENGINE ARCHITECTURE & ETHICS
# ==============================================================================
with tab_methodology:
    st.markdown("### ℹ️ Engine Architecture & Behavioral Methodology")

    st.markdown(
        """
        InsiderTrace AI utilizes a **dual-layer behavioral analytics architecture** designed to minimize false positives
        while providing transparent, explainable alerts for Security Operations Centers (SOCs).
        """
    )

    m_col1, m_col2 = st.columns(2)
    
    with m_col1:
        st.markdown(
            """
            #### 1. Machine Learning Layer (Isolation Forest)
            - **Algorithm:** Isolation Forest (`sklearn.ensemble.IsolationForest`)
            - **Premise:** Anomaly detection through recursive random tree partitioning. Anomalies require fewer splits to isolate in multidimensional feature space.
            - **Engineered Features:**
              - `download_mb`: Transferred file size in megabytes
              - `activity_hour`: Time-of-day integer (0–23)
              - `is_after_hours_num`: Off-hours indicator (0/1)
              - `is_sensitive_num`: Classified file sensitivity (0/1)
              - `is_suspicious_net`: Tor, anonymous proxy, or foreign egress IP (0/1)
              - `is_unmanaged_dev`: Unmanaged personal or unknown hardware (0/1)
            - **Score Normalization:** Decision function scores are percentile-calibrated into a continuous 0–100 Anomaly Intensity score.
            """
        )

    with m_col2:
        st.markdown(
            r"""
            #### 2. Explainable Rule Engine (Deterministic Cyber Rules)
            - **Weight Contribution:** Rules provide explainability for why an alert was generated.
            - **Core Rule Matrix:**
              - **Massive Exfiltration:** Downloads $\ge$ 5 GB (+40 pts) or $\ge$ 1.5 GB (+25 pts)
              - **Graveyard Access:** Sensitive data access between 00:00–05:00 (+22 pts)
              - **Untrusted Egress:** Tor / Proxy / Offshore IP (+25 pts)
              - **Unmanaged Hardware:** BYOD / Personal device (+15 pts)
              - **High-Risk Action:** External sharing (+20 pts)
              - **Crown-Jewel Asset:** Infrastructure or Intellectual Property (+12 pts)
            - **Composite Score Formula:**
              $$\\text{Score} = \\min(100, 0.40 \\times \\text{ML\\_Score} + 0.60 \\times \\text{Rule\\_Score})$$
            """
        )

    st.markdown("---")
    st.markdown(
        """
        #### ⚖️ Ethical Governance & SOC Human-in-the-Loop Standard
        1. **Signal, Not Verdict:** Machine-learning anomalies indicate **statistical divergence**, not malice. A developer running a late-night database migration or downloading logs to resolve a critical P0 outage exhibits identical statistical patterns to an adversary.
        2. **Privacy Protection:** No keystroke logging or invasive screen recording is performed. Telemetry is restricted to file access logs and corporate network metadata.
        3. **Auditable Decision Trails:** Every flagged alert includes explicit `risk_factors` and human-readable explanations, preventing "black-box" personnel discrimination.
        4. **Verification Protocol:** Prior to privilege revocation, analysts are mandated to cross-reference with authorized change tickets, on-call schedules, and manager approvals.
        """
    )
