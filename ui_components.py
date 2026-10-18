"""Reusable UI Components and Plotly Visualizations for InsiderTrace AI.

Provides cyber-themed charts, KPI widgets, investigative timelines, and risk indicators.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from src.styles import get_risk_badge_html

# Cybersecurity Palette
COLOR_CRITICAL = "#EF4444"
COLOR_HIGH = "#F97316"
COLOR_MEDIUM = "#EAB308"
COLOR_LOW = "#10B981"
BG_DARK = "#0B132B"
BG_CARD = "#1C2541"
TEXT_LIGHT = "#E2E8F0"
GRID_COLOR = "rgba(51, 65, 85, 0.4)"

RISK_COLOR_MAP = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH": COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM,
    "LOW": COLOR_LOW
}


def render_kpi_summary(df: pd.DataFrame) -> None:
    """Render executive KPI cards at the top of the dashboard."""
    total_events = len(df)
    flagged_events = df["is_flagged"].sum() if "is_flagged" in df.columns else 0
    critical_events = (df["risk_level"] == "CRITICAL").sum() if "risk_level" in df.columns else 0
    high_events = (df["risk_level"] == "HIGH").sum() if "risk_level" in df.columns else 0
    
    # Suspicious data volume (downloads with risk >= 70)
    high_risk_mask = df["risk_score"] >= 70 if "risk_score" in df.columns else False
    suspicious_volume_gb = (df.loc[high_risk_mask, "download_mb"].sum()) / 1024.0
    
    top_score = df["risk_score"].max() if "risk_score" in df.columns else 0.0

    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Activities",
            value=f"{total_events:,}",
            help="Total number of logged employee activity events"
        )
    with col2:
        st.metric(
            label="Flagged Anomalies",
            value=f"{flagged_events:,}",
            delta=f"{(flagged_events / max(1, total_events) * 100):.1f}% Anomaly Rate",
            delta_color="inverse",
            help="Events flagged as behavioral anomalies or elevated risk"
        )
    with col3:
        st.metric(
            label="High & Critical Alerts",
            value=f"{critical_events + high_events:,}",
            delta=f"{critical_events} Critical Alerts",
            delta_color="inverse",
            help="Events requiring priority human investigation"
        )
    with col4:
        st.metric(
            label="High-Risk Downloads",
            value=f"{suspicious_volume_gb:.2f} GB",
            help="Total download volume in high/critical risk events"
        )
    with col5:
        st.metric(
            label="Peak Risk Score",
            value=f"{top_score:.0f} / 100",
            help="Highest individual risk score recorded"
        )


def render_risk_distribution_chart(df: pd.DataFrame) -> go.Figure:
    """Generate risk score distribution histogram with calibrated zones."""
    fig = px.histogram(
        df,
        x="risk_score",
        nbins=30,
        color="risk_level",
        color_discrete_map=RISK_COLOR_MAP,
        labels={"risk_score": "Composite Risk Score (0-100)", "count": "Event Count"},
        title="<b>Risk Score Distribution</b> (ML + Rule Composite)"
    )
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        font=dict(color=TEXT_LIGHT, family="Inter"),
        margin=dict(l=20, r=20, t=50, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis=dict(gridcolor=GRID_COLOR, range=[0, 102]),
        yaxis=dict(gridcolor=GRID_COLOR),
        bargap=0.1
    )
    return fig


def render_risk_donut_chart(df: pd.DataFrame) -> go.Figure:
    """Generate risk level composition donut chart."""
    counts = df["risk_level"].value_counts().reset_index()
    counts.columns = ["risk_level", "count"]
    
    fig = px.pie(
        counts,
        names="risk_level",
        values="count",
        hole=0.58,
        color="risk_level",
        color_discrete_map=RISK_COLOR_MAP,
        title="<b>Threat Tier Composition</b>"
    )
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_LIGHT, family="Inter"),
        margin=dict(l=10, r=10, t=50, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
        annotations=[
            dict(
                text=f"<b>{len(df):,}</b><br>Logs",
                x=0.5, y=0.5,
                font_size=16,
                font_color="#38BDF8",
                showarrow=False
            )
        ]
    )
    return fig


def render_download_vs_hour_chart(df: pd.DataFrame) -> go.Figure:
    """Scatter plot of Activity Hour vs Download Volume with risk coloring."""
    fig = px.scatter(
        df,
        x="activity_hour",
        y="download_mb",
        color="risk_level",
        color_discrete_map=RISK_COLOR_MAP,
        size="risk_score",
        hover_data=["employee_name", "action", "file_name", "risk_score", "location"],
        labels={"activity_hour": "Activity Hour (24h)", "download_mb": "Data Volume (MB)"},
        title="<b>Data Volume vs. Activity Hour</b> (Bubble size = Risk Score)"
    )
    
    # Shade off-hours
    fig.add_vrect(x0=-0.5, x1=6.5, fillcolor="rgba(239, 68, 68, 0.08)", line_width=0, annotation_text="Off-Hours", annotation_position="top left")
    fig.add_vrect(x0=19.5, x1=23.5, fillcolor="rgba(239, 68, 68, 0.08)", line_width=0, annotation_text="Off-Hours", annotation_position="top right")

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        font=dict(color=TEXT_LIGHT, family="Inter"),
        margin=dict(l=20, r=20, t=50, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis=dict(gridcolor=GRID_COLOR, tickmode="linear", tick0=0, dtick=2, range=[-0.5, 23.5]),
        yaxis=dict(gridcolor=GRID_COLOR)
    )
    return fig


def render_top_risky_employees_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart ranking employees by maximum risk score."""
    emp_summary = df.groupby(["employee_id", "employee_name", "department"]).agg(
        max_score=("risk_score", "max"),
        anomaly_count=("is_anomaly", "sum"),
        total_downloads=("download_mb", "sum")
    ).reset_index()
    
    top_emp = emp_summary.sort_values("max_score", ascending=True).tail(8)
    
    # Assign color based on max score
    colors = []
    for s in top_emp["max_score"]:
        if s >= 85:
            colors.append(COLOR_CRITICAL)
        elif s >= 70:
            colors.append(COLOR_HIGH)
        elif s >= 40:
            colors.append(COLOR_MEDIUM)
        else:
            colors.append(COLOR_LOW)
            
    fig = go.Figure(go.Bar(
        x=top_emp["max_score"],
        y=[f"{name} ({eid})" for name, eid in zip(top_emp["employee_name"], top_emp["employee_id"])],
        orientation="h",
        marker=dict(color=colors, line=dict(color="#38BDF8", width=1)),
        text=[f"{s:.0f} pts" for s in top_emp["max_score"]],
        textposition="inside",
        hovertext=[
            f"Department: {dept}<br>Anomalies: {anom}<br>Total Vol: {vol:.1f} MB"
            for dept, anom, vol in zip(top_emp["department"], top_emp["anomaly_count"], top_emp["total_downloads"])
        ]
    ))
    
    fig.update_layout(
        title="<b>Top Riskiest Personnel (Peak Threat Score)</b>",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        font=dict(color=TEXT_LIGHT, family="Inter"),
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(gridcolor=GRID_COLOR, range=[0, 105]),
        yaxis=dict(gridcolor=GRID_COLOR)
    )
    return fig


def render_threat_timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Timeline chart showing threat occurrence over time."""
    df_sorted = df.copy()
    df_sorted["datetime"] = pd.to_datetime(df_sorted["timestamp"])
    df_sorted = df_sorted.sort_values("datetime")

    fig = px.scatter(
        df_sorted,
        x="datetime",
        y="risk_score",
        color="risk_level",
        color_discrete_map=RISK_COLOR_MAP,
        size="download_mb",
        size_max=28,
        hover_data=["employee_name", "action", "file_name", "risk_factors_str"],
        labels={"datetime": "Timeline", "risk_score": "Risk Score"},
        title="<b>Threat Incidents Over Time</b>"
    )
    
    # Add horizontal threshold line
    fig.add_hline(y=70, line_dash="dash", line_color="#F97316", annotation_text="High Threat Baseline (70)", annotation_position="bottom right")
    fig.add_hline(y=85, line_dash="dot", line_color="#EF4444", annotation_text="Critical Threat Baseline (85)", annotation_position="top right")

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        font=dict(color=TEXT_LIGHT, family="Inter"),
        margin=dict(l=20, r=20, t=50, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis=dict(gridcolor=GRID_COLOR),
        yaxis=dict(gridcolor=GRID_COLOR, range=[0, 105])
    )
    return fig


def render_event_investigation_card(event: pd.Series, idx: int) -> None:
    """Render a detailed, expandable investigation card for a single alert."""
    level = str(event.get("risk_level", "LOW")).upper()
    score = float(event.get("risk_score", 0.0))
    ts = str(event.get("timestamp", ""))
    emp_name = str(event.get("employee_name", ""))
    emp_id = str(event.get("employee_id", ""))
    action = str(event.get("action", ""))
    file_name = str(event.get("file_name", ""))
    dl_mb = float(event.get("download_mb", 0.0))
    loc = str(event.get("location", ""))
    dev = str(event.get("device_type", ""))
    ip = str(event.get("ip_address", ""))
    factors = event.get("risk_factors", [])
    explanation = str(event.get("explanation", ""))
    rec = str(event.get("soc_recommendation", ""))
    ml_score = float(event.get("ml_score", 0.0))
    rule_score = float(event.get("rule_score", 0.0))

    badge_html = get_risk_badge_html(level)
    
    card_class = f"timeline-card {level.lower()}"
    
    st.markdown(
        f"""
        <div class="{card_class}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div>
                    <span style="font-weight: 700; color: #38BDF8; font-size: 1.05rem;">{emp_name}</span>
                    <span style="color: #94A3B8; font-size: 0.85rem; margin-left: 8px;">({emp_id})</span>
                </div>
                <div>
                    {badge_html}
                    <span style="font-size: 1.1rem; font-weight: 700; margin-left: 8px; color: #F8FAFC;">
                        {score:.0f}<span style="font-size: 0.75rem; color: #94A3B8;">/100</span>
                    </span>
                </div>
            </div>
            <div style="color: #CBD5E1; font-size: 0.9rem; margin-bottom: 6px;">
                <strong>Action:</strong> <code>{action}</code> on <code>{file_name}</code> ({dl_mb:,.1f} MB)
            </div>
            <div style="color: #94A3B8; font-size: 0.8rem; display: flex; gap: 16px; flex-wrap: wrap;">
                <span>⏱️ {ts}</span>
                <span>🌐 {loc} ({ip})</span>
                <span>💻 {dev}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.expander(f"🔍 View Forensic Details & Triage Guidance (Alert #{idx + 1})"):
        c1, c2 = st.columns([1, 1])
        with c1:
            st.markdown("**Scoring Composition:**")
            st.write(f"- **ML Anomaly Intensity:** `{ml_score:.1f} / 100`")
            st.write(f"- **Rule Engine Score:** `{rule_score:.1f} / 100`")
            st.write(f"- **Calibrated Composite:** `{score:.1f} / 100`")
        with c2:
            st.markdown("**Triggered Risk Signals:**")
            if factors:
                for f in factors:
                    st.markdown(f"- ⚠️ {f}")
            else:
                st.write("No severe rule factors; flagged via behavioral deviation.")

        st.markdown(f"**Analyst Narrative:** {explanation}")
        st.info(f"**SOC Recommended Action:** {rec}")
