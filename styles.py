"""Custom CSS and Theme Styling for InsiderTrace AI.

Provides dark navy cybersecurity styling with cyan/teal accents, glowing KPI cards,
risk level badges, alert boxes, and professional typography.
"""

CYBER_THEME_CSS = """
<style>
/* Main App Styling */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    color: #E2E8F0;
}

code, .stCode, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Background gradient */
.stApp {
    background: radial-gradient(circle at 10% 10%, #0F172A 0%, #070B19 100%);
    color: #E2E8F0;
}

/* Header Banner */
.cyber-header {
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%);
    border: 1px solid rgba(0, 173, 181, 0.3);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 8px 32px 0 rgba(0, 173, 181, 0.1);
    position: relative;
    overflow: hidden;
}

.cyber-header::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    width: 6px;
    height: 100%;
    background: linear-gradient(180deg, #00ADB5, #00FFF0);
}

.cyber-title {
    font-size: 2.2rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    background: linear-gradient(90deg, #FFFFFF 0%, #38BDF8 50%, #00FFF0 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 12px;
}

.cyber-subtitle {
    color: #94A3B8;
    font-size: 0.95rem;
    margin-top: 6px;
    margin-bottom: 0px;
}

/* Modern KPI Cards */
.kpi-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.kpi-card {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 10px;
    padding: 16px 20px;
    position: relative;
    transition: all 0.3s ease;
    backdrop-filter: blur(10px);
}

.kpi-card:hover {
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.6);
    box-shadow: 0 4px 20px rgba(0, 173, 181, 0.15);
}

.kpi-title {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #94A3B8;
    margin-bottom: 6px;
    font-weight: 600;
}

.kpi-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #F8FAFC;
    line-height: 1.2;
}

.kpi-delta {
    font-size: 0.78rem;
    margin-top: 4px;
    display: flex;
    align-items: center;
    gap: 4px;
}

.delta-danger { color: #F87171; }
.delta-warning { color: #FBBF24; }
.delta-success { color: #34D399; }
.delta-info { color: #38BDF8; }

/* Risk Badges */
.badge-risk-critical {
    background: rgba(239, 68, 68, 0.18);
    color: #FCA5A5;
    border: 1px solid rgba(239, 68, 68, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

.badge-risk-high {
    background: rgba(249, 115, 22, 0.18);
    color: #FDBA74;
    border: 1px solid rgba(249, 115, 22, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

.badge-risk-medium {
    background: rgba(234, 179, 8, 0.18);
    color: #FDE047;
    border: 1px solid rgba(234, 179, 8, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

.badge-risk-low {
    background: rgba(16, 185, 129, 0.18);
    color: #6EE7B7;
    border: 1px solid rgba(16, 185, 129, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
}

/* Live Stream Indicator and Alerts */
.live-indicator {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: #34D399;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 600;
}

.live-dot {
    width: 10px;
    height: 10px;
    background-color: #10B981;
    border-radius: 50%;
    box-shadow: 0 0 8px #10B981;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0% { transform: scale(0.95); opacity: 0.7; }
    50% { transform: scale(1.2); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.7; }
}

.live-alert-box {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.5);
    border-left: 5px solid #EF4444;
    padding: 12px 18px;
    border-radius: 8px;
    margin-bottom: 16px;
}

.live-normal-box {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-left: 5px solid #10B981;
    padding: 12px 18px;
    border-radius: 8px;
    margin-bottom: 16px;
}

/* SOC Investigation Notice */
.soc-ethics-banner {
    background: rgba(30, 41, 59, 0.7);
    border-left: 4px solid #38BDF8;
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    margin: 16px 0 24px 0;
    font-size: 0.9rem;
    color: #CBD5E1;
    display: flex;
    align-items: flex-start;
    gap: 12px;
}

/* Timeline Cards */
.timeline-card {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(51, 65, 85, 0.7);
    border-left: 4px solid #38BDF8;
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 12px;
    transition: transform 0.2s ease;
}

.timeline-card.critical {
    border-left-color: #EF4444;
    background: rgba(239, 68, 68, 0.05);
}

.timeline-card.high {
    border-left-color: #F97316;
    background: rgba(249, 115, 22, 0.05);
}

.timeline-card.medium {
    border-left-color: #EAB308;
}

.timeline-card.low {
    border-left-color: #10B981;
}

/* Streamlit Widget Overrides */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: transparent;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 6px 6px 0px 0px;
    padding: 10px 18px;
    background-color: rgba(15, 23, 42, 0.4);
    border: 1px solid rgba(51, 65, 85, 0.4);
    color: #94A3B8;
    font-weight: 500;
}

.stTabs [aria-selected="true"] {
    background-color: rgba(30, 41, 59, 0.9) !important;
    border-bottom: 2px solid #00ADB5 !important;
    color: #00FFF0 !important;
    font-weight: 600;
}

div[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 10px;
    padding: 14px 18px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
}

div[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
}

div[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
    font-weight: 700 !important;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #0B132B !important;
    border-right: 1px solid rgba(51, 65, 85, 0.5);
}

/* Buttons */
.stButton>button {
    background: linear-gradient(135deg, #00ADB5 0%, #00818A 100%);
    color: white;
    font-weight: 600;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    transition: all 0.2s ease;
}

.stButton>button:hover {
    background: linear-gradient(135deg, #00FFF0 0%, #00ADB5 100%);
    box-shadow: 0 0 15px rgba(0, 173, 181, 0.4);
    color: #0F172A;
}

/* Dataframe styling */
div[data-testid="stDataFrame"] {
    border-radius: 8px;
    border: 1px solid rgba(51, 65, 85, 0.5);
    overflow: hidden;
}
</style>
"""

def get_risk_badge_html(risk_level: str) -> str:
    """Return colored HTML badge for a given risk level."""
    level = str(risk_level).lower().strip()
    if level == "critical":
        return '<span class="badge-risk-critical">CRITICAL</span>'
    elif level == "high":
        return '<span class="badge-risk-high">HIGH</span>'
    elif level == "medium":
        return '<span class="badge-risk-medium">MEDIUM</span>'
    else:
        return '<span class="badge-risk-low">LOW</span>'
