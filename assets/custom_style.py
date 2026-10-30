import streamlit as st  # type: ignore

def apply_custom_theme():
    """Áp dụng bộ CSS tinh gọn, tối ưu tốc độ render và giữ giao diện Dark SOC chuyên nghiệp."""
    custom_css = """
    <style>
    /* Dark Base & Clean Typography */
    .stApp {
        background-color: #0b0f19 !important;
        color: #e2e8f0;
    }

    /* Sidebar Clean */
    [data-testid="stSidebar"] {
        background-color: #070a13 !important;
        border-right: 1px solid #1e293b !important;
    }

    /* KPI Metric Cards - Fast Rendering */
    [data-testid="stMetric"] {
        background-color: #131b2e !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
    }
    [data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 13px !important;
        font-weight: 600 !important;
    }
    [data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700 !important;
        font-size: 24px !important;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 6px !important;
        font-weight: 600 !important;
        border: 1px solid #334155 !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #0b0f19;
    }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 3px;
    }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)
