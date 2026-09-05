"""
Streamlit Threat Forensics Dashboard
Interactive security analyst workstation for email artifact inspection and Grok AI URL analysis.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import json
import time

from config import settings
from src.url_analysis import get_url_analyzer
from src.origin_analysis import get_origin_analyzer
from src.header_forensics.parser import parse_received_header, extract_ip_candidates
from src.header_forensics.auth_trust import parse_auth_context, check_auth_results
from src.header_forensics.anomalies import detect_anomalies
from src.header_forensics.scoring import compute_risk_score
from src.fusion import fuse_threat_intelligence
import email

# Page configuration
st.set_page_config(
    page_title="SIH-26106 Threat Forensics & Grok AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #888;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1e1e24;
        border-radius: 8px;
        padding: 1.2rem;
        border: 1px solid #333;
    }
    .tier-critical { color: #ff4b4b; font-weight: bold; font-size: 1.4rem; }
    .tier-high { color: #ff8c00; font-weight: bold; font-size: 1.4rem; }
    .tier-suspicious { color: #ffd700; font-weight: bold; font-size: 1.4rem; }
    .tier-low { color: #00cc66; font-weight: bold; font-size: 1.4rem; }
</style>
""", unsafe_allow_html=True)


def get_tier_html(tier: str, score: int) -> str:
    color_map = {
        "CRITICAL": "tier-critical",
        "HIGH": "tier-high",
        "SUSPICIOUS": "tier-suspicious",
        "LOW": "tier-low"
    }
    cls = color_map.get(tier, "tier-low")
    return f"<span class='{cls}'>{tier} ({score}/100)</span>"


# Header
st.markdown("<div class='main-header'>🛡️ SIH-26106 Threat Forensics & Grok AI</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-header'>Explainable Email Threat Investigation & Grok-Powered URL Classification</div>", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("Configuration & Status")
url_analyzer = get_url_analyzer()
grok_client = url_analyzer.grok_client

if grok_client.is_available:
    st.sidebar.success(f"🟢 Grok AI Active ({grok_client.model})")
else:
    st.sidebar.warning("🟡 Grok AI Offline (Deterministic Mode)")

st.sidebar.info(f"📁 Cache: SQLite ({settings.CACHE_DB_PATH.name})")

# Sample loader
st.sidebar.subheader("Quick Test Samples")
sample_files = list(settings.SAMPLES_DIR.glob("*.eml")) if settings.SAMPLES_DIR.exists() else []
selected_sample = st.sidebar.selectbox(
    "Load Sample EML",
    options=["None"] + [f.name for f in sample_files]
)

# Tabs
tab_email, tab_url, tab_telemetry = st.tabs([
    "📧 Email Forensics Investigation",
    "🔗 Grok AI URL Scanner",
    "⚙️ Cache & Telemetry"
])

# ------------------------------------------------------------------------------
# TAB 1: Email Forensics
# ------------------------------------------------------------------------------
with tab_email:
    st.subheader("Upload or Paste Raw Email Artifact")

    sample_content = ""
    if selected_sample != "None":
        p = settings.SAMPLES_DIR / selected_sample
        if p.exists():
            sample_content = p.read_text(encoding="utf-8", errors="replace")

    col_upload, col_text = st.columns([1, 1])

    with col_upload:
        uploaded_file = st.file_uploader("Upload .eml file", type=["eml", "txt"])

    with col_text:
        raw_input = st.text_area(
            "Or Paste Raw RFC 822 Email Headers & Body",
            value=sample_content,
            height=200
        )

    eml_bytes = None
    if uploaded_file is not None:
        eml_bytes = uploaded_file.read()
    elif raw_input.strip():
        eml_bytes = raw_input.encode("utf-8", errors="replace")

    if st.button("🚀 Run Comprehensive Threat Investigation", type="primary"):
        if not eml_bytes:
            st.error("Please upload an .eml file or paste email text.")
        else:
            with st.spinner("Analyzing email headers, origin infrastructure, and embedded URLs..."):
                msg = email.message_from_bytes(eml_bytes)
                received_hdrs = msg.get_all("Received") or []
                relay_chain = [parse_received_header(h) for h in received_hdrs]
                all_candidates = []
                for h in received_hdrs:
                    all_candidates.extend(extract_ip_candidates(h))
                origin_ip = all_candidates[-1] if all_candidates else None

                auth_context = parse_auth_context(msg, relay_chain)
                auth_results = check_auth_results(auth_context)
                anomalies, domain_rel, brand_cat = detect_anomalies(msg, relay_chain, auth_results)
                header_risk_score = compute_risk_score(anomalies, auth_results)

                header_data = {
                    "subject": msg.get("Subject", "(No Subject)"),
                    "from_addr": msg.get("From", ""),
                    "return_path": msg.get("Return-Path", ""),
                    "auth_results": auth_results,
                    "relay_hops_count": len(relay_chain),
                    "anomalies": anomalies,
                    "risk_score": header_risk_score,
                    "selected_origin_ip": origin_ip,
                }

                origin_analyzer = get_origin_analyzer()
                origin_data = origin_analyzer.analyze(origin_ip) if origin_ip else {
                    "ip": None, "valid": False, "risk_score": 0.0, "reasons": ["No origin IP found"]
                }

                url_data = url_analyzer.analyze_email(eml_bytes)
                fusion = fuse_threat_intelligence(header_data, origin_data, url_data)

            # Executive Summary Section
            st.markdown("---")
            st.subheader("🎯 Executive Threat Verdict")

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Final Threat Score", f"{fusion['final_threat_score']}/100")
            with col2:
                st.metric("Operational Tier", fusion['threat_tier'])
            with col3:
                st.metric("Confidence", f"{int(fusion['confidence'] * 100)}%")
            with col4:
                st.metric("Primary Vector", fusion['primary_threat_vector'])

            # Recommendation Alert
            rec = fusion["recommendation"]
            if fusion["threat_tier"] in ["CRITICAL", "HIGH"]:
                st.error(f"⚠️ **Action Required**: {rec}")
            elif fusion["threat_tier"] == "SUSPICIOUS":
                st.warning(f"🔍 **Advisory**: {rec}")
            else:
                st.success(f"✅ **Safe**: {rec}")

            # Breakdown Cards
            st.markdown("### 📊 Multi-Vector Component Analysis")
            b_col1, b_col2, b_col3 = st.columns(3)

            with b_col1:
                st.markdown("#### ✉️ Header Forensics")
                st.write(f"**From:** `{header_data['from_addr']}`")
                st.write(f"**Return-Path:** `{header_data['return_path']}`")
                st.write(f"**SPF:** `{auth_results.get('spf_result', 'N/A')}` | **DKIM:** `{auth_results.get('dkim_result', 'N/A')}`")
                st.write(f"**Risk Score:** {header_data['risk_score']}/100")
                if anomalies:
                    st.write("**Detected Header Anomalies:**")
                    for a in anomalies:
                        st.markdown(f"- 🔴 {a}")
                else:
                    st.write("🟢 No header anomalies detected.")

            with b_col2:
                st.markdown("#### 🌐 Origin Infrastructure")
                st.write(f"**Origin IP:** `{origin_data.get('ip') or 'N/A'}`")
                st.write(f"**Classification:** `{origin_data.get('classification', 'unknown')}`")
                st.write(f"**Datacenter / Cloud:** {'⚠️ YES' if origin_data.get('is_datacenter') else '🟢 NO'}")
                st.write(f"**VPN / Proxy:** {'⚠️ YES' if origin_data.get('is_vpn') else '🟢 NO'}")
                st.write(f"**Infrastructure Risk:** {origin_data.get('risk_score', 0)}/100")

            with b_col3:
                st.markdown("#### 🔗 Grok URL Threat Intelligence")
                st.write(f"**Total URLs Found:** {url_data['total_urls']}")
                st.write(f"**Malicious Links:** {url_data['malicious_count']}")
                st.write(f"**Suspicious Links:** {url_data['suspicious_count']}")
                st.write(f"**Max Link Threat Score:** {url_data['max_threat_score']}/100")

            # URL Details Table
            if url_data["analyzed_urls"]:
                st.markdown("#### 🔍 Analyzed URLs Detail")
                for u in url_data["analyzed_urls"]:
                    with st.expander(f"{u['reputation']} | {u['url'][:70]}... (Score: {u['threatScore']}/100)"):
                        st.write(f"**Domain:** `{u['domain']}`")
                        st.write(f"**Reputation:** `{u['reputation']}`")
                        st.write(f"**Flags:** {', '.join(u['flags'])}")
                        if u.get("grok_analysis"):
                            st.info(
                                f"**Grok AI Verdict:** {u['grok_analysis']['verdict']} (Confidence: {int(u['grok_analysis']['confidence']*100)}%)\n\n"
                                f"**Reason:** {u['grok_analysis']['reason']}"
                            )

# ------------------------------------------------------------------------------
# TAB 2: Grok AI URL Scanner
# ------------------------------------------------------------------------------
with tab_url:
    st.subheader("Isolated URL Threat Scanner with Grok AI")

    demo_urls = [
        "https://google.com",
        "https://paypa1-security-update.com/login",
        "http://185.220.101.5/invoice.zip",
        "https://bit.ly/3xSampleShortener",
        "http://microsoft-verify-account.top/auth"
    ]

    selected_demo = st.selectbox("Or choose a pre-configured demo test case:", ["(Custom URL)"] + demo_urls)
    default_url_val = "" if selected_demo == "(Custom URL)" else selected_demo

    target_url = st.text_input("Enter URL to inspect:", value=default_url_val, placeholder="https://example.com/path")

    if st.button("🔎 Scan URL Threat Intelligence", type="primary"):
        if not target_url.strip():
            st.error("Please enter a valid URL to scan.")
        else:
            with st.spinner("Analyzing structural heuristics & querying Grok AI..."):
                start_t = time.time()
                result = url_analyzer.analyze_url(target_url.strip())
                elapsed = time.time() - start_t

            st.markdown("---")
            col_res1, col_res2, col_res3 = st.columns(3)
            with col_res1:
                st.metric("Threat Score", f"{result['threatScore']}/100")
            with col_res2:
                st.metric("Reputation", result["reputation"])
            with col_res3:
                st.metric("Scan Latency", f"{elapsed:.2f}s", "Cached" if result.get("cached") else "Live")

            grok = result.get("grok_analysis")
            if grok:
                st.markdown("### 🤖 Grok AI Intelligence Assessment")
                st.info(
                    f"**AI Classification:** {grok['verdict']} | **Confidence:** {int(grok['confidence']*100)}%\n\n"
                    f"**Technical Reasoning:** {grok['reason']}"
                )

            st.markdown("### 🚩 Detected Heuristic Indicators & Flags")
            for f in result.get("flags", []):
                st.markdown(f"- 🔸 {f}")

# ------------------------------------------------------------------------------
# TAB 3: Telemetry & Cache
# ------------------------------------------------------------------------------
with tab_telemetry:
    st.subheader("System Telemetry & Cache Management")

    cache = url_analyzer.cache
    st.write(f"**Database Path:** `{cache.db_path}`")
    st.write(f"**Cache TTL:** {cache.default_ttl} seconds")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🧹 Purge Expired Cache Entries"):
            count = cache.clear_expired()
            st.success(f"Purged {count} expired cache records.")
    with col_btn2:
        if st.button("🔄 Refresh Circuit Breaker"):
            grok_client.consecutive_failures = 0
            grok_client.state = "CLOSED"
            st.success("Circuit breaker reset to CLOSED.")
