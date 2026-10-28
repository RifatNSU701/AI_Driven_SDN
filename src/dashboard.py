import os
import json
import time
import requests
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="AI-Powered SDN Threat Protection Dashboard",
    layout="wide",
)

API_BASE = "http://127.0.0.1:8000"
EVENTS_FILE = os.path.join("logs", "security_events.json")
METRICS_FILE = os.path.join("models", "evaluation_metrics.json")
IMPORTANCE_FILE = os.path.join("models", "feature_importances.json")
DATASET_FILE = os.path.join("data", "flow_telemetry.csv")


def load_json(path, default_val):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default_val
    return default_val


st.title("🛡️ AI-Powered SDN Threat Protection System")
st.caption("Multi-Algorithm Closed-Loop OpenFlow 1.3 Telemetry, Explainable AI (XAI) & Automated Policy Enforcement")

sidebar = st.sidebar
sidebar.header("⚙️ SOC Control Center")

models_list = [
    "Ensemble Voting (All 5 Models)",
    "Random Forest",
    "Gradient Boosting",
    "Deep Neural Network (MLP)",
    "Isolation Forest",
    "Baseline Threshold",
]
selected_model = sidebar.selectbox("Active Detection Algorithm", models_list)
if sidebar.button("Apply Detection Model", use_container_width=True):
    try:
        requests.post(f"{API_BASE}/api/models/select", json={"model_name": selected_model}, timeout=1.5)
        st.sidebar.success(f"Active: {selected_model}")
    except Exception:
        st.sidebar.warning("Start FastAPI server to switch live models.")

sidebar.markdown("---")
sidebar.subheader("⚡ Interactive Traffic Simulator")
sim_col1, sim_col2 = sidebar.columns(2)
if sim_col1.button("🟢 Benign Flow", use_container_width=True):
    requests.post(f"{API_BASE}/api/simulate", json={"scenario": "benign"}, timeout=1.5)
if sim_col2.button("🔵 iperf3 Burst", use_container_width=True):
    requests.post(f"{API_BASE}/api/simulate", json={"scenario": "high_vol"}, timeout=1.5)
if sim_col1.button("🟠 Port Scan (h3)", use_container_width=True):
    requests.post(f"{API_BASE}/api/simulate", json={"scenario": "port_scan"}, timeout=1.5)
if sim_col2.button("🔴 SYN Flood (h3)", use_container_width=True):
    requests.post(f"{API_BASE}/api/simulate", json={"scenario": "syn_flood"}, timeout=1.5)
if sidebar.button("🐉 Simulate Kali VM Attack (10.10.10.2)", use_container_width=True):
    requests.post(f"{API_BASE}/api/simulate", json={"scenario": "kali_attack"}, timeout=1.5)
if sidebar.button("🗑️ Clear Live Security Log", use_container_width=True):
    requests.delete(f"{API_BASE}/api/events/clear", timeout=1.5)

sidebar.markdown("---")
view_mode = sidebar.radio("Telemetry Source", ["Live API Security Log", "Offline Training Dataset"])
auto_refresh = sidebar.checkbox("Enable Auto-Refresh (2s)", value=False)

events_data = load_json(EVENTS_FILE, [])
metrics_data = load_json(METRICS_FILE, [])
importance_data = load_json(IMPORTANCE_FILE, {})

col1, col2, col3, col4 = st.columns(4)
total_events = len(events_data)
quarantines = sum(1 for e in events_data if e.get("action") == "quarantine")
avg_latency = (
    round(sum(e.get("inference_latency_ms", 0.0) for e in events_data) / max(1, total_events), 3)
    if total_events > 0
    else 0.111
)

col1.metric("Live Telemetry Windows", total_events)
col2.metric("Automated Host Quarantines", quarantines)
col3.metric("Mean ML Inference Latency", f"{avg_latency} ms")
col4.metric("Active Engine", selected_model.split(" ")[0])

st.markdown("---")

st.subheader("📊 5-Algorithm Anomaly Detection Benchmark & Explainable AI (XAI)")
if metrics_data:
    metrics_df = pd.DataFrame(metrics_data)
    c1, c2, c3 = st.columns([2.2, 1.5, 1.3])
    with c1:
        st.dataframe(
            metrics_df[["model", "precision", "recall", "f1_score", "false_positive_rate", "latency_ms_per_sample"]],
            use_container_width=True,
            hide_index=True,
        )
    with c2:
        fig_metrics = px.bar(
            metrics_df,
            x="model",
            y=["precision", "recall", "f1_score"],
            barmode="group",
            title="5-Model Detection Quality",
            height=260,
        )
        st.plotly_chart(fig_metrics, use_container_width=True, key="metrics_bar_chart")
    with c3:
        if importance_data:
            imp_df = pd.DataFrame(
                [{"feature": k, "importance": v} for k, v in importance_data.items()]
            ).sort_values("importance", ascending=True)
            fig_imp = px.bar(
                imp_df,
                x="importance",
                y="feature",
                orientation="h",
                title="XAI Feature Importance",
                height=260,
            )
            st.plotly_chart(fig_imp, use_container_width=True, key="xai_imp_chart")

st.markdown("---")

if view_mode == "Live API Security Log":
    st.subheader("🚨 Live Closed-Loop Security Events & Explainable AI Log")
    if events_data:
        ev_df = pd.DataFrame(events_data)
        left_col, right_col = st.columns(2)
        with left_col:
            fig_rate = px.line(
                ev_df,
                x="time",
                y="pkt_rate",
                color="src_ip",
                markers=True,
                title="Live Packet Rate (pkts/s) by Source IP",
            )
            st.plotly_chart(fig_rate, use_container_width=True, key="live_rate_chart")
        with right_col:
            fig_ports = px.bar(
                ev_df,
                x="time",
                y="unique_dst_ports",
                color="action",
                title="Unique Destination Ports Probed & Enforcement Action",
            )
            st.plotly_chart(fig_ports, use_container_width=True, key="live_ports_chart")

        display_cols = [
            c for c in [
                "time", "src_ip", "dst_ip", "pkt_rate", "unique_dst_ports",
                "syn_ratio", "active_model", "threat_type", "action",
                "rf_confidence", "inference_latency_ms", "explanation"
            ] if c in ev_df.columns
        ]
        st.dataframe(ev_df[display_cols].iloc[::-1], use_container_width=True, hide_index=True)
    else:
        st.info("No live events recorded yet. Use the 'Interactive Traffic Simulator' buttons in the left sidebar to test all 5 models live.")
else:
    st.subheader("📁 Captured OpenFlow 1.3 Telemetry Dataset (`flow_telemetry.csv`)")
    if os.path.exists(DATASET_FILE):
        df_data = pd.read_csv(DATASET_FILE)
        left_col, right_col = st.columns(2)
        with left_col:
            fig_scatter = px.scatter(
                df_data,
                x="pkt_rate",
                y="byte_rate",
                color="attack_type",
                size="flow_count",
                title="Packet Rate vs. Byte Rate Across Traffic Classes",
            )
            st.plotly_chart(fig_scatter, use_container_width=True, key="dataset_scatter")
        with right_col:
            fig_dist = px.histogram(
                df_data,
                x="attack_type",
                color="attack_type",
                title="Telemetry Window Distribution by Traffic Class",
            )
            st.plotly_chart(fig_dist, use_container_width=True, key="dataset_hist")
        st.dataframe(df_data.tail(50), use_container_width=True, hide_index=True)

if auto_refresh:
    time.sleep(2)
    st.rerun()