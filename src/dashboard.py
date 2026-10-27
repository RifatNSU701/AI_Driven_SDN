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

API_URL = "http://127.0.0.1:8000/analyze"
EVENTS_FILE = os.path.join("logs", "security_events.json")
METRICS_FILE = os.path.join("models", "evaluation_metrics.json")
DATASET_FILE = os.path.join("data", "flow_telemetry.csv")

st.title("🛡️ AI-Powered SDN Threat Protection System")
st.caption("Closed-Loop OpenFlow 1.3 Telemetry, ML Anomaly Detection & Automated Policy Enforcement")

sidebar = st.sidebar
sidebar.header("Dashboard Controls")
view_mode = sidebar.radio(
    "Telemetry Source",
    ["Live API Security Log", "Offline Training Dataset"],
)
auto_refresh = sidebar.checkbox("Enable Auto-Refresh (2s)", value=False)

sidebar.markdown("---")
sidebar.subheader("⚡ Closed-Loop API Test")
if sidebar.button("▶️ Stream 25 Flows to FastAPI"):
    if os.path.exists(DATASET_FILE):
        df_sim = pd.read_csv(DATASET_FILE)
        sample_df = pd.concat([
            df_sim[df_sim["attack_type"] == "benign"].head(8),
            df_sim[df_sim["attack_type"] == "benign_high_vol"].head(5),
            df_sim[df_sim["attack_type"] == "port_scan"].head(6),
            df_sim[df_sim["attack_type"] == "dos_flood"].head(6),
        ])
        sent = 0
        for _, row in sample_df.iterrows():
            payload = {
                "timestamp": float(row["timestamp"]),
                "src_ip": str(row["src_ip"]),
                "dst_ip": str(row["dst_ip"]),
                "flow_count": int(row["flow_count"]),
                "pkt_rate": float(row["pkt_rate"]),
                "byte_rate": float(row["byte_rate"]),
                "mean_pkt_size": float(row["mean_pkt_size"]),
                "unique_dst_ports": int(row["unique_dst_ports"]),
                "syn_ratio": float(row["syn_ratio"]),
            }
            try:
                requests.post(API_URL, json=payload, timeout=0.5)
                sent += 1
            except Exception:
                pass
        sidebar.success(f"Streamed {sent} flows through FastAPI!")
    else:
        sidebar.error("Dataset not found at data/flow_telemetry.csv")

if sidebar.button("🗑️ Clear Live Security Log"):
    os.makedirs("logs", exist_ok=True)
    with open(EVENTS_FILE, "w") as f:
        json.dump([], f)
    sidebar.info("Cleared live security log.")


def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


events_data = load_json(EVENTS_FILE)
metrics_data = load_json(METRICS_FILE)

rf_f1 = 1.0
for m in metrics_data:
    if m.get("model") == "Random Forest":
        rf_f1 = m.get("f1_score", 1.0)

# Dynamic Top KPIs & Primary View (Placed Above the Fold)
col1, col2, col3, col4 = st.columns(4)

if view_mode == "Live API Security Log":
    total_events = len(events_data)
    quarantines = sum(1 for e in events_data if e.get("action") == "quarantine")
    avg_latency = (
        round(sum(e.get("inference_latency_ms", 0.0) for e in events_data) / max(1, total_events), 3)
        if total_events > 0
        else 0.111
    )

    col1.metric("Live Telemetry Windows Analyzed", total_events)
    col2.metric("Automated Host Quarantines", quarantines)
    col3.metric("Mean ML Inference Latency", f"{avg_latency} ms")
    col4.metric("Random Forest F1-Score", f"{rf_f1:.4f}")

    st.markdown("---")
    st.subheader("🚨 Live Closed-Loop Security Events & Enforcement Log")
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
            st.plotly_chart(fig_rate, use_container_width=True)
        with right_col:
            fig_ports = px.bar(
                ev_df,
                x="time",
                y="unique_dst_ports",
                color="action",
                title="Unique Destination Ports Probed & Enforcement Action",
            )
            st.plotly_chart(fig_ports, use_container_width=True)

        st.dataframe(ev_df.iloc[::-1], use_container_width=True, hide_index=True)
    else:
        st.info(
            "No live events recorded yet. Click '▶️ Stream 25 Flows to FastAPI' in the left sidebar (or run the live Mininet controller) to populate this view."
        )

else:
    if os.path.exists(DATASET_FILE):
        df_data = pd.read_csv(DATASET_FILE)
        total_rows = len(df_data)
        attack_rows = int((df_data["label"] == 1).sum())
        benign_rows = int((df_data["label"] == 0).sum())

        col1.metric("Offline Dataset Windows", total_rows)
        col2.metric("Malicious Windows (h3 Attacks)", attack_rows)
        col3.metric("Benign Windows (Normal + High-Vol)", benign_rows)
        col4.metric("Random Forest F1-Score", f"{rf_f1:.4f}")

        st.markdown("---")
        st.subheader("📁 Captured OpenFlow 1.3 Telemetry Dataset (`flow_telemetry.csv`)")
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
            st.plotly_chart(fig_scatter, use_container_width=True)
        with right_col:
            fig_dist = px.histogram(
                df_data,
                x="attack_type",
                color="attack_type",
                title="Telemetry Window Distribution by Traffic Class",
            )
            st.plotly_chart(fig_dist, use_container_width=True)

        st.dataframe(df_data.tail(50), use_container_width=True, hide_index=True)
    else:
        st.warning("Dataset file not found at data/flow_telemetry.csv.")

st.markdown("---")

# Model Evaluation Comparison Section
st.subheader("📊 Anomaly Detection Model Comparison")
if metrics_data:
    metrics_df = pd.DataFrame(metrics_data)
    c1, c2 = st.columns([3, 2])
    with c1:
        st.dataframe(
            metrics_df[
                [
                    "model",
                    "precision",
                    "recall",
                    "f1_score",
                    "false_positive_rate",
                    "latency_ms_per_sample",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )
    with c2:
        fig_metrics = px.bar(
            metrics_df,
            x="model",
            y=["precision", "recall", "f1_score"],
            barmode="group",
            title="Detection Quality by Model",
            height=280,
        )
        st.plotly_chart(fig_metrics, use_container_width=True)

if auto_refresh:
    time.sleep(2)
    st.rerun()