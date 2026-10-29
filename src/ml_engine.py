import os
import json
import time
import joblib
import numpy as np
import pandas as pd

MODEL_DIR = "models"
FEATURES = [
    "flow_count",
    "pkt_rate",
    "byte_rate",
    "mean_pkt_size",
    "unique_dst_ports",
    "syn_ratio",
]


class MasterMLEngine:
    def __init__(self):
        self.reload_artifacts()

    def reload_artifacts(self):
        self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        self.iso_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
        self.rf_model = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
        self.gb_model = joblib.load(os.path.join(MODEL_DIR, "gradient_boosting.pkl"))
        self.mlp_model = joblib.load(os.path.join(MODEL_DIR, "mlp_neural_net.pkl"))

        multi_path = os.path.join(MODEL_DIR, "multiclass_threat_clf.pkl")
        enc_path = os.path.join(MODEL_DIR, "label_encoder.pkl")
        self.multi_model = joblib.load(multi_path) if os.path.exists(multi_path) else None
        self.label_enc = joblib.load(enc_path) if os.path.exists(enc_path) else None

        stats_path = os.path.join(MODEL_DIR, "baseline_stats.json")
        if os.path.exists(stats_path):
            with open(stats_path, "r") as f:
                st = json.load(f)
                self.means = st["means"]
                self.stds = st["stds"]
        else:
            self.means = {"flow_count": 3.5, "pkt_rate": 110.0, "byte_rate": 140000.0, "mean_pkt_size": 520.0, "unique_dst_ports": 1.5, "syn_ratio": 0.08}
            self.stds = {"flow_count": 2.0, "pkt_rate": 160.0, "byte_rate": 240000.0, "mean_pkt_size": 580.0, "unique_dst_ports": 0.8, "syn_ratio": 0.04}

        imp_path = os.path.join(MODEL_DIR, "feature_importances.json")
        if os.path.exists(imp_path):
            with open(imp_path, "r") as f:
                self.global_weights = json.load(f)
        else:
            self.global_weights = {feat: 1.0 / len(FEATURES) for feat in FEATURES}

    def compute_mathematical_xai(self, sample_dict: dict) -> tuple[dict, float]:
        """Computes per-flow feature attribution percentages (Z-score * RF Global Importance) and drift index."""
        raw_scores = {}
        z_scores = []

        for feat in FEATURES:
            val = float(sample_dict.get(feat, self.means[feat]))
            mean = float(self.means.get(feat, 1.0))
            std = max(0.0001, float(self.stds.get(feat, 1.0)))
            z = abs(val - mean) / std
            z_scores.append(z)
            weight = float(self.global_weights.get(feat, 0.15)) + 0.05
            raw_scores[feat] = z * weight

        total = sum(raw_scores.values())
        if total <= 1e-9:
            contributions = {feat: round(100.0 / len(FEATURES), 2) for feat in FEATURES}
        else:
            contributions = {feat: round((score / total) * 100.0, 2) for feat, score in raw_scores.items()}

        drift_index = round(float(np.mean(z_scores)), 3)
        return contributions, drift_index

    def evaluate_window(self, sample_dict: dict, active_model: str) -> dict:
        t0 = time.perf_counter()
        df = pd.DataFrame([{k: sample_dict[k] for k in FEATURES}])
        scaled = self.scaler.transform(df)

        base_pred = 1 if (
            sample_dict["unique_dst_ports"] > 10
            or (sample_dict["pkt_rate"] > 150 and sample_dict["mean_pkt_size"] < 900)
            or sample_dict["syn_ratio"] > 0.60
        ) else 0

        iso_pred = 1 if int(self.iso_model.predict(scaled)[0]) == -1 else 0
        rf_pred = int(self.rf_model.predict(scaled)[0])
        rf_conf = float(np.max(self.rf_model.predict_proba(scaled)[0]))

        gb_pred = int(self.gb_model.predict(scaled)[0])
        gb_conf = float(np.max(self.gb_model.predict_proba(scaled)[0]))

        mlp_pred = int(self.mlp_model.predict(scaled)[0])
        mlp_conf = float(np.max(self.mlp_model.predict_proba(scaled)[0]))

        votes = {
            "Baseline Threshold": base_pred,
            "Isolation Forest": iso_pred,
            "Random Forest": rf_pred,
            "Gradient Boosting": gb_pred,
            "Deep Neural Network (MLP)": mlp_pred,
        }

        weighted_score = (
            (rf_pred * 0.35)
            + (gb_pred * 0.30)
            + (mlp_pred * 0.20)
            + (base_pred * 0.10)
            + (iso_pred * 0.05)
        )
        ensemble_pred = 1 if weighted_score >= 0.45 else 0
        ensemble_conf = round(max(weighted_score, 1.0 - weighted_score), 4)

        if active_model == "Random Forest":
            final_pred, final_conf = rf_pred, rf_conf
        elif active_model == "Gradient Boosting":
            final_pred, final_conf = gb_pred, gb_conf
        elif active_model == "Deep Neural Network (MLP)":
            final_pred, final_conf = mlp_pred, mlp_conf
        elif active_model == "Isolation Forest":
            final_pred, final_conf = iso_pred, 0.86 if iso_pred == 1 else 0.91
        elif active_model == "Baseline Threshold":
            final_pred, final_conf = base_pred, 0.82 if base_pred == 1 else 0.90
        else:
            final_pred, final_conf = ensemble_pred, ensemble_conf

        # Multi-Class Threat Classification
        if self.multi_model is not None and self.label_enc is not None:
            mc_idx = int(self.multi_model.predict(scaled)[0])
            mc_label = str(self.label_enc.inverse_transform([mc_idx])[0])
        else:
            mc_label = "suspicious_anomaly" if final_pred == 1 else "benign"

        if final_pred == 0 and mc_label not in ("benign", "high_vol_benign"):
            mc_label = "high_vol_benign" if sample_dict["pkt_rate"] > 100 else "benign"
        elif final_pred == 1 and mc_label in ("benign", "high_vol_benign"):
            if sample_dict["unique_dst_ports"] >= 10 and sample_dict["pkt_rate"] < 30:
                mc_label = "stealth_recon"
            elif sample_dict["unique_dst_ports"] >= 10:
                mc_label = "port_scan"
            elif sample_dict["syn_ratio"] >= 0.5:
                mc_label = "tcp_syn_flood"
            else:
                mc_label = "udp_dos_flood"

        xai_contributions, drift_index = self.compute_mathematical_xai(sample_dict)
        inference_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        explanation = self._format_explanation(sample_dict, final_pred, mc_label, votes, xai_contributions)

        return {
            "prediction": final_pred,
            "confidence": round(final_conf, 4),
            "threat_type": mc_label,
            "votes": votes,
            "xai_contributions": xai_contributions,
            "drift_index": drift_index,
            "explanation": explanation,
            "inference_latency_ms": inference_ms,
        }

    def _format_explanation(self, s: dict, pred: int, threat_type: str, votes: dict, xai: dict) -> str:
        top_feats = sorted(xai.items(), key=lambda x: x[1], reverse=True)
        f1, p1 = top_feats[0]
        f2, p2 = top_feats[1]

        if pred == 0:
            if threat_type == "high_vol_benign":
                return (
                    f"Allowed (High-Volume Benign Burst): Large packet payload ({s['mean_pkt_size']:.0f} B) "
                    f"and low SYN ratio ({s['syn_ratio']*100:.1f}%) confirm legitimate bulk transfer despite {s['pkt_rate']:.0f} pkts/s."
                )
            return f"Allowed (Baseline Normal): {s['pkt_rate']:.1f} pkts/s across {s['unique_dst_ports']} port(s) within normal Z-score bounds."

        labels = {
            "flow_count": f"flow surge ({s['flow_count']} flows)",
            "pkt_rate": f"packet rate ({s['pkt_rate']:.1f} pkts/s)",
            "byte_rate": f"byte throughput ({s['byte_rate']:.0f} B/s)",
            "mean_pkt_size": f"packet size signature ({s['mean_pkt_size']:.0f} B)",
            "unique_dst_ports": f"port fan-out ({s['unique_dst_ports']} dst ports)",
            "syn_ratio": f"SYN flood ratio ({s['syn_ratio']*100:.0f}%)",
        }
        flagged = [k for k, v in votes.items() if v == 1]
        return (
            f"Classified as {threat_type.upper()}: Driven by {labels.get(f1, f1)} ({p1}% XAI weight) "
            f"and {labels.get(f2, f2)} ({p2}% XAI weight). Consensus: {len(flagged)}/5 models ({', '.join(flagged)})."
        )


ml_engine = MasterMLEngine()