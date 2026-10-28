import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest,
    GradientBoostingClassifier,
)
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

DATA_PATH = os.path.join("data", "flow_telemetry.csv")
MODEL_DIR = "models"

FEATURES = [
    "flow_count",
    "pkt_rate",
    "byte_rate",
    "mean_pkt_size",
    "unique_dst_ports",
    "syn_ratio",
]


def baseline_rule_detector(X_df):
    """Static rule-based threshold reference detector."""
    preds = []
    for _, row in X_df.iterrows():
        if row["unique_dst_ports"] > 10 or row["pkt_rate"] > 150 or row["syn_ratio"] > 0.6:
            preds.append(1)
        else:
            preds.append(0)
    return np.array(preds)


def evaluate_predictions(name, y_true, y_pred, latency_ms):
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / max(1, (fp + tn))

    return {
        "model": name,
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "latency_ms_per_sample": round(float(latency_ms), 4),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    print(f"[*] Loaded dataset: {len(df)} rows | Class distribution:\n{df['attack_type'].value_counts()}\n")

    X = df[FEATURES]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = []

    # 1. Baseline Threshold Detector
    t0 = time.perf_counter()
    y_pred_base = baseline_rule_detector(X_test)
    base_lat = ((time.perf_counter() - t0) * 1000.0) / len(X_test)
    results.append(evaluate_predictions("Baseline Threshold", y_test, y_pred_base, base_lat))

    # 2. Unsupervised Isolation Forest
    contamination = max(0.05, min(0.45, float(y_train.mean())))
    iso = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    iso.fit(X_train_scaled)

    t0 = time.perf_counter()
    iso_raw = iso.predict(X_test_scaled)
    iso_lat = ((time.perf_counter() - t0) * 1000.0) / len(X_test)
    y_pred_iso = np.where(iso_raw == -1, 1, 0)
    results.append(evaluate_predictions("Isolation Forest", y_test, y_pred_iso, iso_lat))

    # 3. Supervised Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    rf.fit(X_train_scaled, y_train)

    t0 = time.perf_counter()
    y_pred_rf = rf.predict(X_test_scaled)
    rf_lat = ((time.perf_counter() - t0) * 1000.0) / len(X_test)
    results.append(evaluate_predictions("Random Forest", y_test, y_pred_rf, rf_lat))

    # 4. Supervised Gradient Boosting Ensemble
    gb = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)
    gb.fit(X_train_scaled, y_train)

    t0 = time.perf_counter()
    y_pred_gb = gb.predict(X_test_scaled)
    gb_lat = ((time.perf_counter() - t0) * 1000.0) / len(X_test)
    results.append(evaluate_predictions("Gradient Boosting", y_test, y_pred_gb, gb_lat))

    # 5. Lightweight Deep Neural Network (MLPClassifier)
    mlp = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=500, random_state=42)
    mlp.fit(X_train_scaled, y_train)

    t0 = time.perf_counter()
    y_pred_mlp = mlp.predict(X_test_scaled)
    mlp_lat = ((time.perf_counter() - t0) * 1000.0) / len(X_test)
    results.append(evaluate_predictions("Deep Neural Network (MLP)", y_test, y_pred_mlp, mlp_lat))

    # Print comparison table
    results_df = pd.DataFrame(results)
    print("=== 5-Model Anomaly Detection Benchmark Summary ===")
    print(
        results_df[
            [
                "model",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
                "latency_ms_per_sample",
            ]
        ].to_string(index=False)
    )

    # Extract Explainable AI (XAI) global feature importances from Random Forest
    feature_importances = {
        feat: round(float(imp), 4)
        for feat, imp in zip(FEATURES, rf.feature_importances_)
    }
    print("\n=== Explainable AI (XAI) Feature Importance ===")
    for feat, imp in sorted(feature_importances.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {feat:<18}: {imp:.4f}")

    # Save all trained model artifacts
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))
    joblib.dump(gb, os.path.join(MODEL_DIR, "gradient_boosting.pkl"))
    joblib.dump(mlp, os.path.join(MODEL_DIR, "mlp_neural_net.pkl"))

    with open(os.path.join(MODEL_DIR, "feature_importances.json"), "w") as f:
        json.dump(feature_importances, f, indent=2)

    metrics_path = os.path.join(MODEL_DIR, "evaluation_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Saved all 5 trained models, XAI importances, and {metrics_path} successfully.")


if __name__ == "__main__":
    main()