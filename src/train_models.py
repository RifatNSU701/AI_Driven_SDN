import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

DATA_PATH = os.path.join("data", "flow_telemetry.csv")
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURES = [
    "flow_count",
    "pkt_rate",
    "byte_rate",
    "mean_pkt_size",
    "unique_dst_ports",
    "syn_ratio",
]


def baseline_threshold_predict(df: pd.DataFrame) -> np.ndarray:
    cond = (
        (df["unique_dst_ports"] > 10)
        | (df["pkt_rate"] > 150 and df["mean_pkt_size"] < 200)
        | (df["syn_ratio"] > 0.60)
    )
    return cond.astype(int).values


def evaluate_predictions(name: str, y_true: np.ndarray, y_pred: np.ndarray, elapsed_sec: float, n_samples: int) -> dict:
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    latency_ms = (elapsed_sec / max(1, n_samples)) * 1000.0
    return {
        "model": name,
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "latency_ms_per_sample": round(float(latency_ms), 4),
    }


def main():
    df = pd.read_csv(DATA_PATH)
    print(f"[*] Loaded dataset: {len(df)} rows | Class distribution:")
    print(df["attack_type"].value_counts())

    X = df[FEATURES]
    y_bin = df["label"].values

    label_enc = LabelEncoder()
    y_multi = label_enc.fit_transform(df["attack_type"].values)

    X_train, X_test, y_train, y_test, ym_train, ym_test = train_test_split(
        X, y_bin, y_multi, test_size=0.25, random_state=42, stratify=y_multi
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Population baseline statistics for mathematical Z-score XAI attribution
    benign_df = df[df["label"] == 0][FEATURES]
    baseline_stats = {
        "means": benign_df.mean().round(4).to_dict(),
        "stds": benign_df.std().replace(0, 1.0).round(4).to_dict(),
    }
    with open(os.path.join(MODEL_DIR, "baseline_stats.json"), "w") as f:
        json.dump(baseline_stats, f, indent=2)

    results = []

    # 1. Baseline Threshold
    t0 = time.perf_counter()
    base_preds = np.where(
        (X_test["unique_dst_ports"] > 10)
        | ((X_test["pkt_rate"] > 150) & (X_test["mean_pkt_size"] < 900))
        | (X_test["syn_ratio"] > 0.60),
        1,
        0,
    )
    t_base = time.perf_counter() - t0
    results.append(evaluate_predictions("Baseline Threshold", y_test, base_preds, t_base, len(X_test)))

    # 2. Isolation Forest
    iso = IsolationForest(n_estimators=150, contamination=0.38, random_state=42, n_jobs=-1)
    iso.fit(X_train_scaled)
    t0 = time.perf_counter()
    iso_raw = iso.predict(X_test_scaled)
    t_iso = time.perf_counter() - t0
    iso_preds = np.where(iso_raw == -1, 1, 0)
    results.append(evaluate_predictions("Isolation Forest", y_test, iso_preds, t_iso, len(X_test)))

    # 3. Random Forest (Binary Anomaly Detector)
    rf = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    t0 = time.perf_counter()
    rf_preds = rf.predict(X_test_scaled)
    t_rf = time.perf_counter() - t0
    results.append(evaluate_predictions("Random Forest", y_test, rf_preds, t_rf, len(X_test)))

    # 4. Gradient Boosting
    gb = GradientBoostingClassifier(n_estimators=120, learning_rate=0.1, max_depth=5, random_state=42)
    gb.fit(X_train_scaled, y_train)
    t0 = time.perf_counter()
    gb_preds = gb.predict(X_test_scaled)
    t_gb = time.perf_counter() - t0
    results.append(evaluate_predictions("Gradient Boosting", y_test, gb_preds, t_gb, len(X_test)))

    # 5. Deep Neural Network (MLPClassifier)
    mlp = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42)
    mlp.fit(X_train_scaled, y_train)
    t0 = time.perf_counter()
    mlp_preds = mlp.predict(X_test_scaled)
    t_mlp = time.perf_counter() - t0
    results.append(evaluate_predictions("Deep Neural Network (MLP)", y_test, mlp_preds, t_mlp, len(X_test)))

    # 6. Master Multi-Class Threat Classifier (6-Class Taxonomy)
    multi_clf = RandomForestClassifier(n_estimators=180, max_depth=14, random_state=42, n_jobs=-1)
    multi_clf.fit(X_train_scaled, ym_train)
    multi_acc = float(np.mean(multi_clf.predict(X_test_scaled) == ym_test))

    # Save all models and artifacts
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))
    joblib.dump(gb, os.path.join(MODEL_DIR, "gradient_boosting.pkl"))
    joblib.dump(mlp, os.path.join(MODEL_DIR, "mlp_neural_net.pkl"))
    joblib.dump(multi_clf, os.path.join(MODEL_DIR, "multiclass_threat_clf.pkl"))
    joblib.dump(label_enc, os.path.join(MODEL_DIR, "label_encoder.pkl"))

    importances = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: x[1], reverse=True)
    }
    with open(os.path.join(MODEL_DIR, "feature_importances.json"), "w") as f:
        json.dump(importances, f, indent=2)

    with open(os.path.join(MODEL_DIR, "evaluation_metrics.json"), "w") as f:
        json.dump(results, f, indent=2)

    print("\n=== 5-Model Anomaly Detection Benchmark Summary ===")
    print(pd.DataFrame(results).to_string(index=False))
    print(f"\n[+] 6-Class Threat Taxonomy Classifier Accuracy: {multi_acc * 100:.2f}%")
    print("[+] Saved all 6 models, label encoder, baseline Z-stats, and XAI importances.")


if __name__ == "__main__":
    main()