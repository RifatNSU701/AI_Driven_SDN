import os
import numpy as np
import pandas as pd

DATA_DIR = "data"
DATA_PATH = os.path.join(DATA_DIR, "flow_telemetry.csv")


def generate_production_dataset(num_samples: int = 5000, random_seed: int = 42):
    np.random.seed(random_seed)
    os.makedirs(DATA_DIR, exist_ok=True)

    records = []

    # Traffic class distributions
    classes = [
        ("benign", 0.40, 0, {"flow_count": (1, 6), "pkt_rate": (2.0, 15.0), "byte_rate": (200, 1500), "mean_pkt_size": (80, 120), "unique_dst_ports": (1, 2), "syn_ratio": (0.05, 0.15)}),
        ("high_vol_benign", 0.20, 0, {"flow_count": (2, 8), "pkt_rate": (200.0, 650.0), "byte_rate": (250000, 950000), "mean_pkt_size": (1200, 1500), "unique_dst_ports": (1, 3), "syn_ratio": (0.01, 0.08)}),
        ("port_scan", 0.12, 1, {"flow_count": (30, 80), "pkt_rate": (30.0, 90.0), "byte_rate": (1800, 5500), "mean_pkt_size": (45, 65), "unique_dst_ports": (15, 60), "syn_ratio": (0.85, 0.99)}),
        ("stealth_recon", 0.08, 1, {"flow_count": (10, 30), "pkt_rate": (8.0, 22.0), "byte_rate": (600, 1800), "mean_pkt_size": (50, 70), "unique_dst_ports": (12, 35), "syn_ratio": (0.70, 0.90)}),
        ("tcp_syn_flood", 0.12, 1, {"flow_count": (25, 70), "pkt_rate": (200.0, 500.0), "byte_rate": (8000, 25000), "mean_pkt_size": (40, 52), "unique_dst_ports": (1, 2), "syn_ratio": (0.95, 1.00)}),
        ("udp_dos_flood", 0.08, 1, {"flow_count": (20, 60), "pkt_rate": (250.0, 600.0), "byte_rate": (300000, 900000), "mean_pkt_size": (1000, 1450), "unique_dst_ports": (1, 2), "syn_ratio": (0.0, 0.10)}),
    ]

    samples_per_class = [int(num_samples * proportion) for _, proportion, _, _ in classes]

    for (class_name, _, label_val, ranges), count in zip(classes, samples_per_class):
        for _ in range(count):
            fc = np.random.randint(ranges["flow_count"][0], ranges["flow_count"][1] + 1)
            pr = np.random.uniform(ranges["pkt_rate"][0], ranges["pkt_rate"][1])
            br = np.random.uniform(ranges["byte_rate"][0], ranges["byte_rate"][1])
            mps = np.random.uniform(ranges["mean_pkt_size"][0], ranges["mean_pkt_size"][1])
            udp = np.random.randint(ranges["unique_dst_ports"][0], ranges["unique_dst_ports"][1] + 1)
            sr = np.random.uniform(ranges["syn_ratio"][0], ranges["syn_ratio"][1])

            # Add minor Gaussian noise for realistic variance
            pr = max(1.0, pr + np.random.normal(0, 1.5))
            br = max(100.0, br + np.random.normal(0, 50.0))
            sr = np.clip(sr + np.random.normal(0, 0.02), 0.0, 1.0)

            records.append({
                "flow_count": fc,
                "pkt_rate": round(pr, 2),
                "byte_rate": round(br, 2),
                "mean_pkt_size": round(mps, 2),
                "unique_dst_ports": udp,
                "syn_ratio": round(sr, 4),
                "attack_type": class_name,
                "label": label_val,
            })

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    df.to_csv(DATA_PATH, index=False)
    print(f"[+] Generated production-grade SDN telemetry dataset: {len(df)} rows saved to {DATA_PATH}")
    print(df["attack_type"].value_counts())


if __name__ == "__main__":
    generate_production_dataset()