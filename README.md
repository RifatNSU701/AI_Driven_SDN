# AI-Powered Software-Defined Networking (SDN) Threat Protection System

**Prepared By:** Rifat Khan  
**Project Type:** Enterprise Multi-Platform Cybersecurity, SDN & Machine Learning Suite  
**Platforms:** Web Portal • Windows/Linux/macOS Desktop App • Android/iOS Flutter Mobile App  

---

## 1. Executive Summary
This system delivers an end-to-end, closed-loop threat protection architecture for Software-Defined Networking (SDN). It continuously collects OpenFlow 1.3 telemetry from Open vSwitch (OVS), extracts flow-level behavioural features, evaluates traffic across **5 Machine Learning & Anomaly Detection algorithms** with **Explainable AI (XAI)** reasoning, and dynamically enforces OpenFlow 1.3 quarantine (`priority=100, actions=drop`) and rate-limiting policies in real time.

## 2. Multi-Platform Architecture
- **Core Enforcement & ML Engine (`src/api_server.py`):** FastAPI server with JWT Role-Based Access Control (`Admin` / `Analyst`), SQLAlchemy database (`SQLite` / `PostgreSQL`), Explainable AI (XAI), and live OpenFlow policy orchestration.
- **Cyber-SOC Web Portal (`src/web/index.html`):** High-density dark-mode SOC portal featuring an interactive SDN & Multi-VM topology map, Guided Assistant, 1-click traffic simulator, live telemetry charts, and CSV report export.
- **Cross-Platform Desktop Suite (`src/desktop_app.py`):** Standalone desktop GUI application for Windows, Linux, and macOS.
- **Mobile SOC App (`mobile_app/`):** Flutter application for Android and iOS providing live threat telemetry, model switching, one-tap simulations, and remote host quarantine/unblocking.
- **3-VM Virtualized SDN Testbed (`scripts/`):**
  - `Ubuntu 22.04.5 LTS SDN-Core (10.10.10.1/24)` — Open vSwitch 2.17.12, Mininet 2.3.0, Ryu 4.34 Controller.
  - `Kali Linux (10.10.10.2/24)` — Authorized offensive security testing node.
  - `Linux Mint 22.3 (10.10.10.3/24)` — Legitimate enterprise client node.

## 3. Machine Learning & Anomaly Detection Models
All 5 detection models are trained (`src/train_models.py`), benchmarked, and live-selectable from the Web, Desktop, Streamlit, and Mobile interfaces:
1. **Ensemble Voting (All 5 Models Weighted)**
2. **Random Forest Classifier** (Precision: `1.0000`, Recall: `1.0000`, F1: `1.0000`, FPR: `0.0000`, Latency: `0.1111 ms`)
3. **Gradient Boosting Classifier**
4. **Lightweight Deep Neural Network (`MLPClassifier`)**
5. **Isolation Forest (Unsupervised)**
6. **Baseline Threshold Detector**

## 4. Verified Closed-Loop Benchmark Results
| Metric | Verified Result |
| :--- | :--- |
| **Normal & High-Volume (`iperf3`) False-Positive Rate** | `0.00%` (Zero disruption to benign bursts) |
| **Mean Detection-to-Enforcement Latency** | `121.90 ms` (End-to-End HTTP + OpenFlow 1.3 `add-flow`) |
| **Attacker (`10.0.0.3` / `10.10.10.2`) Post-Quarantine Loss** | `100% packet loss` (Isolated via `priority=100,actions=drop`) |
| **Benign Host (`10.0.0.2` / `10.10.10.3`) Traffic Loss** | `0% packet loss` (Zero collateral impact) |

## 5. Quick-Start Guide

### A. Train All 5 ML Models & Initialize Database
```powershell
.\venv\Scripts\python.exe -m src.auth
.\venv\Scripts\python.exe .\src\train_models.py