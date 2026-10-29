import os
import sys
import subprocess


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def main():
    py = sys.executable
    while True:
        print("\n====================================================================")
        print("   AI-POWERED SDN THREAT PROTECTION — MASTER PRODUCTION LAUNCHER    ")
        print("====================================================================")
        print("  [1] Launch Cyber-SOC Web Portal & Desktop GUI (Port 8000)")
        print("  [2] Launch Streamlit Analytical Dashboard (Port 8501)")
        print("  [3] Train / Re-Verify All 5 ML Anomaly Detection Models")
        print("  [4] Run Phase 5 & 6 Robustness, Evasion & 1,000-Flow Scale Suite")
        print("  [5] Run Automated 7-Subsystem Production Verification Suite")
        print("  [6] Build Standalone Desktop Executable (.exe / Binary)")
        print("  [0] Exit")
        print("====================================================================")

        choice = input("Select an option [0-6]: ").strip()

        if choice == "1":
            subprocess.run([py, "-m", "src.desktop_app"])
        elif choice == "2":
            subprocess.run([py, "-m", "streamlit", "run", "src/dashboard.py"])
        elif choice == "3":
            subprocess.run([py, "-m", "src.auth"])
            subprocess.run([py, "src/train_models.py"])
        elif choice == "4":
            subprocess.run([py, "src/robustness_suite.py"])
        elif choice == "5":
            subprocess.run([py, "tests/test_production_suite.py"])
        elif choice == "6":
            subprocess.run([py, "scripts/build_desktop.py"])
        elif choice == "0":
            print("[*] Exiting Master Launcher.")
            break
        else:
            print("[!] Invalid selection. Choose 0-6.")


if __name__ == "__main__":
    main()