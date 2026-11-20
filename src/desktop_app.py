import os
import sys
import time
import socket
import threading
import webbrowser
import urllib.request
import multiprocessing

# Production fix: PyInstaller --windowed sets sys.stdout/sys.stderr to None on Windows,
# which crashes Uvicorn's default logger unless redirected to a persistent log file.
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".ai_sdn_cybersoc")
os.makedirs(APP_DATA_DIR, exist_ok=True)
DESKTOP_LOG = os.path.join(APP_DATA_DIR, "desktop.log")

if sys.stdout is None:
    sys.stdout = open(DESKTOP_LOG, "a", encoding="utf-8", buffering=1)
if sys.stderr is None:
    sys.stderr = open(DESKTOP_LOG, "a", encoding="utf-8", buffering=1)

# Ensure bundled PyInstaller onefile assets (models/ and src/web/) are found
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    os.chdir(sys._MEIPASS)

import uvicorn
from src.api_server import app


def is_port_in_use(port: int = 8000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_api_server():
    if not is_port_in_use(8000):
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_config=None,
            access_log=False,
        )


def wait_for_server(url: str = "http://127.0.0.1:8000/health", timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def launch_desktop_suite():
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()
    wait_for_server()

    url = "http://127.0.0.1:8000"
    try:
        import webview

        webview.create_window(
            title="AI-SDN Cyber-SOC v3.1 — Enterprise Threat Protection Suite",
            url=url,
            width=1480,
            height=920,
            min_size=(1100, 720),
            background_color="#050811",
        )
        webview.start()
    except Exception:
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    multiprocessing.freeze_support()
    launch_desktop_suite()