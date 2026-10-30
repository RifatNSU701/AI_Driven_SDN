import os
import sys
import time
import socket
import threading
import webbrowser
import urllib.request
import uvicorn

# Ensure bundled PyInstaller onefile assets (models/ and src/web/) are found
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    os.chdir(sys._MEIPASS)

from src.api_server import app


def is_port_in_use(port: int = 8000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_api_server():
    if not is_port_in_use(8000):
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")


def wait_for_server(url: str = "http://127.0.0.1:8000/health", timeout: float = 10.0):
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
        window = webview.create_window(
            title="AI-SDN Cyber-SOC v3.0 — Enterprise Threat Protection Suite",
            url=url,
            width=1480,
            height=920,
            min_size=(1100, 720),
            background_color="#050811",
        )
        webview.start()
    except Exception:
        print(f"[+] Cyber-SOC Portal active at {url}")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    launch_desktop_suite()