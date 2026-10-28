import os
import sys
import time
import socket
import threading
import subprocess
import webbrowser
import uvicorn
from src.api_server import app

HOST = "127.0.0.1"
PORT = 8000
APP_URL = f"http://{HOST}:{PORT}"


def is_port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def start_backend():
    if not is_port_in_use(HOST, PORT):
        uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")


def launch_desktop_gui():
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()

    for _ in range(30):
        if is_port_in_use(HOST, PORT):
            break
        time.sleep(0.2)

    # 1. Try native PyWebView window (Windows / Linux / macOS)
    try:
        import webview
        webview.create_window(
            title="AI-Powered SDN Threat Protection — Cyber-SOC Desktop Suite",
            url=APP_URL,
            width=1440,
            height=860,
            min_size=(1024, 680),
        )
        webview.start()
        return
    except ImportError:
        pass

    # 2. Fallback: Native frameless Desktop App Window via Edge/Chrome (--app mode)
    if sys.platform.startswith("win"):
        for browser_cmd in [
            ["cmd", "/c", "start", "msedge", f"--app={APP_URL}"],
            ["cmd", "/c", "start", "chrome", f"--app={APP_URL}"],
        ]:
            try:
                subprocess.run(browser_cmd, check=True)
                print(f"[+] Launched Desktop GUI Window at {APP_URL} (Press Ctrl+C to exit)")
                while True:
                    time.sleep(1)
            except Exception:
                continue

    webbrowser.open(APP_URL)
    print(f"[+] Cyber-SOC Portal running at {APP_URL} (Press Ctrl+C to exit)")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    launch_desktop_gui()