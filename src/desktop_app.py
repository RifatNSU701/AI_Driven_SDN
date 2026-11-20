import os
import sys
import time
import shutil
import socket
import threading
import subprocess
import webbrowser
import urllib.request
import multiprocessing

# Redirect stdout/stderr for PyInstaller --windowed builds so Uvicorn never crashes
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".ai_sdn_cybersoc")
os.makedirs(APP_DATA_DIR, exist_ok=True)
DESKTOP_LOG = os.path.join(APP_DATA_DIR, "desktop.log")

if sys.stdout is None:
    sys.stdout = open(DESKTOP_LOG, "a", encoding="utf-8", buffering=1)
if sys.stderr is None:
    sys.stderr = open(DESKTOP_LOG, "a", encoding="utf-8", buffering=1)

# Resolve bundled PyInstaller onefile assets (models/ and src/web/)
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


def find_chromium_app_runtime() -> str | None:
    """Locates the OS native Chromium/Edge engine for standalone frameless desktop app windows."""
    candidates = []
    if sys.platform.startswith("win"):
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        local_app = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local_app, "Google", "Chrome", "Application", "chrome.exe"),
            shutil.which("msedge"),
            shutil.which("chrome"),
        ]
    elif sys.platform == "darwin":
        candidates = [
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    else:
        candidates = [
            shutil.which("microsoft-edge"),
            shutil.which("google-chrome"),
            shutil.which("chromium"),
            shutil.which("chromium-browser"),
        ]

    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def launch_standalone_app_window(url: str) -> bool:
    """Opens a dedicated app window (no address bar, no browser tabs) and exits cleanly on close."""
    runtime = find_chromium_app_runtime()
    if not runtime:
        return False

    profile_dir = os.path.join(APP_DATA_DIR, "app_profile")
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        runtime,
        f"--app={url}",
        f"--user-data-dir={profile_dir}",
        "--window-size=1480,920",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-sync",
        "--class=AI_SDN_CyberSOC",
    ]
    proc = subprocess.Popen(cmd)
    proc.wait()
    return True


def launch_desktop_suite():
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()
    wait_for_server()

    url = "http://127.0.0.1:8000"

    # 1. Try native pywebview if bundled
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
        os._exit(0)
    except Exception:
        pass

    # 2. Launch standalone native Chromium/Edge App Window (no tabs, no URL bar)
    if launch_standalone_app_window(url):
        os._exit(0)

    # 3. Last-resort fallback only if no local runtime exists
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        os._exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    launch_desktop_suite()