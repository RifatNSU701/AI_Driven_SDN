import os
import sys
import shutil
import subprocess

HIDDEN_IMPORTS = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "src.api_server",
    "src.database",
    "src.auth",
    "src.ml_engine",
    "src.pcap_ingest",
    "src.observability",
    "src.robustness_suite",
    "sklearn.ensemble",
    "sklearn.neural_network",
    "sklearn.preprocessing",
    "sklearn.tree",
    "jwt",
    "bcrypt",
]


def build_production_packages():
    sep = ";" if sys.platform.startswith("win") else ":"
    platform_tag = (
        "windows_x64"
        if sys.platform.startswith("win")
        else ("macos_universal" if sys.platform == "darwin" else "linux_x64")
    )

    os.makedirs("dist", exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "AI_SDN_CyberSOC",
        f"--add-data=src/web{sep}src/web",
        f"--add-data=models{sep}models",
    ]
    for mod in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", mod])
    cmd.append("src/desktop_app.py")

    print(f"[*] Building production standalone executable for {platform_tag}...")
    subprocess.run(cmd, check=True)

    if sys.platform.startswith("win"):
        exe_src = os.path.join("dist", "AI_SDN_CyberSOC.exe")
        zip_path = shutil.make_archive(
            os.path.join("dist", "AI_SDN_CyberSOC_Windows_x64"),
            "zip",
            "dist",
            "AI_SDN_CyberSOC.exe",
        )
        print(f"[+] Windows Native Executable : {exe_src}")
        print(f"[+] Windows Release Archive   : {zip_path}")
    elif sys.platform == "darwin":
        bin_src = os.path.join("dist", "AI_SDN_CyberSOC")
        dmg_path = os.path.join("dist", "AI_SDN_CyberSOC_macOS.dmg")
        try:
            subprocess.run(
                [
                    "hdiutil",
                    "create",
                    "-volname",
                    "AI_SDN_CyberSOC",
                    "-srcfolder",
                    bin_src,
                    "-ov",
                    "-format",
                    "UDZO",
                    dmg_path,
                ],
                check=True,
            )
            print(f"[+] macOS Disk Image (.dmg)   : {dmg_path}")
        except Exception:
            shutil.make_archive(os.path.join("dist", "AI_SDN_CyberSOC_macOS"), "zip", "dist")
    else:
        bin_src = os.path.join("dist", "AI_SDN_CyberSOC")
        bin_dst = os.path.join("dist", "AI_SDN_CyberSOC_Linux_x64.bin")
        if os.path.exists(bin_src):
            shutil.copy2(bin_src, bin_dst)
            os.chmod(bin_dst, 0o755)
            print(f"[+] Linux Standalone Binary   : {bin_dst}")


if __name__ == "__main__":
    build_production_packages()