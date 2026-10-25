#!/usr/bin/env python3
"""
NetGuardian Runner Entrypoint
Launches the full integrated NetGuardian system:
- Passive Device Discovery
- Network Packet Capture
- Multi-vector Threat Detection & Behaviour Drift Engine
- Risk-Based Automated Quarantine
- Interactive Web Security Dashboard
"""

import os
import sys
import subprocess
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Auto-detect virtual environment: if user runs with global python without dependencies,
# seamlessly switch to the project's .venv interpreter
venv_python = BASE_DIR / ".venv" / "Scripts" / "python.exe"
if not venv_python.exists():
    venv_python = BASE_DIR / ".venv" / "bin" / "python"

if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
    try:
        import flask
        import requests, dotenv, reportlab
        import scapy
    except ImportError:
        print(f"[NetGuardian] Detected dependencies in virtual environment. Launching with: {venv_python}")
        proc = subprocess.run([str(venv_python), str(BASE_DIR / "run.py")] + sys.argv[1:])
        sys.exit(proc.returncode)

import config
from app import app, startup_initialization

BANNER = r"""
 _   _      _    _____                     _ _             
| \ | |    | |  / ____|                   | (_)            
|  \| | ___| |_| |  __ _   _  __ _ _ __ __| |_  __ _ _ __  
| . ` |/ _ \ __| | |_ | | | |/ _` | '__/ _` | |/ _` | '_ \ 
| |\  |  __/ |_| |__| | |_| | (_| | | | (_| | | (_| | | | |
|_| \_|\___|\__|\_____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|
============================================================
 Behavioural Fingerprinting & Automated Quarantine System
============================================================
"""


def main():
    print(BANNER)
    print(f"[*] Target Network Subnet: {config.TARGET_NETWORK}")
    print(f"[*] Database Path        : {config.DATABASE_PATH}")
    print(f"[*] Web Server Address   : http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print("=" * 60)

    # Initialize all subsystems and start background workers
    startup_initialization()

    # Start Flask Web Dashboard
    app.run(
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=False,
        use_reloader=False
    )


if __name__ == "__main__":
    main()
