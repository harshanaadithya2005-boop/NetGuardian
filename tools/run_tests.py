"""Run unittest coverage and vetted legacy scripts against temporary databases.

Usage: .venv/Scripts/python.exe tools/run_tests.py
Hardware/router/production-data diagnostic scripts are intentionally excluded.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LEGACY = [
    "alert_api_integration", "baseline_history", "baseline_history_v2",
    "behaviour_history_pipeline", "behaviour_shadow", "behaviour_windows",
    "capture_health_integration", "capture_heartbeat", "capture_sessions_v2",
    "collection_schedule", "complete_heartbeat_pipeline", "continuity_eligibility",
    "detection_alert_pipeline", "device_ip_conflict", "eligibility_collector",
    "first_discovery_alert", "heartbeat_bridge", "heartbeat_error_priority",
    "heartbeat_reporter", "heartbeat_restart_safety", "identity_guard",
    "learned_baseline_sensitivity", "missed_windows", "risk_device_filter",
    "risk_integration", "safe_history_collector", "scheduled_history",
    "threat_detectors", "updated_dns_anomaly", "updated_port_scan",
    "window_eligibility", "worker_health",
]
BOOT = """
import os, sys, runpy
from pathlib import Path
sys.path.insert(0, os.getcwd())
os.environ['TARGET_NETWORK'] = '192.168.8.0/24'
from database import db
db.DB_PATH = Path(sys.argv[1])
db.initialize_database()
runpy.run_path(sys.argv[2], run_name='__main__')
"""


def main():
    (ROOT/".test-work").mkdir(exist_ok=True)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", TARGET_NETWORK="192.168.8.0/24", TEMP=str(ROOT/".test-work"), TMP=str(ROOT/".test-work"))
    checks = [([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], "unittest")]
    with tempfile.TemporaryDirectory(prefix="netguardian_tests_", dir=ROOT/".test-work") as temp:
        for name in LEGACY:
            checks.append(([sys.executable, "-c", BOOT, str(Path(temp)/(name+'.db')), str(ROOT/('test_'+name+'.py'))], name))
        failed = []
        for args, name in checks:
            try:
                result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=180 if name=='unittest' else 60)
                print(('PASS' if result.returncode == 0 else 'FAIL') + ' ' + name, flush=True)
                if result.returncode:
                    failed.append(name)
                    print(result.stdout[-6000:] + result.stderr[-6000:], flush=True)
                elif name == 'unittest':
                    print(result.stderr[-2500:], flush=True)
            except subprocess.TimeoutExpired:
                failed.append(name)
                print('TIMEOUT '+name, flush=True)
        print(f'{len(checks)-len(failed)}/{len(checks)} test groups passed')
        return bool(failed)

if __name__ == '__main__':
    raise SystemExit(main())
