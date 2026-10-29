# NetGuardian — Formal Unit & Integration Test Suites

This directory contains the primary automated `unittest` test suites covering end-to-end security pipelines, quarantine enforcement, router integrations, simulation demo isolation, and web dashboard routes.

## Running Tests

Run all unit tests using Python's standard test discovery:

```powershell
python -m unittest discover -s tests -v
```

Or run an individual test module:

```powershell
python -m unittest tests/test_security_pipeline.py -v
```

## Test Suites

| Module | Description | Test Count |
| :--- | :--- | :--- |
| `test_application.py` | Core application lifecycle, database migration, and Flask routes | 13 |
| `test_dashboard_modes.py` | Read-only vs. DEMO vs. LIVE mode gating and CSRF security | 15 |
| `test_manual_live_recovery.py` | Emergency manual quarantine overrides and router state recovery | 12 |
| `test_quarantine_identity.py` | MAC and IP binding consistency checks during quarantine events | 10 |
| `test_router_quarantine.py` | Router ACL/firewall isolation, timeout fallback, and rollback | 22 |
| `test_security_pipeline.py` | Full multi-vector detection, drift calculation, and risk scoring | 24 |
| `test_simulation_demo.py` | In-memory attack simulation scenarios and isolation guarantees | 4 |
| `test_stabilization_pages.py` | Stabilization of legacy routes and defensive error handling | 7 |
| `test_stable_restore.py` | Database schema restore, backup rotation, and migration safety | 3 |
| `test_wifi_identity.py` | Wi-Fi identity verification, client rotation, and anti-spoofing | 9 |
| **Total** | | **119 Tests** |

