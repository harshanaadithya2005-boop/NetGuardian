# NetGuardian — Legacy Test Suites

This directory contains standalone integration, regression, and behavioral verification scripts authored across earlier development milestones of NetGuardian.

## Execution

Do **not** run these test files directly against production databases (`database/network_monitor.db`). 

To execute the entire vetted test suite safely in isolated temporary workspaces with ephemeral databases, run:

```powershell
python tools/run_tests.py
```

`tools/run_tests.py` automatically provisions an isolated SQLite database for each test file, applies the latest database schema with WAL mode enabled, sets the virtual test subnet (`TARGET_NETWORK=192.168.8.0/24`), and executes each test script independently via Python's `runpy`.

## Directory Contents

| Test Script | Scope |
| :--- | :--- |
| `test_alert_api_integration.py` | Validates Flask alert API endpoints and JSON serialisation |
| `test_baseline_history.py` | Tests device baseline generation and history persistence |
| `test_baseline_history_v2.py` | Tests secondary baseline heuristics and history rollups |
| `test_behaviour_history_pipeline.py` | Verifies full behavioral history ingest and sliding windows |
| `test_behaviour_shadow.py` | Tests shadow mode observation vs active alerting |
| `test_behaviour_windows.py` | Evaluates 5-minute / 15-minute behavioral traffic windows |
| `test_capture_health_integration.py` | Validates packet capture health checks and telemetry streams |
| `test_capture_heartbeat.py` | Tests packet sniffer background heartbeat intervals |
| `test_capture_sessions_v2.py` | Verifies multi-session capture tracking and lifecycle states |
| `test_collection_schedule.py` | Verifies cron and periodic scheduler intervals |
| `test_complete_heartbeat_pipeline.py` | End-to-end capture heartbeat and recovery pipeline |
| `test_continuity_eligibility.py` | Tests device continuity eligibility thresholds |
| `test_database.py` | Validates SQLite table creation, indexes, and constraints |
| `test_detection_alert_pipeline.py` | Verifies end-to-end detection rule triggering to alert storage |
| `test_device_ip_conflict.py` | Validates MAC-to-IP conflict detection and resolution |
| `test_eligibility_collector.py` | Verifies metrics collector qualification logic |
| `test_first_discovery_alert.py` | Tests new device discovery alerts on initial ARP sweep |
| `test_heartbeat_bridge.py` | Tests inter-thread heartbeat communication |
| `test_heartbeat_error_priority.py` | Verifies error escalation when heartbeats stall |
| `test_heartbeat_reporter.py` | Tests reporter output formatting and status summaries |
| `test_heartbeat_restart_safety.py` | Ensures safe restart of worker threads after failure |
| `test_hostname.py` | Tests reverse DNS resolution and NetBIOS name fallback |
| `test_identity_guard.py` | Validates anti-spoofing and MAC identity enforcement |
| `test_learned_baseline_sensitivity.py` | Tests drift sensitivity calibration for learned baselines |
| `test_missed_windows.py` | Tests graceful handling of missed capture observation windows |
| `test_models.py` | Validates `database/models.py` CRUD queries |
| `test_network.py` | Tests local interface enumeration and subnet detection |
| `test_read_devices.py` | Tests device query performance and pagination |
| `test_risk_device_filter.py` | Tests filtering of excluded/gateway devices from risk scoring |
| `test_risk_integration.py` | Validates risk engine aggregation and quarantine thresholds |
| `test_safe_history_collector.py` | Tests safe exception handling during historical data collection |
| `test_scapy.py` | Verifies Scapy environment and Npcap availability |
| `test_scheduled_history.py` | Validates scheduled background history rollups |
| `test_threat_detectors.py` | Unit tests for port scan, DNS anomaly, and volume detectors |
| `test_updated_dns_anomaly.py` | Validates Shannon entropy calculation and DGA detection |
| `test_updated_port_scan.py` | Validates horizontal and vertical port scan detection thresholds |
| `test_window_eligibility.py` | Tests time-window eligibility criteria for drift evaluation |
| `test_worker_health.py` | Verifies monitoring worker health states and watchdog checks |

