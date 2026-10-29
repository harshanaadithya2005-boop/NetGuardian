# NetGuardian — Developer & Diagnostic Tools

This directory contains standalone utility scripts for development, seeding test data, manual diagnostic runs, and executing the automated test runner.

## Utilities

### 1. Unified Test Runner (`run_tests.py`)
Executes all 10 formal `unittest` test suites (119 test cases) in `tests/`, followed by 32 legacy regression test scripts in `tests_legacy/` against ephemeral temporary databases.
```powershell
python tools/run_tests.py
```

### 2. Device Discovery Diagnostic (`device_discovery_test.py`)
Performs a direct Scapy ARP sweep on the detected network interface and falls back to the operating system's ARP table to verify subnet connectivity.
```powershell
python tools/device_discovery_test.py
```

### 3. Insert Sample Data (`insert_sample_data.py`)
Populates the active database (`database/network_monitor.db`) with representative sample devices, baseline profiles, network traffic flows, and alerts for UI verification and development.
```powershell
python tools/insert_sample_data.py
```

### 4. Bulk Device Seeding (`seed_many_devices.py`)
Generates 50+ diverse device records across various vendors, device types, presence statuses, and risk profiles to test table pagination, filtering, and search performance.
```powershell
python tools/seed_many_devices.py
```

### 5. Add Test Alert (`add_test_alert.py`)
Injects a single synthetic security alert for testing alert feed reactivity, triage status updates, and Gemini AI investigation modal workflows.
```powershell
python tools/add_test_alert.py
```

### 6. Delete Test Device (`delete_test_device.py`)
Cleans up temporary or synthetic test devices created during testing sessions.
```powershell
python tools/delete_test_device.py
```
