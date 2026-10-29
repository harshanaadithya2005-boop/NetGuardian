# NetGuardian Architecture & Repository Structure

This document provides a comprehensive structural guide to the NetGuardian codebase, detailing module responsibilities, entrypoints, background services, and storage architectures.

---

## High-Level System Architecture

```
                                 ┌────────────────────────────────┐
                                 │     Physical / Wi-Fi Subnet    │
                                 │       (e.g., 192.168.1.0/24)   │
                                 └───────────────┬────────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │      Passive Discovery       │
                                  │   (discovery/device_disc...) │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────┐       ┌──────────────────────┐
│     Scapy Packet Capture        ├──────►│   Metadata Logging   │
│   (capture/packet_capture.py)   │       │   (database/db.py)   │
└─────────────────────────────────┘       └──────────┬───────────┘
                                                     │
                                                     ▼
                                          ┌──────────────────────┐
                                          │   Multi-Vector Drift │
                                          │  & Threat Detection  │
                                          │     (detection/)     │
                                          └──────────┬───────────┘
                                                     │
                                                     ▼
                                          ┌──────────────────────┐
                                          │  Risk Scoring Engine │
                                          │ (risk/risk_engine.py)│
                                          └──────────┬───────────┘
                                                     │
                     ┌───────────────────────────────┴───────────────────────────────┐
                     │                                                               │
                     ▼                                                               ▼
        [ Risk Score >= 70 (HIGH) ]                                     [ Risk Score < 70 (LOW/MED) ]
                     │                                                               │
                     ▼                                                               ▼
       ┌───────────────────────────┐                                   ┌───────────────────────────┐
       │   Automated Quarantine    │                                   │   Logged to Alerts Feed   │
       │  (response/quarantine.py) │                                   │     & Telemetry Stream    │
       │   - Host Status Blocked   │                                   └─────────────┬─────────────┘
       │   - Router ACL / Firewall │                                                 │
       │   - Audit Event Recorded  │                                                 │
       └─────────────┬─────────────┘                                                 │
                     │                                                               │
                     └───────────────────────┬───────────────────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │   Flask Web Security UI   │
                               │  - Cyber-Dark Dashboard   │
                               │  - Interactive Inventory  │
                               │  - Async Alert Triage     │
                               │  - Gemini AI Analysis     │
                               │  - Attack Simulation Lab  │
                               └───────────────────────────┘
```

---

## Root Files

| File | Purpose |
| :--- | :--- |
| `run.py` | Unified execution launcher. Boots passive discovery, packet sniffer, and Flask server simultaneously. |
| `app.py` | Primary Flask application. Hosts REST APIs, alert triage, device management, Gemini AI proxy, and web routes. |
| `config.py` | Central configuration values (subnets, weights, thresholds, database path, `GEMINI_API_KEY`). |
| `start.bat` | Windows batch script helper for launching NetGuardian inside the activated virtual environment. |
| `requirements.txt` | Python package dependencies (Flask, Scapy, Requests, etc.). |
| `pytest.ini` | Pytest configuration file. |
| `.env.example` | Environment variable template (subnet overrides, Gemini API key, router credentials). |
| `README.md` | Primary project presentation, setup instructions, and quickstart guide. |
| `STRUCTURE.md` | Complete architectural layout and directory documentation (this file). |

---

## Directory Hierarchy & Modules

### `ai/` — Artificial Intelligence & Gemini Explanation Engine
- `ai_engine.py`: Generates context-rich security incident breakdowns and actionable containment steps. Uses Google's official Gemini API (`gemini-3.8-flash` with graceful fallback to `gemini-flash-latest`, `gemini-2.0-flash`, and deterministic rule-based templates when offline or unconfigured). Explanations are cached in `alerts.ai_explanation` for fast retrieval.

### `alerts/` — Alert Persistence & Lifecycle
- `alerts_engine.py`: Manages the lifecycle of security alerts, deduplication windows, severity classification, and status transitions (`open`, `acknowledged`, `resolved`, `dismissed`).

### `analytics/` — Telemetry & Chart Metrics
- `analytics_engine.py`: Aggregates hourly packet counts, protocol distributions, risk band distributions, and active device trends for rendering in Chart.js visualizations.

### `capture/` — Network Packet Sniffing
- `packet_capture.py`: Passive multi-threaded packet sniffer built on Scapy. Filters IP traffic, extracts flow metadata (source/destination IP, port, protocol, byte size, DNS domain queries), and buffers data for asynchronous persistence without dropping packets.

### `dashboard/` — Web Interface & Client Assets
- `templates/`: Jinja2 HTML templates adhering to cyber-dark aesthetics:
  - `base.html`: Common layout with responsive navigation, active page indicator, quick live feed toggle, off-canvas Admin Drawer, and global AI Investigation modal.
  - `index.html`: Main mission-control dashboard with telemetry cards, 1-click Attack Simulation Lab, live device status counters, alert feed, and live packet stream.
  - `devices.html`: Interactive device inventory with live search, presence/trust filters, column sorting, inline rename, and 1-click quarantine/trust actions.
  - `device.html`: Detailed single-device security dossier with 4 tabbed panels: *Behaviour & Drift*, *Host Telemetry*, *Quarantine Logs*, and *Hardware Router Management*.
  - `alerts.html`: Full-screen incident triage console with async status updates, multi-facet filtering, search, and direct modal AI investigation.
  - `explain.html`: Dedicated deep-dive incident page for AI threat explanation and remediation recommendations.
  - `analytics.html`: Real-time network telemetry graphs, protocol breakdown, and threat velocity charts using Chart.js with dark-mode styling.
  - `reports.html`: Security compliance reporting dashboard with 1-click CSV exports for devices and alerts, plus printable executive audit reports.
- `static/`: Frontend CSS and JavaScript assets:
  - `css/style.css`: Unified cyber dark theme stylesheet featuring high-contrast tokens, CSS grid layouts, off-canvas drawers, modal overlays, and responsive breakpoints.
  - `js/dashboard.js`: Interactive client logic including AJAX simulation dispatch, live alert stream polling, device table search/filtering/sorting, async alert status triage, and AI modal handling.

### `database/` — Data Layer & Concurrency
- `db.py`: SQLite initialization with **WAL (Write-Ahead Logging)** mode (`PRAGMA journal_mode = WAL`, `PRAGMA synchronous = NORMAL`, `PRAGMA busy_timeout = 5000`) enabling high-throughput concurrent reads and writes between the packet sniffer, discovery sweeper, and Flask web threads.
- `models.py`: Strongly-typed CRUD queries for devices, baseline profiles, network flows, security alerts, and quarantine audit logs.
- `network_monitor.db`: Unified SQLite database file (auto-created on first run).

### `detection/` — Multi-Vector Threat Detectors
- `unknown_device.py`: Identifies unrecognized MAC/IP addresses on the subnet and flags untrusted hosts (+20 risk).
- `port_scan.py`: Analyzes connection velocity across distinct ports to detect horizontal and vertical port scanning reconnaissance (+30 risk).
- `dns_anomaly.py`: Evaluates domain name length, Shannon entropy, and query frequency to identify DGA (Domain Generation Algorithm) malware and DNS data exfiltration (+20 risk).
- `behaviour_drift.py`: Compares short-term device telemetry against established historical baselines across multiple vectors (port variety, volume bursts, active hours) to calculate behavioral drift (+15 risk).

### `discovery/` — Passive & Active Device Discovery
- `device_discovery.py`: Auto-detects local network adapters, resolves subnet gateways, and executes Scapy ARP sweeps with fallback to the host operating system's ARP table to maintain a comprehensive inventory of connected devices.

### `monitoring/` — Background Telemetry Workers
- Background heartbeat monitors, worker thread health checkers, and sliding-window capture collectors that ensure stability during continuous 24/7 network monitoring.

### `response/` — Automated Quarantine & Containment
- `quarantine.py`: Containment engine. Triggers automated host isolation when cumulative device risk scores reach 70/100 (HIGH). Appends isolation rules to the local firewall (or router ACLs) and registers audit entries in the `quarantine_logs` table.

### `risk/` — Risk Assessment Engine
- `risk_engine.py`: Normalizes and aggregates multi-vector detection signals into a unified 0–100 risk score, classifying devices into LOW (0–39), MEDIUM (40–69), and HIGH (70–100) risk bands.

### `router/` — Physical Hardware Router Enforcement
- SSH and Telnet router drivers for applying live MAC-based access control rules directly to physical network routers, with read-only gates, manual confirmation tokens, and state recovery rollbacks.

### `simulation/` — Safe Attack Simulation Lab
- `simulate_traffic.py`: Self-contained demonstration scenarios (Port Scan, DNS Exfiltration, Traffic Burst, Rogue Device, and Full Attack) providing reproducible incident workflows in the web UI without affecting physical network devices.

### `tests/` — Primary Automated Unit Test Suites
- Contains 10 formal `unittest` test suites (119 test cases) validating security pipelines, mode security, CSRF protection, router rollback, and Flask web routes. See [tests/README.md](file:///tests/README.md).

### `tests_legacy/` — Vetted Regression Test Scripts
- Contains 32 historical regression test scripts executed against isolated temporary databases via `tools/run_tests.py`. See [tests_legacy/README.md](file:///tests_legacy/README.md).

### `tools/` — Developer & Diagnostic Utilities
- Helper scripts for seeding synthetic devices, inserting test alerts, performing standalone ARP discovery sweeps, and running the unified test suite. See [tools/README.md](file:///tools/README.md).

### `docs/` — Guides & Documentation
- Integration specifications, deployment manuals, and demonstration guides.

