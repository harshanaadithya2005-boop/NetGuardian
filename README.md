# NetGuardian
**Behavioural Fingerprinting, Multi-Vector Threat Detection & Risk-Based Automated Quarantine for Small Networks**

NetGuardian is an integrated, lightweight Network Intrusion Detection and Automated Response System designed specifically for small business, school, and laboratory networks. Instead of relying solely on heavy deep packet inspection, NetGuardian establishes a behavioral baseline for each connected device and detects threats using multi-dimensional **Behaviour Drift Scoring**, **Rule-Based Threat Detection**, **Weighted Risk Scoring (0–100)**, **Automated Quarantine Containment**, and **Gemini AI Incident Analysis**.

---

## 🌟 Key Capabilities & Quality-of-Life Highlights

- ⚡ **High-Throughput SQLite WAL Concurrency**: Configured with `PRAGMA journal_mode = WAL` and `PRAGMA busy_timeout = 5000`, eliminating database locks and enabling non-blocking simultaneous packet sniffing, ARP discovery sweeps, and web dashboard interactions.
- 🤖 **Google Gemini AI Threat Investigations**: On-demand AI incident analysis (`gemini-3.8-flash` via official Gemini API with multi-tier fallback to `gemini-flash-latest`, `gemini-2.0-flash`, and deterministic rule engines). Delivers instant root cause summaries, confidence ratings, and actionable containment guidance directly in an interactive modal, with results permanently cached for zero-latency retrieval.
- 🎨 **Modern Cyber-Dark Web Interface**: Clean cyber-security aesthetics with active navigation indicators, mobile-responsive navbar, off-canvas quick Admin Drawer, and a global header toggle to pause/resume real-time telemetry polling.
- 🔍 **Interactive Device Inventory**: Live search, multi-facet status filter chips (online/offline, trusted/untrusted/quarantined), column sorting, inline device renaming, and 1-click trust toggles or quarantine actions.
- 🛡️ **Async Alert Triage & Incident Center**: Full-screen incident triage console featuring asynchronous status transitions (`open`, `acknowledged`, `resolved`, `dismissed`) via AJAX without page reloads, plus multi-facet severity and status filtering.
- 📊 **Tabbed Device Security Dossiers**: 4-panel deep dive for each host (*Behaviour & Drift*, *Host Traffic Telemetry*, *Quarantine & Containment Logs*, and *Hardware Router Management*).
- 📈 **Real-Time Analytics & Dark Charts**: Real-time traffic volume, protocol distribution, and risk band graphs powered by Chart.js with dark-theme palettes.
- 📥 **1-Click Security Reports & Exports**: Instant download of complete device inventories as CSV (`/reports/devices.csv`), alert history as CSV (`/reports/alerts.csv`), and executive audit summaries.
- 🧪 **Built-In Attack Simulation Lab**: 1-click in-memory attack scenarios for safe live demonstrations without risking physical network disruptions.

---

## 👥 Project Team & Workstreams

| Member | Focus Area | Key Modules |
| :--- | :--- | :--- |
| **Member 1 (Networking Lead)** | Network Topology, Device Discovery, Packet Capture, Network Isolation | `discovery/`, `capture/`, `response/`, `router/` |
| **Member 2 (Detection & Risk Lead)** | Suspicious Rules, Behaviour Drift Scoring, Risk Engine, Attack Simulations | `detection/`, `risk/`, `simulation/` |
| **Member 3 (Platform & Dashboard Lead)** | SQLite Database Schema, Data Models, Flask REST API, Web Security Dashboard | `database/`, `app.py`, `dashboard/`, `ai/` |

---

## 🏗️ System Architecture & Workflow

NetGuardian connects raw network traffic to automated containment across a unified 6-stage pipeline:

```
[ Local Network / Wi-Fi Subnet / Npcap ]
                 │
                 ▼
  1. Passive Device Discovery (`discovery/device_discovery.py`)
     ├── Auto-detects active network interface & subnet gateway
     ├── Performs Scapy ARP sweep with OS ARP table fallback
     └── Saves devices & baseline profiles to SQLite (`database/db.py`)
                 │
                 ▼
  2. Traffic Metadata Sniffing (`capture/packet_capture.py`)
     ├── Captures IP, TCP, UDP, and DNS query flows in real time
     └── Logs telemetry (ports, packet size, protocols, queried domains)
                 │
                 ▼
  3. Multi-Vector Threat & Behaviour Drift Detection (`detection/`)
     ├── Unknown / Untrusted Device Detection (+20 Risk)
     ├── Port Scanning Reconnaissance Detection (+30 Risk)
     ├── DNS Anomaly & Exfiltration / DGA Detection (+20 Risk)
     ├── Traffic-Volume Burst Spike Detection (+15 Risk)
     └── Behaviour Drift Scoring (+15 Risk) (Proposal Section 8.2)
                 │
                 ▼
  4. Risk Scoring Engine (`risk/risk_engine.py`)
     ├── Computes normalized combined risk score (0 – 100)
     ├── Categorizes into threat bands:
     │   ├── LOW (0–39): Normal (Green)
     │   ├── MEDIUM (40–69): Suspicious (Amber) -> Flagged on Dashboard
     │   └── HIGH (70–100): Critical (Red) -> Triggers Automated Quarantine
                 │
                 ▼
  5. Automated Quarantine Response (`response/quarantine.py`)
     ├── Updates device status to 'quarantined' in database
     ├── Applies firewall block rule (Windows Firewall / Router ACL)
     ├── Emits high-priority Critical Security Alert
     └── Logs isolation event with timestamp to `quarantine_logs` table
                 │
                 ▼
  6. Web Security Dashboard & AI Copilot (`dashboard/`, `app.py`, `ai/`)
     ├── Real-time telemetry cards & live alerts stream
     ├── Interactive device inventory with risk meters & trust toggles
     ├── Async incident triage console & status lifecycle management
     ├── Gemini AI Incident Investigation modal with instant explanation
     ├── Real-time traffic analytics and protocol distribution graphs
     └── 1-Click Attack Simulation Demonstration Lab
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.10+** (tested on Python 3.10 through 3.14 on Windows)
- **Npcap** (installed with Wireshark or standalone with *WinPcap API-compatible mode* enabled for live Scapy sniffing)

### 2. Environment Setup
Clone the repository and activate the virtual environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

Or initialize a fresh environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and configure your settings:
```powershell
cp .env.example .env
```

Key environment configuration options:
```ini
# Gemini API Key for AI threat explanations
GEMINI_API_KEY=your_gemini_api_key_here

# Target network subnet (auto-detected if omitted)
TARGET_NETWORK=192.168.1.0/24

# Execution mode: DEMO (safe simulation) or LIVE (physical firewall/router enforcement)
ENFORCEMENT_MODE=DEMO
```

### 4. Launch NetGuardian
Run the central entrypoint:
```powershell
python run.py
```
*(Alternatively, run the Flask web service directly: `python app.py`)*

Once started, open your web browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Built-In Attack Simulation Lab

The web dashboard includes a built-in **Attack Simulation & Demonstration Lab** at the top of the main dashboard. You can trigger controlled attack scenarios with one click to demonstrate the end-to-end detection and response workflow safely in memory:

| Scenario | What It Simulates | Expected Outcome |
| :--- | :--- | :--- |
| **Simulate Port Scan** | Rapid reconnaissance targeting 12+ ports | Port scan alert (+30 risk), device flagged on dashboard |
| **Simulate DNS Anomaly** | Long exfiltration domains & high-entropy DGA C2 queries | DNS anomaly alert (+20 risk) |
| **Simulate Traffic Spike & Drift** | Massive data transfer burst across 25+ external IPs | Traffic volume spike (+15) and Behaviour Drift (+15) |
| **Inject Rogue Device** | Unauthorized attacker host joins network | New untrusted device alert (+20 risk) |
| **Full Attack (Quarantine)** | Combined multi-vector assault | Risk reaches **HIGH (85–100/100)**; Automatic Quarantine triggered |
| **Reset Simulation** | Clears attack flows and resets states | Network returns to baseline normal |

You can also run scenarios directly from the command line:
```powershell
python -m simulation.simulate_traffic
```

---

## 📊 Automated Verification & Test Suites

NetGuardian includes a comprehensive, dual-tier test suite to guarantee safety, regression protection, and zero runtime breaks:

### 1. Formal Unit & Integration Test Suites (119 Tests)
Covers application routing, mode gating, router isolation rollback, CSRF defenses, and detection algorithms:
```powershell
python -m unittest discover -s tests -v
```
*Result: 119/119 tests pass cleanly.*

### 2. Full Unified Regression Runner (33/33 Test Groups)
Runs all 119 unittests plus all 32 historical regression scripts in `tests_legacy/` against ephemeral temporary databases:
```powershell
python tools/run_tests.py
```
*Result: 33/33 test groups pass cleanly.*

---

## 📁 Repository Structure Overview

A clean, modular project layout separating production core modules, web presentation, test suites, and developer utilities:

```
NetGuardian/
│
├── run.py                       # Unified system launcher (discovery + capture + Flask)
├── app.py                       # Flask web backend, REST APIs, and Gemini proxy
├── config.py                    # Unified configuration (subnets, weights, AI key)
├── requirements.txt             # Python package dependencies
├── .env.example                 # Environment configuration template
├── README.md                    # Primary project documentation
├── STRUCTURE.md                 # Full architectural map and module breakdown
│
├── ai/                          # Google Gemini AI incident explanation engine
├── alerts/                      # Security alert lifecycle and storage
├── analytics/                   # Real-time telemetry metrics and chart aggregators
├── capture/                     # Passive Scapy packet sniffer (TCP/UDP/DNS flows)
├── dashboard/                   # Flask templates and static assets (CSS/JS)
│   ├── templates/               # Cyber-dark Jinja2 templates (index, devices, alerts, etc.)
│   └── static/                  # Responsive cyber CSS and interactive dashboard JS
├── database/                    # SQLite schema with WAL concurrency and models
├── detection/                   # Threat detectors (port scan, DNS, drift, unknown host)
├── discovery/                   # Passive ARP sweeper and network interface detector
├── monitoring/                  # Background worker health checkers and heartbeat monitors
├── response/                    # Automated quarantine enforcement and audit logging
├── risk/                        # Weighted risk scoring engine (0–100)
├── router/                      # Physical router hardware drivers (SSH/Telnet ACLs)
├── simulation/                  # In-memory attack simulation scenarios
│
├── tests/                       # 10 formal unittest test suites (119 test cases)
├── tests_legacy/                # 32 regression test scripts executed by run_tests.py
├── tools/                       # Developer utilities (seed devices, test runner, etc.)
└── docs/                        # Integration and deployment guides
```

For detailed descriptions of every file and directory, refer to [STRUCTURE.md](file:///STRUCTURE.md).
