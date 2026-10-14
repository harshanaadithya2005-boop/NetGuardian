# NetGuardian
**Behavioural Fingerprinting and Risk-Based Automated Quarantine for Small Network Security**

NetGuardian is an integrated, lightweight Network Intrusion Detection and Automated Response System designed specifically for small business, school, and laboratory networks. Instead of relying solely on heavy deep packet inspection, NetGuardian establishes a behavioral baseline for each connected device and detects threats using multi-dimensional **Behaviour Drift Scoring**, **Rule-Based Threat Detection**, **Weighted Risk Scoring (0–100)**, and **Instant Automated Network Quarantine**.

---

## 👥 Project Team & Workstreams

| Member | Focus Area | Key Modules |
| :--- | :--- | :--- |
| **Member 1 (Networking Lead)** | Network Topology, Device Discovery, Packet Capture, Network Isolation | `discovery/`, `capture/`, `response/` |
| **Member 2 (Detection & Risk Lead)** | Suspicious Rules, Behaviour Drift Scoring, Risk Engine, Attack Simulations | `detection/`, `risk/`, `simulation/` |
| **Member 3 (Platform & Dashboard Lead)** | SQLite Database Schema, Data Models, Flask REST API, Web Security Dashboard | `database/`, `app.py`, `dashboard/` |

---

## 🏗️ System Architecture & Workflow

NetGuardian connects raw network traffic to automated containment across a unified 5-stage pipeline:

```
[ Local Network / ARP / Scapy ]
             │
             ▼
  1. Passive Device Discovery (`discovery/device_discovery.py`)
     ├── Auto-detects active network interface & subnet
     ├── Performs Scapy ARP sweep with OS ARP table fallback
     └── Saves devices & baseline profiles to SQLite (`database/db.py`)
             │
             ▼
  2. Traffic Metadata Sniffing (`capture/packet_capture.py`)
     ├── Captures IP, TCP, UDP, and DNS query flows
     └── Logs telemetry (ports, packet size, domains)
             │
             ▼
  3. Multi-Vector Threat & Behaviour Drift Detection (`detection/`)
     ├── Unknown / Untrusted Device (+20 Risk)
     ├── Port Scanning Reconnaissance (+30 Risk)
     ├── DNS Anomaly & Exfiltration / DGA (+20 Risk)
     ├── Traffic-Volume Spike (+15 Risk)
     └── Behaviour Drift Score (+15 Risk) (Proposal Section 8.2)
             │
             ▼
  4. Risk Scoring Engine (`risk/risk_engine.py`)
     ├── Computes combined risk score (0 – 100)
     ├── Categorizes into bands:
     │   ├── LOW (0–39): Normal (Green)
     │   ├── MEDIUM (40–69): Suspicious (Amber) -> Flagged on Dashboard
     │   └── HIGH (70–100): Critical (Red) -> Triggers Automated Quarantine
             │
             ▼
  5. Automated Quarantine Response (`response/quarantine.py`)
     ├── Sets device status to 'quarantined' in database
     ├── Applies firewall block rule (Windows Firewall / Simulated Cisco ACL)
     ├── Issues Critical Alert
     └── Emits audit log to `quarantine_logs` table
             │
             ▼
  6. Web Security Dashboard (`dashboard/` & `app.py`)
     ├── Real-time telemetry cards & live alerts feed
     ├── Interactive device inventory with risk meters & trust toggles
     ├── Device-specific Behavioural Baseline vs. Observed Drift view
     └── 1-Click Attack Simulation Control Panel
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14 on Windows)
- Npcap (installed with Wireshark or standalone for live Scapy sniffing)

### 2. Environment Setup
Activate the included virtual environment:

**On Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1
```

**Or install dependencies if creating a fresh environment:**
```bash
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

### 3. Launch NetGuardian
Run the central entrypoint:
```bash
python run.py
```
*(Or alternatively: `python app.py`)*

Once started, open your web browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Testing & Demonstration (Simulation Lab)

The web dashboard includes a built-in **Attack Simulation & Demonstration Lab** at the top of the page. You can trigger controlled attack scenarios with one click to demonstrate the end-to-end detection and response workflow:

| Scenario | What It Simulates | Expected Outcome |
| :--- | :--- | :--- |
| **Simulate Port Scan** | Rapid reconnaissance targeting 12+ ports | Port scan alert (+30 risk), device flagged on dashboard |
| **Simulate DNS Anomaly** | Long exfiltration domains & high-entropy DGA C2 queries | DNS anomaly alert (+20 risk) |
| **Simulate Traffic Spike & Drift** | Massive data transfer burst across 25+ external IPs | Traffic volume spike (+15) and Behaviour Drift (+15) |
| **Inject Rogue Device** | Unauthorized attacker host joins network | New untrusted device alert (+20 risk) |
| **Full Attack (Quarantine)** | Combined multi-vector assault | Risk reaches **100/100 (HIGH)**; **Automatic Quarantine** is triggered instantly |
| **Reset Simulation** | Clears attack flows and resets states | Network returns to baseline normal |

You can also run scenarios directly from the command line:
```bash
python -m simulation.simulate_traffic
```

---

## 📁 Repository Structure

```
NetGuardian/
│
├── run.py                       # Root launcher script (single-command entrypoint)
├── app.py                       # Flask web backend & REST API orchestrator
├── config.py                    # Unified configuration (subnets, weights, thresholds)
├── requirements.txt             # Python package dependencies
├── README.md                    # Project documentation
│
├── database/
│   ├── db.py                    # SQLite schema: devices, traffic, alerts, profiles, quarantine
│   ├── models.py                # CRUD queries for devices, telemetry, alerts, and audit logs
│   └── network_monitor.db       # Unified SQLite database file
│
├── discovery/
│   └── device_discovery.py      # Network interface detection, Scapy ARP scan, ARP cache fallback
│
├── capture/
│   └── packet_capture.py        # Passive Scapy packet sniffer (TCP/UDP/DNS/IP metadata)
│
├── detection/
│   ├── unknown_device.py        # Unrecognized & untrusted host detection
│   ├── port_scan.py             # Reconnaissance / horizontal & vertical port scan detection
│   ├── dns_anomaly.py           # Domain length, Shannon entropy DGA, and query rate detection
│   └── behaviour_drift.py       # Multi-dimensional Behaviour Drift Score (Proposal Section 8.2)
│
├── risk/
│   └── risk_engine.py           # Weighted risk calculation (0-100) & risk band evaluation
│
├── response/
│   └── quarantine.py            # Windows Firewall rules / ACL isolation & audit logging
│
├── simulation/
│   └── simulate_traffic.py      # Test scenarios for live attack demonstrations
│
└── dashboard/
    ├── templates/
    │   ├── base.html            # Dark-theme base template with live status indicator
    │   ├── index.html           # Main dashboard: stats, devices, alerts feed, traffic stream
    │   └── device.html          # Host detail: baseline comparison & drift meters
    └── static/
        ├── css/style.css        # Responsive cyber-security theme CSS
        └── js/dashboard.js      # AJAX handlers, simulation buttons, and live polling
```

---

## 📊 Verification Test Scripts
All individual test scripts pass cleanly:
- `python test_scapy.py` — Verifies Scapy environment
- `python test_network.py` — Lists local network interfaces
- `python test_hostname.py` — Tests reverse DNS resolution
- `python test_database.py` — Verifies database tables
- `python test_read_devices.py` — Reads all stored devices
- `python device_discovery_test.py` — Tests active ARP network scan
- `python test_models.py` — Tests adding or updating devices
- `python delete_test_device.py` — Tests removing a test device
