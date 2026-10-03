git -- versionNetGuardian/
│
├── .venv/
│
├── app.py
├── config.py
├── requirements.txt
│
├── database/
│   ├── __init__.py
│   ├── db.py
│   └── models.py
│
├── discovery/
│   ├── __init__.py
│   └── device_discovery.py
│
├── capture/
│   ├── __init__.py
│   └── packet_capture.py
│
├── monitoring/
│   ├── __init__.py
│   └── traffic_monitor.py
│
├── detection/
│   ├── __init__.py
│   ├── unknown_device.py
│   ├── port_scan.py
│   ├── dns_anomaly.py
│   └── behaviour_drift.py
│
├── risk/
│   ├── __init__.py
│   └── risk_engine.py
│
├── ai/
│   ├── __init__.py
│   └── ai_engine.py
│
├── response/
│   ├── __init__.py
│   └── quarantine.py
│
├── alerts/
│   ├── __init__.py
│   └── alert_manager.py
│
├── analytics/
│   ├── __init__.py
│   └── analytics.py
│
├── dashboard/
│   ├── templates/
│   └── static/
│
└── tests/