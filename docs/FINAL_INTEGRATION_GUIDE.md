# NetGuardian — Final Integration & Demonstration Guide

## Purpose
NetGuardian monitors a local network, discovers devices, stores observations in SQLite, evaluates suspicious behavior and risk, and presents a Flask dashboard. In DEMO mode, real-device quarantine is simulated without firewall changes, but real-device records may still be updated by the normal monitoring engine. The separate Attack Simulation Lab uses **fictional devices and in-memory results only**.

## Install this dashboard patch
1. Make a full backup of your existing project. **Do not delete or replace `database/network_monitor.db`.**
2. Copy the three files under `dashboard/` into the matching folders in your project, replacing only those files. The `docs/` and `tests/` additions are optional but recommended.
3. Stop any running Flask server. Activate your existing `.venv` and run `python app.py` from the project root.
4. Open `http://127.0.0.1:5000` and press Ctrl+Shift+R.
5. The dashboard should display **Simulation Results & History** below the five simulation buttons.

## Safe demonstration
- Click Port Scan: 30/100 LOW, Would quarantine No.
- Click DNS Anomaly: 20/100 LOW, No.
- Click Traffic Spike: 15/100 LOW, No.
- Click Rogue Device: 20/100 LOW, No.
- Click Full Attack: 85/100 HIGH, **YES (demo only)**.
- Click Reset Simulation: clears only in-memory demonstration history.
- The **real device counters and alert feed do not change from these demo buttons**. That is intended.
- Do not use real-device **Isolate**, **Release**, or **Scan Network** buttons as part of the safe simulation demonstration without understanding their effects.

## Final verification
From the project root, with your environment active, run:

```powershell
python -m compileall -q app.py database discovery detection risk simulation response dashboard monitoring capture
python -m flask --app app routes
python -m unittest discover -s tests -p "test_simulation_demo.py" -v
```

The last command requires copying `tests/test_simulation_demo.py` into your project. It tests only the in-memory simulation functions, not your live network or database.

## Troubleshooting
- `GET /api/simulate/history` must return HTTP 200 and JSON `{ "status": "success", "simulation": true, "events": [...] }`.
- If the history API works but the panel is absent, check that Flask's `/` route renders `index.html`, and that you copied `dashboard/templates/index.html` (not the older `dashboard.html`).
- If the panel is visible but buttons do nothing, check browser F12 Console and confirm `dashboard/static/js/dashboard.js` loads.
- If a browser returns 405 while Flask's test client returns 200, restart the running server and ensure you are visiting the correct local port.

## Known limitations
- In-memory history is reset when the Python process restarts; with multiple server processes each has separate history.
- The simulation is **not live packet injection** and does not demonstrate real firewall blocking.
- Passive packet capture and discovery depend on Windows permissions, network configuration and Npcap availability.
- The original README's statements that demo scenarios create real alerts, change real-device scores, or reach 100/100 are outdated for this safe implementation.
- Before GitHub submission, review `git status`, unresolved merges, test scripts and secret files. Do not commit `.venv`, SQLite databases, or credentials.
