
from unittest.mock import patch
import risk.risk_engine as risk

print("=== STEP 370: RISK DEVICE FILTER TEST ===")

devices = [
    {
        "id": 1,
        "ip_address": "192.168.8.1",
        "mac_address": "02:ED:00:00:00:01",
        "status": "online"
    },
    {
        "id": 4,
        "ip_address": "192.168.8.101",
        "mac_address": "02:11:22:33:44:55",
        "status": "offline"
    },
    {
        "id": 29,
        "ip_address": "192.168.8.103",
        "mac_address": "AUTO-CAPTURED",
        "status": "offline"
    },
    {
        "id": 40,
        "ip_address": "8.8.8.8",
        "mac_address": "02:AA:BB:CC:DD:EE",
        "status": "online"
    }
]

evaluated_ids = []

def fake_evaluate(device, auto_quarantine=False):
    evaluated_ids.append(device["id"])
    return {"device_id": device["id"]}

with patch.object(risk, "get_all_devices", return_value=devices):
    with patch.object(
        risk,
        "evaluate_device_risk",
        side_effect=fake_evaluate
    ):
        results = risk.evaluate_all_devices(
            auto_quarantine=False
        )

print("Evaluated IDs:", evaluated_ids)
print("Historical placeholder excluded:", 29 not in evaluated_ids)
print("Public IP excluded:", 40 not in evaluated_ids)
print("Offline verified device included:", 4 in evaluated_ids)
print("Router included:", 1 in evaluated_ids)
print("Result count:", len(results))

assert set(evaluated_ids) == {1, 4}
assert len(results) == 2

print("\nOVERALL RESULT: PASS")
print("No SQLite writes or router operations performed.")
