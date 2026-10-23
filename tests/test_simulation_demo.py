"""Safe in-memory demonstration regression tests; no database or network access."""
import unittest
from simulation import simulate_traffic as sim

class SimulationDemoTests(unittest.TestCase):
    def setUp(self):
        sim.reset_simulation()

    def tearDown(self):
        sim.reset_simulation()

    def test_scenario_scores(self):
        cases = [
            (sim.simulate_port_scan, 30, "LOW", False),
            (sim.simulate_dns_anomaly, 20, "LOW", False),
            (sim.simulate_traffic_spike, 15, "LOW", False),
            (sim.simulate_unknown_rogue_device, 20, "LOW", False),
            (sim.simulate_critical_incident, 85, "HIGH", True),
        ]
        for action, score, level, would_quarantine in cases:
            with self.subTest(action=action.__name__):
                action()
                event = sim.get_simulation_history()[-1]
                self.assertEqual(event["risk_score"], score)
                self.assertEqual(event["risk_level"], level)
                self.assertEqual(event["would_quarantine"], would_quarantine)
                self.assertTrue(event["simulation"])
        self.assertEqual(len(sim.get_simulation_history()), 5)

    def test_reset_only_clears_demo_history(self):
        sim.simulate_port_scan()
        self.assertEqual(len(sim.get_simulation_history()), 1)
        sim.reset_simulation()
        self.assertEqual(sim.get_simulation_history(), [])

    def test_demo_uses_fictional_addresses(self):
        self.assertEqual(sim.get_target_device()["ip_address"], "192.0.2.42")
        self.assertEqual(sim.DEMO_ROGUE_IP, "192.0.2.250")

if __name__ == "__main__":
    unittest.main()
