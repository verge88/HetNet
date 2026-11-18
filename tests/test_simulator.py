"""Regression tests for the abstract signaling engine (Python stdlib only)."""
from __future__ import annotations

from pathlib import Path
import csv
import json
import tempfile
import unittest

from hetnet import RULES, Scenario, Simulator, default_topology
from hetnet.cli import export_run


class HetNetTests(unittest.TestCase):
    def clean(self) -> dict:
        return Simulator(Scenario(duration_s=12, subscribers=8, seed=7,
                                  inject_attacks=False)).run()

    def test_all_four_generations_and_five_stacks_coexist(self) -> None:
        result = self.clean()
        generations = result["summary"]["by_generation"]
        protocols = result["summary"]["by_protocol"]
        for generation in ("2G", "3G", "4G", "5G"):
            self.assertGreater(generations[generation], 0)
        for protocol in ("SS7/MAP", "Diameter", "GTPv2-C", "SIP/IMS", "5G-SBI/HTTP2"):
            self.assertGreater(protocols[protocol], 0)

    def test_reproducibility_with_fixed_seed(self) -> None:
        a = self.clean()
        b = self.clean()
        self.assertEqual(a, b)
        c = Simulator(Scenario(duration_s=12, subscribers=8,
                               seed=8, inject_attacks=False)).run()
        self.assertNotEqual(a["events"], c["events"])

    def test_inter_rat_is_semantic_not_fabricated_wire_packet(self) -> None:
        result = self.clean()
        moves = [e for e in result["events"]
                 if e["operation"] == "InterRAT.ContextTransition"]
        self.assertEqual(len(moves), 8)
        self.assertTrue(all(e["protocol"] == "INTERWORKING"
                            and e["detail"]["wire_message"] is False
                            for e in moves))
        self.assertTrue(all(value in ("3G", "4G", "5G")
                            for value in result["registered"].values()))

    def test_clean_run_has_no_security_alarms(self) -> None:
        result = self.clean()
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["summary"]["rejected"], 0)
        self.assertEqual(result["summary"]["lost"], 0)

    def test_sip_invite_ack_is_correlated(self) -> None:
        result = self.clean()
        completed = {e["correlation_id"] for e in result["events"]
                     if e["operation"] == "SIP.200_INVITE"
                     and e["outcome"] == "DELIVERED"}
        acked = {e["correlation_id"] for e in result["events"]
                 if e["operation"] == "SIP.ACK"
                 and e["outcome"] == "DELIVERED"}
        self.assertTrue(completed)
        self.assertEqual(completed, acked)

    def test_synthetic_security_scenarios(self) -> None:
        result = Simulator(Scenario(duration_s=15, subscribers=8,
                                    seed=7, inject_attacks=True)).run()
        categories = {a["category"] for a in result["alerts"]}
        self.assertIn("unauthorized_operation", categories)
        self.assertIn("signaling_rate_spike", categories)
        self.assertIn("cu_discrepancy", categories)
        self.assertGreaterEqual(result["summary"]["rejected"], 3)

    def test_nf_profile_lifecycle_validation(self) -> None:
        sim = Simulator(Scenario(duration_s=10, subscribers=4,
                                 inject_attacks=False))
        sim.request(200, "Nnrf_NFManagement.NFRegister", "amf5", "nrf5",
                    "nf-amf", "invalid-nf", "5G", payload={
                        "nfInstanceId": "bad-id", "nfType": "AMF",
                        "nfStatus": "REGISTERED",
                    })
        result = sim.run()
        self.assertTrue(any(a["category"] == "nfprofile_invariant"
                            for a in result["alerts"]))

    def test_topology_and_no_phantom_routes(self) -> None:
        net = default_topology()
        path = net.path("sgsn3", "hlr")
        self.assertEqual(path, ("sgsn3", "stp", "hlr"))
        self.assertEqual(net.path("missing", "hlr"), ())
        self.assertGreater(net.latency(path), 0)

    def test_full_loss_blocks_traffic(self) -> None:
        result = Simulator(Scenario(duration_s=7, subscribers=4,
                                    seed=1, inject_attacks=False,
                                    loss_rate=1.0)).run()
        self.assertEqual(result["summary"]["delivered"], 0)
        self.assertGreater(result["summary"]["lost"], 0)

    def test_validation(self) -> None:
        for value in (-0.1, 1.1):
            with self.assertRaises(ValueError):
                Scenario(loss_rate=value)
        with self.assertRaises(ValueError):
            Scenario(subscribers=3)
        with self.assertRaises(ValueError):
            Scenario(duration_s=0)
        sim = Simulator(Scenario(inject_attacks=False))
        with self.assertRaises(ValueError):
            sim.request(0, "invented", "msc2", "hlr", "ue", "x", "2G")
        sim.run()
        with self.assertRaises(RuntimeError):
            sim.run()

    def test_standards_traceable(self) -> None:
        self.assertTrue(all(rule.reference and rule.protocol
                            for rule in RULES.values()))
        self.assertIn("RFC 3261", RULES["SIP.INVITE"].reference)
        self.assertIn("29.510", RULES["Nnrf_NFManagement.NFRegister"].reference)

    def test_exports_are_machine_readable(self) -> None:
        result = self.clean()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            export_run(result, folder)
            self.assertEqual(json.loads((folder / "result.json").read_text(
                encoding="utf-8")), result)
            with (folder / "events.csv").open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), len(result["events"]))


if __name__ == "__main__":
    unittest.main()
