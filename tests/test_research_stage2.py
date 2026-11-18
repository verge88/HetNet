"""V2 tests: transaction order, statistical traffic, queues and experiments."""
from __future__ import annotations

import unittest

from hetnet import Scenario, Simulator, default_topology
from hetnet.experiment import classify_correlations, rates, run_multiseed
from hetnet.observations import WINDOW_SECONDS, aggregate
from hetnet.procedures import ProcedureLedger
from hetnet.traffic import TrafficGenerator, daily_factor, poisson
import random


class TransactionTests(unittest.TestCase):
    def test_requires_successful_authentication(self) -> None:
        ledger = ProcedureLedger()
        rejected = ledger.inspect_request(
            100, "Diameter.ULR", "Diameter.ULA", "mme4",
            "hss4", "ue-1", "flow")
        self.assertFalse(rejected.accepted)
        self.assertEqual(rejected.category, "procedure_order")
        request = ledger.inspect_request(101, "Diameter.AIR", "Diameter.AIA",
                                         "mme4", "hss4", "ue-1", "flow")
        self.assertTrue(request.accepted)
        reply = ledger.inspect_response(120, "Diameter.AIA",
                                        "hss4", "mme4", "ue-1", "flow")
        self.assertEqual(reply.completed, "Diameter.AIR")
        valid = ledger.inspect_request(150, "Diameter.ULR", "Diameter.ULA",
                                       "mme4", "hss4", "ue-1", "flow")
        self.assertTrue(valid.accepted)

    def test_provisional_final_and_unmatched_sip(self) -> None:
        ledger = ProcedureLedger()
        ledger.inspect_request(0, "SIP.REGISTER", "SIP.200_REGISTER",
                               "pcscf", "scscf", "ue", "reg")
        ledger.inspect_response(20, "SIP.200_REGISTER",
                                "scscf", "pcscf", "ue", "reg")
        ledger.inspect_request(100, "SIP.INVITE", "SIP.200_INVITE",
                               "pcscf", "scscf", "ue", "call")
        self.assertTrue(ledger.inspect_response(
            110, "SIP.100_TRYING", "scscf", "pcscf", "ue", "call").accepted)
        self.assertEqual(len(ledger.pending), 1)
        self.assertEqual(ledger.inspect_response(
            130, "SIP.200_INVITE", "scscf", "pcscf", "ue", "call").completed,
            "SIP.INVITE")
        self.assertEqual(len(ledger.pending), 0)
        self.assertFalse(ledger.inspect_response(
            200, "SIP.200_INVITE", "scscf", "pcscf", "ue", "call").accepted)

    def test_forged_ack_cannot_enable_bye(self) -> None:
        ledger = ProcedureLedger()
        bad_ack = ledger.inspect_request(
            50, "SIP.ACK", None, "pcscf", "scscf", "ue", "forged")
        self.assertFalse(bad_ack.accepted)
        self.assertFalse(ledger.inspect_request(
            60, "SIP.BYE", "SIP.200_BYE", "pcscf", "scscf", "ue",
            "forged").accepted)

    def test_duplicate_ack_is_rejected(self) -> None:
        ledger = ProcedureLedger()
        ledger.completed[("call", "ue")] = {"SIP.INVITE"}
        self.assertTrue(ledger.inspect_request(
            10, "SIP.ACK", None, "pcscf", "scscf", "ue", "call").accepted)
        self.assertFalse(ledger.inspect_request(
            20, "SIP.ACK", None, "pcscf", "scscf", "ue", "call").accepted)

    def test_reply_reverse_endpoint_and_timeout(self) -> None:
        ledger = ProcedureLedger(timeout_ms=300)
        ledger.inspect_request(0, "Diameter.AIR", "Diameter.AIA",
                               "mme4", "hss4", "ue", "corr")
        self.assertFalse(ledger.inspect_response(
            20, "Diameter.AIA", "mme4", "hss4", "ue", "corr").accepted)
        expired = ledger.expire(301)
        self.assertEqual(len(expired), 1)
        self.assertEqual(ledger.snapshot()["timeouts"], 1)


class TrafficTests(unittest.TestCase):
    def test_day_night_multiplier(self) -> None:
        self.assertAlmostEqual(daily_factor(18 * 3600), 1.35)
        self.assertAlmostEqual(daily_factor(6 * 3600), 0.65)
        self.assertAlmostEqual(daily_factor(18 * 3600, amplitude=0), 1.0)

    def test_poisson_mean_and_reproducibility(self) -> None:
        rng = random.Random(77)
        counts = [poisson(rng, 2.5) for _ in range(4000)]
        self.assertAlmostEqual(sum(counts) / len(counts), 2.5, delta=0.15)
        a = list(TrafficGenerator(11, scale=4).stream(25, 8))
        b = list(TrafficGenerator(11, scale=4).stream(25, 8))
        self.assertEqual(a, b)
        self.assertTrue(a)
        self.assertFalse(list(TrafficGenerator(11, scale=0).stream(25, 8)))

    def test_synthetic_traffic_integration(self) -> None:
        result = Simulator(Scenario(
            duration_s=12, subscribers=8, seed=42,
            traffic_scale=5, inject_attacks=False,
        )).run()
        self.assertGreater(sum(result["summary"]["traffic_generated"].values()), 0)
        self.assertGreater(result["summary"]["total_messages"], 0)
        self.assertIn("transactions", result["summary"])

    def test_causal_link_queues(self) -> None:
        net = default_topology()
        self.assertEqual(net.edge("msc2", "stp").capacity_bps, 64_000)
        sim = Simulator(Scenario(
            duration_s=8, subscribers=4, traffic_scale=0,
            inject_attacks=False,
        ))
        for i in range(160):
            sim.request(800, "MAP.SendAuthenticationInfo", "msc2", "hlr",
                        "ue-0001", "burst-" + str(i), "2G")
        result = sim.run()
        self.assertGreater(result["summary"]["max_queue_delay_ms"], 0)
        self.assertGreater(result["summary"]["queue_drops"], 0)

    def test_windowing_and_counts(self) -> None:
        result = Simulator(Scenario(
            duration_s=12, subscribers=8, seed=3,
            inject_attacks=False,
        )).run()
        self.assertEqual(WINDOW_SECONDS["SS7/MAP"], 30)
        self.assertEqual(WINDOW_SECONDS["Diameter"], 15)
        self.assertEqual(WINDOW_SECONDS["SIP/IMS"], 20)
        windows = aggregate(result["events"])
        self.assertEqual(windows, result["observations"])
        self.assertTrue(windows)
        for row in windows:
            self.assertEqual(row["total"],
                             row["delivered"] + row["rejected"]
                             + row["lost"] + row["congested"]
                             + sum(
                                 1 for e in result["events"]
                                 if e["source"] == row["source"]
                                 and e["protocol"] == row["protocol"]
                                 and e["outcome"] == "NO_ROUTE"
                                 and row["start_ms"] <= e["time_ms"] < row["end_ms"]))


class ExperimentTests(unittest.TestCase):
    def test_confusion_metrics(self) -> None:
        metric = rates([
            {"ground_truth": True, "detected": True},
            {"ground_truth": True, "detected": False},
            {"ground_truth": False, "detected": False},
            {"ground_truth": False, "detected": True},
        ])
        self.assertEqual((metric["tp"], metric["fp"],
                          metric["fn"], metric["tn"]), (1, 1, 1, 1))
        self.assertEqual(metric["f1"], 0.5)
        self.assertEqual(metric["fpr"], 0.5)

    def test_multiseed_reproducible_and_stratified(self) -> None:
        a = run_multiseed(
            duration_s=12, subscribers=8, seeds=(42, 43, 44),
            traffic_scale=2)
        b = run_multiseed(
            duration_s=12, subscribers=8, seeds=(42, 43, 44),
            traffic_scale=2)
        self.assertEqual(a, b)
        self.assertEqual(a["seeds"], [42, 43, 44])
        self.assertIn("mean", a["summary"]["f1"])
        self.assertIn("SS7/MAP", a["per_stack"])
        self.assertIn("5G-SBI/HTTP2", a["per_stack"])
        self.assertTrue(all(0 <= run["fpr"] <= 1 for run in a["runs"]))

    def test_truth_does_not_influence_alerts(self) -> None:
        result = Simulator(Scenario(
            duration_s=15, subscribers=8, seed=42,
            inject_attacks=True)).run()
        groups = classify_correlations(result)
        self.assertIn("attack-ss7", groups)
        self.assertTrue(groups["attack-ss7"]["ground_truth"])
        self.assertTrue(groups["attack-ss7"]["detected"])
        self.assertTrue(any(row["ground_truth"] is False
                            for row in groups.values()))


if __name__ == "__main__":
    unittest.main()
