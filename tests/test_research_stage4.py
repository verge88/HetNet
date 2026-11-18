"""Stage 4: node evidence, CU transport-loss controls and truth isolation."""
from __future__ import annotations

import unittest

from hetnet import Scenario, Simulator
from hetnet.control import inspect_cu_events
from hetnet.node_validation import node_study


def cu(node: str, t: int, *, delivered: bool = True,
       mac: bool | None = True, consistent: bool | None = True,
       reported: int | None = 5, observed: int | None = 5) -> dict:
    return {
        "protocol": "CU", "operation": "CU.Reconciliation", "source": node,
        "time_ms": t, "correlation_id": "cu-" + str(t),
        "detail": {
            "cu_delivered": delivered, "mac_valid": mac,
            "reported_total": reported, "observed_total": observed,
            "observer_consistent": consistent,
        },
    }


class EvidenceUnitTests(unittest.TestCase):
    def test_two_authenticated_discrepancies_not_single(self) -> None:
        one = inspect_cu_events([cu("dra", 100, consistent=False,
                                    reported=10, observed=5)])["nodes"][0]
        self.assertEqual(one["classification"], "unconfirmed_divergence")
        second = inspect_cu_events([
            cu("dra", 100, consistent=False, reported=10, observed=5),
            cu("dra", 200, consistent=False, reported=11, observed=6),
        ])["nodes"][0]
        self.assertEqual(second["classification"], "persistent_report_divergence")
        self.assertEqual(second["max_mismatch_streak"], 2)

    def test_mac_failure_is_not_node_compromise(self) -> None:
        result = inspect_cu_events([
            cu("msc2", 100, mac=False, consistent=False),
            cu("msc2", 200, mac=False, consistent=False),
        ])["nodes"][0]
        self.assertEqual(result["classification"], "report_integrity_failure")
        self.assertEqual(result["authenticated_mismatches"], 0)
        self.assertEqual(result["invalid_macs"], 2)

    def test_missing_responses_are_telemetry_degradation(self) -> None:
        missing = [cu("dra", t, delivered=False, mac=None,
                      consistent=None, reported=None, observed=None)
                   for t in (100, 200, 300)]
        result = inspect_cu_events(missing)["nodes"][0]
        self.assertEqual(result["classification"], "telemetry_degraded")
        self.assertEqual(result["delivery_ratio"], 0)
        self.assertEqual(result["max_missing_streak"], 3)
        self.assertEqual(result["authenticated_mismatches"], 0)

    def test_matching_report_with_some_missing_cu_is_not_compromise(self) -> None:
        observed = [
            cu("sgsn3", 100, consistent=True),
            cu("sgsn3", 200, delivered=False, mac=None,
               consistent=None, reported=None, observed=None),
            cu("sgsn3", 300, consistent=True),
        ]
        finding = inspect_cu_events(observed)["nodes"][0]
        self.assertEqual(finding["classification"], "consistent_with_loss")
        self.assertEqual(finding["authenticated_matches"], 2)
        self.assertEqual(finding["missing"], 1)

    def test_missing_breaks_discrepancy_confirmation(self) -> None:
        result = inspect_cu_events([
            cu("dra", 100, consistent=False, reported=7, observed=5),
            cu("dra", 200, delivered=False, mac=None,
               consistent=None, reported=None, observed=None),
            cu("dra", 300, consistent=False, reported=7, observed=5),
        ])["nodes"][0]
        self.assertEqual(result["classification"], "unconfirmed_divergence")
        self.assertEqual(result["max_mismatch_streak"], 1)

    def test_vector_disagreement_even_when_totals_match(self) -> None:
        result = inspect_cu_events([
            cu("dra", 100, consistent=False, reported=10, observed=10),
            cu("dra", 200, consistent=False, reported=10, observed=10),
        ])["nodes"][0]
        self.assertEqual(result["classification"], "persistent_report_divergence")

    def test_evidence_does_not_read_attack_flags_or_alerts(self) -> None:
        sample = [
            cu("dra", 100, consistent=False, reported=6, observed=5),
            cu("dra", 200, consistent=False, reported=7, observed=5),
        ]
        first = inspect_cu_events(sample)
        mutated = [{**item, "attack": True, "alerts": ["fake"]} for item in sample]
        self.assertEqual(first, inspect_cu_events(mutated))

    def test_malformed_or_no_comparisons_are_inconclusive(self) -> None:
        sample = cu("dra", 100, mac=True, consistent=None,
                    reported=None, observed=None)
        result = inspect_cu_events([sample])["nodes"][0]
        self.assertEqual(result["classification"], "insufficient_evidence")
        with self.assertRaises(ValueError):
            inspect_cu_events([], min_confirmations=0)


class ControlIntegrationTests(unittest.TestCase):
    def simulate(self, *, node_case: str, loss_rate: float = 0,
                 seed: int = 42) -> dict:
        return Simulator(Scenario(
            duration_s=18, subscribers=8, seed=seed,
            inject_attacks=False, node_case=node_case,
            loss_rate=loss_rate,
        )).run()

    def test_clean_all_cu_consistent(self) -> None:
        result = self.simulate(node_case="none")
        classes = {r["classification"] for r in result["node_evidence"]["nodes"]}
        self.assertEqual(classes, {"consistent"})
        self.assertEqual(result["summary"]["cu_delivery_ratio"], 1)
        self.assertEqual(result["summary"]["cu_observations"],
                         result["summary"]["cu_delivered"])

    def test_report_falsification_is_distinct_from_integrity_failure(self) -> None:
        result = self.simulate(node_case="report")
        classes = {r["node"]: r["classification"]
                   for r in result["node_evidence"]["nodes"]}
        self.assertEqual(classes["dra"], "persistent_report_divergence")
        self.assertEqual(classes["msc2"], "consistent")
        self.assertFalse(any(e["attack"] for e in result["events"] if e["protocol"] == "CU"))
        self.assertIn("cu_discrepancy", {a["category"] for a in result["alerts"]})

    def test_tampered_control_messages_are_not_attributed_to_node(self) -> None:
        result = self.simulate(node_case="tamper")
        classes = {r["node"]: r["classification"]
                   for r in result["node_evidence"]["nodes"]}
        self.assertEqual(classes["msc2"], "report_integrity_failure")
        self.assertEqual(classes["dra"], "consistent")
        categories = {a["category"] for a in result["alerts"]}
        self.assertIn("cu_integrity", categories)
        self.assertNotIn("cu_discrepancy", categories)

    def test_total_control_path_loss_is_not_compromise(self) -> None:
        result = self.simulate(node_case="none", loss_rate=1)
        classes = {r["classification"] for r in result["node_evidence"]["nodes"]}
        self.assertEqual(classes, {"telemetry_degraded"})
        self.assertEqual(result["summary"]["cu_delivered"], 0)
        self.assertTrue(all(e["outcome"] == "MISSING" for e in result["events"]
                            if e["protocol"] == "CU"))

    def test_control_losses_reproducible(self) -> None:
        a = self.simulate(node_case="none", loss_rate=.2, seed=83)
        b = self.simulate(node_case="none", loss_rate=.2, seed=83)
        self.assertEqual(a, b)
        self.assertLess(a["summary"]["cu_delivery_ratio"], 1)
        self.assertGreater(a["summary"]["cu_delivered"], 0)

    def test_node_scenarios_are_rejected_if_unknown(self) -> None:
        with self.assertRaises(ValueError):
            Scenario(node_case="wrong")


class NodeStudyTests(unittest.TestCase):
    def test_node_matrix_and_truth_source(self) -> None:
        result = node_study(
            seeds=(42, 43), loss_rates=(0, .25),
            cases=("none", "report", "tamper", "both"),
            duration_s=18, subscribers=8)
        self.assertEqual(len(result["node_records"]), 2 * 2 * 4 * 6)
        self.assertEqual(len(result["conditions"]), 2 * 2)
        clean = [r for r in result["node_records"]
                 if r["case"] == "none" and r["loss_rate"] == 0]
        self.assertTrue(all(r["classification"] == "consistent" for r in clean))
        no_loss = [r for r in result["conditions"] if r["loss_rate"] == 0]
        self.assertTrue(all(r["recall"] == 1 for r in no_loss))
        self.assertTrue(all(r["fp"] == 0 for r in no_loss))

    def test_matrix_requires_distinct_cases_and_valid_loss(self) -> None:
        with self.assertRaises(ValueError):
            node_study(loss_rates=())
        with self.assertRaises(ValueError):
            node_study(loss_rates=(1.1,))
        with self.assertRaises(ValueError):
            node_study(cases=("unknown",))


if __name__ == "__main__":
    unittest.main()
