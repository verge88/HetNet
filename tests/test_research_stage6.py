"""Stage 6: cross-generation compromised nodes and correlated monitoring faults."""
from __future__ import annotations

import copy
import unittest

from hetnet import Scenario, Simulator
from hetnet.cohort_validation import multi_node_study
from hetnet.domain_analysis import analyze_domain_correlations
from hetnet.fault_domains import CommonFaultSchedule, MONITORED_NODES


def run_scenario(targets=(), case="none", probability=1.0, seed=42):
    simulation = Simulator(Scenario(
        duration_s=18, subscribers=8, seed=seed, inject_attacks=False,
        node_case="none", report_fault_nodes=targets,
        shared_zone_case=case, shared_zone_probability=probability,
        loss_rate=0, observer_loss_rate=0,
    ))
    return simulation, simulation.run()


def evidence(result):
    return {x["node"]: x for x in result["node_evidence"]["nodes"]}


class CommonFailureTests(unittest.TestCase):
    def test_epoch_draw_cached_and_reproducible(self):
        first = CommonFaultSchedule(seed=12, kind="epc_5gc_outage",
                                    probability=.5, onset_ms=500)
        second = CommonFaultSchedule(seed=12, kind="epc_5gc_outage",
                                     probability=.5, onset_ms=500)
        self.assertFalse(first.at(400).active)
        for t in (500, 750, 1000, 1500):
            self.assertEqual(first.at(t), first.at(t))
            self.assertEqual(first.at(t), second.at(t))

    def test_shared_failure_applies_to_all_six_nodes_per_epoch(self):
        sim, result = run_scenario(case="epc_outage")
        active = [e for e in result["events"]
                  if e["protocol"] == "CU" and e["time_ms"] >= 13500]
        self.assertEqual(len({e["source"] for e in active}), 6)
        for e in active:
            missing = e["detail"]["observer_quorum"]["missing_observers"]
            self.assertIn("tap-epc", missing)
            self.assertEqual(e["detail"]["observer_quorum"]["support_count"], 2)
        self.assertEqual(result["domain_evidence"],
                         analyze_domain_correlations(result["events"],
                                                     sim._observer_key))

    def test_two_domains_outage_causes_cross_generation_quorum_loss(self):
        _, result = run_scenario(case="epc_5gc_outage")
        active = [row for row in result["domain_evidence"]["epochs"]
                  if row["time_ms"] >= 13500]
        self.assertTrue(active)
        self.assertTrue(all(row["simultaneously_missing_domains"] == 2
                            and row["cross_node_quorum_loss"] for row in active))
        self.assertTrue(all(row["cross_generation_missing"] for row in active))
        self.assertTrue(all(len(row["quorum_lost_nodes"]) == 6 for row in active))
        self.assertEqual(
            {row["classification"] for row in result["node_evidence"]["nodes"]},
            {"observer_quorum_unavailable"})

    def test_four_generation_forged_reports_not_dra_only(self):
        targets = ("msc2", "sgsn3", "mme4", "amf5")
        _, result = run_scenario(targets)
        nodes = evidence(result)
        self.assertTrue(all(nodes[n]["classification"] ==
                            "persistent_report_divergence" for n in targets))
        self.assertEqual(nodes["dra"]["classification"], "consistent")
        self.assertEqual(nodes["pcscf"]["classification"], "consistent")

    def test_one_zone_absence_preserves_detection_for_2g_and_5g(self):
        _, result = run_scenario(("msc2", "amf5"), "epc_outage")
        nodes = evidence(result)
        self.assertEqual(nodes["msc2"]["classification"],
                         "persistent_report_divergence")
        self.assertEqual(nodes["amf5"]["classification"],
                         "persistent_report_divergence")
        self.assertFalse(any(
            nodes[node]["classification"] == "persistent_report_divergence"
            for node in MONITORED_NODES if node not in ("msc2", "amf5")
        ))

    def test_common_collusion_frames_honest_nodes_and_conceals_forged(self):
        targets = ("msc2", "amf5")
        _, result = run_scenario(targets, "epc_5gc_collude")
        nodes = evidence(result)
        for node in MONITORED_NODES:
            if node in targets:
                self.assertNotEqual(nodes[node]["classification"],
                                    "persistent_report_divergence")
            else:
                self.assertEqual(nodes[node]["classification"],
                                 "persistent_report_divergence")
        self.assertGreater(
            result["domain_evidence"]["summary"]["epochs_with_shared_outlier"], 0)

    def test_correlated_outage_not_equivalent_to_node_compromise(self):
        _, result = run_scenario((), "all_outage")
        self.assertFalse(any(
            row["classification"] == "persistent_report_divergence"
            for row in result["node_evidence"]["nodes"]))
        self.assertGreater(
            result["domain_evidence"]["summary"]["epochs_with_two_missing_domains"], 0)

    def test_zero_activation_probability_removes_common_faults(self):
        _, result = run_scenario((), "epc_5gc_collude", probability=0)
        self.assertEqual(
            result["domain_evidence"]["summary"]["epochs_with_shared_outlier"], 0)
        self.assertEqual(
            {r["classification"] for r in result["node_evidence"]["nodes"]},
            {"consistent"})

    def test_metadata_attack_labels_and_claimed_majority_not_trusted(self):
        sim, result = run_scenario(("msc2",), "epc_corrupt")
        data = copy.deepcopy(result["events"])
        for e in data:
            if e["protocol"] != "CU":
                continue
            e["attack"] = not e["attack"]
            e["detail"]["observer_quorum"] = {"quorum": True,
                                               "consensus_counts": {"x": 999}}
        self.assertEqual(
            result["domain_evidence"],
            analyze_domain_correlations(data, sim._observer_key))
        self.assertEqual(result["summary"]["cu_observations"],
                         len([e for e in data if e["protocol"] == "CU"]))

    def test_duplicate_node_event_cannot_inflate_domain_correlation(self):
        sim, result = run_scenario(case="epc_outage")
        copied = copy.deepcopy(result["events"])
        first = next(e for e in copied if e["protocol"] == "CU")
        copied.extend(copy.deepcopy(first) for _ in range(4))
        computed = analyze_domain_correlations(copied, sim._observer_key)
        self.assertEqual(result["domain_evidence"], computed)

    def test_invalid_node_and_shared_settings_are_rejected(self):
        for kwargs in (
            {"report_fault_nodes": ("unknown",)},
            {"report_fault_nodes": ("amf5", "amf5")},
            {"report_fault_nodes": ["amf5"]},
            {"shared_zone_case": "unknown"},
            {"shared_zone_probability": -0.1},
            {"shared_zone_probability": 1.1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Scenario(**kwargs)
        with self.assertRaises(ValueError):
            analyze_domain_correlations([], b"root", min_affected_nodes=1)


class CohortValidationTests(unittest.TestCase):
    def test_multinode_matrix_has_explicit_known_majority_failure(self):
        report = multi_node_study(
            seeds=(42, 43), duration_s=18, subscribers=8,
            fault_cases=("none", "epc_outage", "epc_5gc_outage",
                         "epc_5gc_collude"),
            cohort_names=("none", "legacy_5g"),
        )
        self.assertEqual(len(report["runs"]), 2 * 4 * 2)
        self.assertEqual(len(report["node_records"]), 2 * 4 * 2 * 6)
        groups = {g["shared_zone_case"]: g for g in report["groups"]}
        self.assertEqual(groups["none"]["fp"], 0)
        self.assertEqual(groups["none"]["fn"], 0)
        self.assertEqual(groups["epc_outage"]["fn"], 0)
        self.assertEqual(groups["epc_outage"]["fp"], 0)
        self.assertEqual(groups["epc_5gc_outage"]["tp"], 0)
        self.assertGreater(groups["epc_5gc_outage"]["uncertain_node_records"], 0)
        self.assertEqual(groups["epc_5gc_collude"]["tp"], 0)
        self.assertGreater(groups["epc_5gc_collude"]["fp"], 0)
        self.assertEqual(groups["epc_5gc_collude"]["fn"], 4)
        self.assertEqual(len(report["by_generation"]), 5)

    def test_multinode_matrix_is_seed_reproducible(self):
        kwargs = dict(seeds=(42,), fault_cases=("none", "epc_5gc_collude"),
                      cohort_names=("none", "four_generations"))
        self.assertEqual(multi_node_study(**kwargs),
                         multi_node_study(**kwargs))

    def test_validation_rejects_invalid_inputs(self):
        for kwargs in (
            {"seeds": ()}, {"seeds": (42, 42)},
            {"fault_cases": ("unknown",)},
            {"cohort_names": ("unknown",)},
            {"fault_probability": 2},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                multi_node_study(**kwargs)


if __name__ == "__main__":
    unittest.main()
