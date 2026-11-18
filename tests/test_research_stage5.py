"""Stage 5: quorum-domain, fault attribution and deliberate majority failure."""
from __future__ import annotations

import copy
import unittest

from hetnet import Scenario, Simulator
from hetnet.consensus import OBSERVER_DOMAINS, consensus_from_votes, sign_vote
from hetnet.control import inspect_cu_events
from hetnet.zone_validation import zone_study


KEY = b"laboratory-root-key-for-unit-tests"
NODE, NONCE, TIME = "dra", "cu-1500", 1500


def signed_vote(observer: str, counts: dict[str, int], *,
                at_ms: int = TIME, nonce: str = NONCE) -> dict:
    return {
        "observer": observer,
        "domain": OBSERVER_DOMAINS[observer],
        "node": NODE, "nonce": nonce, "at_ms": at_ms,
        "counts": dict(counts), "delivered": True,
        "mac": sign_vote(KEY, observer, NODE, nonce, at_ms, counts),
    }


class QuorumUnitTests(unittest.TestCase):
    def test_two_honest_signatures_outvote_single_forged_observer(self):
        votes = [
            signed_vote("tap-legacy", {"MAP": 3}),
            signed_vote("tap-epc", {"MAP": 99}),
            signed_vote("tap-5gc", {"MAP": 3}),
        ]
        finding = consensus_from_votes(votes, KEY, NODE, NONCE, TIME)
        self.assertTrue(finding["quorum"])
        self.assertEqual(finding["consensus_counts"], {"MAP": 3})
        self.assertEqual(finding["support_count"], 2)
        self.assertEqual(finding["outlier_observers"], ["tap-epc"])
        self.assertEqual(len(finding["independent_domains"]), 2)

    def test_duplicate_identity_does_not_add_voting_power(self):
        first = signed_vote("tap-legacy", {"a": 1})
        result = consensus_from_votes([first, copy.deepcopy(first)],
                                      KEY, NODE, NONCE, TIME)
        self.assertFalse(result["quorum"])
        self.assertIn("tap-legacy", result["invalid_observers"])
        self.assertEqual(result["valid_votes"], 1)

    def test_mac_tamper_and_replayed_nonce_do_not_count(self):
        good = signed_vote("tap-legacy", {"a": 1})
        tampered = signed_vote("tap-epc", {"a": 1})
        tampered["counts"]["a"] = 999
        replay = signed_vote("tap-5gc", {"a": 1}, nonce="cu-old")
        result = consensus_from_votes(
            [good, tampered, replay], KEY, NODE, NONCE, TIME)
        self.assertFalse(result["quorum"])
        self.assertEqual(set(result["invalid_observers"]),
                         {"tap-epc", "tap-5gc"})

    def test_stale_and_cross_domain_rejected(self):
        old = signed_vote("tap-legacy", {"a": 1}, at_ms=TIME - 2000)
        swapped = signed_vote("tap-epc", {"a": 1})
        swapped["domain"] = "legacy-probe-domain"
        valid = signed_vote("tap-5gc", {"a": 1})
        r = consensus_from_votes([old, swapped, valid],
                                 KEY, NODE, NONCE, TIME)
        self.assertFalse(r["quorum"])
        self.assertEqual(r["valid_votes"], 1)

    def test_split_votes_refuse_attribution(self):
        result = consensus_from_votes([
            signed_vote("tap-legacy", {"a": 1}),
            signed_vote("tap-epc", {"a": 2}),
            {"observer": "tap-5gc", "delivered": False},
        ], KEY, NODE, NONCE, TIME)
        self.assertEqual(result["status"], "split")
        self.assertIsNone(result["consensus_counts"])
        self.assertFalse(result["quorum"])

    def test_honest_majority_assumption_has_known_failure(self):
        result = consensus_from_votes([
            signed_vote("tap-legacy", {"a": 1}),
            signed_vote("tap-epc", {"a": 5}),
            signed_vote("tap-5gc", {"a": 5}),
        ], KEY, NODE, NONCE, TIME)
        self.assertEqual(result["consensus_counts"], {"a": 5})
        self.assertEqual(result["outlier_observers"], ["tap-legacy"])

    def test_validation_of_votes_and_quorum_configuration(self):
        with self.assertRaises(ValueError):
            sign_vote(KEY, "unknown", NODE, NONCE, TIME, {"a": 1})
        with self.assertRaises(ValueError):
            sign_vote(KEY, "tap-epc", NODE, NONCE, TIME, {"a": -1})
        with self.assertRaises(ValueError):
            consensus_from_votes([], KEY, NODE, NONCE, TIME, quorum=1)
        with self.assertRaises(ValueError):
            consensus_from_votes([{}] * 21, KEY, NODE, NONCE, TIME)


class ObserverIntegrationTests(unittest.TestCase):
    def run_scenario(self, observer_case: str, node_case: str = "none",
                     loss: float = 0, seed: int = 42):
        return Simulator(Scenario(
            duration_s=18, subscribers=8, seed=seed,
            inject_attacks=False, node_case=node_case,
            observer_case=observer_case, observer_loss_rate=loss,
        )).run()

    def dra(self, result: dict) -> dict:
        return next(n for n in result["node_evidence"]["nodes"]
                    if n["node"] == "dra")

    def test_nominal_observer_quorum_matches(self):
        r = self.run_scenario("none")
        d = self.dra(r)
        self.assertEqual(d["classification"], "consistent")
        self.assertEqual(d["observer_quorum_missing"], 0)
        self.assertEqual(d["observer_quorum_present"], d["delivered"])
        self.assertEqual(d["observer_outliers"], {})

    def test_single_forged_vote_detected_but_report_is_consistent(self):
        r = self.run_scenario("one_faulty")
        d = self.dra(r)
        self.assertEqual(d["classification"], "consistent_with_observer_outliers")
        self.assertGreater(d["observer_outliers"]["tap-epc"], 0)
        self.assertEqual(d["authenticated_mismatches"], 0)

    def test_one_bad_observer_does_not_hide_real_report_compromise(self):
        r = self.run_scenario("one_faulty", node_case="report")
        self.assertEqual(self.dra(r)["classification"],
                         "persistent_report_divergence")

    def test_two_colluders_can_frame_honest_reporting_node(self):
        r = self.run_scenario("two_colluding", node_case="none")
        d = self.dra(r)
        self.assertEqual(d["classification"], "persistent_report_divergence")
        self.assertGreater(d["authenticated_mismatches"], 0)
        # The algorithm did not read the truth labels, and was fooled.
        self.assertFalse(r["scenario"]["inject_attacks"])

    def test_two_colluders_can_conceal_matching_forged_report(self):
        r = self.run_scenario("two_colluding", node_case="report")
        d = self.dra(r)
        self.assertNotEqual(d["classification"], "persistent_report_divergence")
        self.assertGreater(sum(d["observer_outliers"].values()), 0)

    def test_missing_and_mixed_votes_are_inconclusive(self):
        for case in ("outage", "mixed"):
            with self.subTest(case=case):
                r = self.run_scenario(case, node_case="report")
                d = self.dra(r)
                self.assertEqual(d["classification"],
                                 "observer_quorum_unavailable")
                self.assertEqual(d["authenticated_mismatches"], 0)
                self.assertGreater(d["observer_quorum_missing"], 0)

    def test_stale_and_bad_mac_are_excluded_from_vote_count(self):
        for case in ("stale", "bad_mac"):
            with self.subTest(case=case):
                d = self.dra(self.run_scenario(case))
                self.assertEqual(d["classification"],
                                 "consistent_with_observer_gaps")
                self.assertGreater(d["observer_invalid"]["tap-epc"], 0)
                self.assertGreater(d["observer_quorum_present"], 0)

    def test_full_observer_loss_does_not_erase_good_cu_delivery(self):
        r = self.run_scenario("none", loss=1.0)
        self.assertTrue(all(n["classification"] == "observer_quorum_unavailable"
                            for n in r["node_evidence"]["nodes"]))
        self.assertEqual(r["summary"]["cu_delivery_ratio"], 1.0)
        self.assertNotIn("cu_discrepancy",
                         {a["category"] for a in r["alerts"]})

    def test_truth_labels_cannot_change_evidence_classification(self):
        r = self.run_scenario("one_faulty", node_case="report")
        event_copy = copy.deepcopy(r["events"])
        for item in event_copy:
            item["attack"] = True
            item["detail"]["attack"] = False
        self.assertEqual(r["node_evidence"]["nodes"],
                         inspect_cu_events(event_copy)["nodes"])

    def test_external_quorum_summary_cannot_override_verified_votes(self):
        sim = Simulator(Scenario(
            duration_s=18, subscribers=8, seed=42,
            inject_attacks=False, observer_case="one_faulty",
        ))
        result = sim.run()
        modified = copy.deepcopy(result["events"])
        for event in modified:
            if event["protocol"] == "CU" and event["source"] == "dra":
                event["detail"]["observer_quorum"] = {
                    "quorum": True, "consensus_counts": {"fabricated": 9999},
                    "outlier_observers": [], "valid_observers": [],
                }
        trusted = inspect_cu_events(
            modified, observer_root_key=sim._observer_key)
        self.assertEqual(trusted, result["node_evidence"])
        untrusted = inspect_cu_events(modified)
        self.assertNotEqual(untrusted["nodes"], trusted["nodes"])

    def test_invalid_observer_parameters(self):
        with self.assertRaises(ValueError):
            Scenario(observer_case="invented")
        with self.assertRaises(ValueError):
            Scenario(observer_loss_rate=-0.1)
        with self.assertRaises(ValueError):
            Scenario(observer_loss_rate=1.1)

    def test_study_has_explicit_collusion_failure_not_perfect_score(self):
        result = zone_study(
            seeds=(42, 43), observer_loss_rates=(0.0,),
            observer_cases=("none", "one_faulty", "two_colluding"),
            duration_s=18, subscribers=8,
        )
        by_case = {g["observer_case"]: g for g in result["groups"]}
        self.assertEqual(by_case["none"]["tp"], 2)
        self.assertEqual(by_case["none"]["fp"], 0)
        self.assertEqual(by_case["one_faulty"]["tp"], 2)
        self.assertEqual(by_case["one_faulty"]["fp"], 0)
        self.assertEqual(by_case["two_colluding"]["tp"], 0)
        self.assertEqual(by_case["two_colluding"]["fp"], 2)
        self.assertEqual(len(result["records"]), 12)


if __name__ == "__main__":
    unittest.main()
