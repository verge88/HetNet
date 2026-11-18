"""Stage 7: synthetic independent probe sampling and zonal descriptive features."""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
import unittest

from hetnet import Scenario, Simulator
from hetnet.attestation import sign_cu_report, verify_cu_report
from hetnet.cli import export_run
from hetnet.consensus import OBSERVER_DOMAINS, consensus_from_votes, sign_vote
from hetnet.probes import ProbeSampler
from hetnet.probe_validation import probe_study
from hetnet.zonal import zonal_features

ROOT = b"test-observer-root"
NODE, NONCE, TIME = "amf5", "cu-1500", 1500


def vote(who: str, count: int):
    counts = {"MAP": count}
    return {
        "observer": who, "domain": OBSERVER_DOMAINS[who],
        "node": NODE, "nonce": NONCE, "at_ms": TIME,
        "counts": counts, "delivered": True,
        "mac": sign_vote(ROOT, who, NODE, NONCE, TIME, counts),
    }


class TolerantQuorumTests(unittest.TestCase):
    def test_unique_close_pair_succeeds_at_small_tolerance(self):
        batch = [vote("tap-legacy", 10), vote("tap-epc", 11),
                 vote("tap-5gc", 30)]
        strict = consensus_from_votes(batch, ROOT, NODE, NONCE, TIME)
        self.assertFalse(strict["quorum"])
        relaxed = consensus_from_votes(
            batch, ROOT, NODE, NONCE, TIME, max_count_delta=2)
        self.assertTrue(relaxed["quorum"])
        self.assertEqual(relaxed["support_count"], 2)
        self.assertEqual(relaxed["outlier_observers"], ["tap-5gc"])
        self.assertIn(relaxed["consensus_counts"]["MAP"], (10, 11))

    def test_ambiguous_overlapping_pairs_refuse_quorum(self):
        batch = [vote("tap-legacy", 0), vote("tap-epc", 2),
                 vote("tap-5gc", 4)]
        result = consensus_from_votes(
            batch, ROOT, NODE, NONCE, TIME, max_count_delta=2)
        self.assertFalse(result["quorum"])
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNone(result["consensus_counts"])
        self.assertEqual(result["support_count"], 0)

    def test_colluding_two_votes_still_deceive_relaxed_majority(self):
        batch = [vote("tap-legacy", 10), vote("tap-epc", 16),
                 vote("tap-5gc", 16)]
        result = consensus_from_votes(
            batch, ROOT, NODE, NONCE, TIME, max_count_delta=2)
        self.assertTrue(result["quorum"])
        self.assertEqual(result["consensus_counts"], {"MAP": 16})
        self.assertEqual(result["outlier_observers"], ["tap-legacy"])

    def test_invalid_tolerance(self):
        with self.assertRaises(ValueError):
            consensus_from_votes([], ROOT, NODE, NONCE, TIME,
                                 max_count_delta=-1)
        with self.assertRaises(ValueError):
            consensus_from_votes([], ROOT, NODE, NONCE, TIME,
                                 max_count_delta=True)


class ProbeSamplingTests(unittest.TestCase):
    def test_default_exact_and_independent_reproducible_noise(self):
        clean = ProbeSampler(42)
        counts = {"MAP": 120, "SIP": 75}
        self.assertEqual(clean.observe(NODE, "tap-epc", TIME, counts), counts)
        noisy = ProbeSampler(42, .3)
        first = noisy.observe(NODE, "tap-epc", TIME, counts)
        self.assertEqual(first, noisy.observe(NODE, "tap-epc", TIME, counts))
        self.assertNotEqual(first,
                            noisy.observe(NODE, "tap-legacy", TIME, counts))
        self.assertTrue(all(0 <= first[k] <= counts[k] for k in counts))

    def test_probe_order_and_seed_are_stable(self):
        counts = {"a": 20, "b": 100}
        sampler = ProbeSampler(12, .15)
        a = sampler.observe("msc2", "tap-legacy", 1200, counts)
        sampler.observe("msc2", "tap-epc", 1200, counts)
        self.assertEqual(a, sampler.observe("msc2", "tap-legacy", 1200, counts))
        self.assertEqual(a, ProbeSampler(12, .15).observe(
            "msc2", "tap-legacy", 1200, dict(reversed(list(counts.items())))))

    def test_probe_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            ProbeSampler(1, -.1)
        with self.assertRaises(ValueError):
            ProbeSampler(1, .8)
        with self.assertRaises(ValueError):
            ProbeSampler(1, .1).observe("dra", "unknown", 1, {})


class CUAttestationTests(unittest.TestCase):
    def test_signed_report_includes_node_and_epoch(self):
        secret = b"research-root-key"
        sig = sign_cu_report(secret, "amf5", NONCE, {"x": 2})
        self.assertTrue(verify_cu_report(secret, "amf5", NONCE, {"x": 2}, sig))
        self.assertFalse(verify_cu_report(secret, "dra", NONCE, {"x": 2}, sig))
        self.assertFalse(verify_cu_report(secret, "amf5", "old", {"x": 2}, sig))
        self.assertFalse(verify_cu_report(secret, "amf5", NONCE, {"x": 3}, sig))

    def test_forged_json_report_and_mac_flag_get_rejected(self):
        sim = Simulator(Scenario(duration_s=18, subscribers=8,
                                 inject_attacks=False, node_case="none"))
        original = sim.run()
        payload = copy.deepcopy(original["events"])
        changed = next(x for x in payload if x["protocol"] == "CU"
                       and x["source"] == "amf5")
        changed["detail"]["reported_counts"]["forged"] = 88
        changed["detail"]["mac_valid"] = True  # untrusted cached boolean
        verified = zonal_features(
            payload, observer_root_key=sim._observer_key,
            cu_root_key=sim._cu_key)
        self.assertEqual(
            verified["exclusions"]["invalid_cu_signature"], 1)
        self.assertEqual(
            verified["summary"]["node_features"],
            original["zonal_evidence"]["summary"]["node_features"] - 1)
        self.assertTrue(all(r["excess_ratio"] == 0
                            for r in verified["features"]))


class ZoneFeaturesTests(unittest.TestCase):
    def test_clean_zone_has_stable_zero_residuals_and_tied_rank(self):
        result = Simulator(Scenario(
            duration_s=18, subscribers=8,
            inject_attacks=False, node_case="none")).run()
        zone = result["zonal_evidence"]
        self.assertEqual(zone["summary"]["epochs"], 11)
        self.assertEqual(zone["summary"]["node_features"], 66)
        self.assertTrue(all(x["excess_ratio"] == 0
                            and x["zone_rank_desc"] == 1
                            and x["zone_zscore"] == 0
                            and x["zone_robust_zscore"] == 0
                            for x in zone["features"]))
        self.assertTrue(all(x["peer_statistics_valid"]
                            for x in zone["epochs"]))

    def test_compromised_nodes_stand_out_in_zonal_residual(self):
        compromised = {"msc2", "amf5"}
        result = Simulator(Scenario(
            duration_s=18, subscribers=8,
            inject_attacks=False, node_case="none",
            report_fault_nodes=tuple(sorted(compromised)))).run()
        rows = [r for r in result["zonal_evidence"]["features"]
                if r["time_ms"] >= 13500]
        self.assertTrue(rows)
        for row in rows:
            if row["node"] in compromised:
                self.assertGreater(row["excess_ratio"], 0)
                self.assertGreater(row["delta_from_zone_median"], 0)
                self.assertGreater(row["zone_zscore"], 0)
            else:
                self.assertEqual(row["excess_ratio"], 0)

    def test_zone_does_not_impute_missing_quorum_as_normal(self):
        result = Simulator(Scenario(
            duration_s=18, subscribers=8,
            inject_attacks=False, node_case="none",
            shared_zone_case="epc_5gc_outage")).run()
        zone = result["zonal_evidence"]
        lost = [row for row in zone["epochs"] if row["time_ms"] >= 13500]
        self.assertEqual(len(lost), 3)
        self.assertTrue(all(r["valid_nodes"] == 0
                            and r["median_excess_ratio"] is None
                            for r in lost))
        self.assertGreater(zone["exclusions"]["observer_quorum_unavailable"], 0)

    def test_tolerant_probe_run_is_json_roundtrip_safe(self):
        result = Simulator(Scenario(
            duration_s=18, subscribers=8,
            inject_attacks=False, node_case="none",
            observer_capture_miss=.05, quorum_max_count_delta=2)).run()
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(result["zonal_evidence"]["quorum_tolerance"], 2)
        with tempfile.TemporaryDirectory() as folder:
            export_run(result, Path(folder))
            self.assertEqual(
                json.loads((Path(folder) / "result.json").read_text()), result)
            self.assertTrue((Path(folder) / "zonal_evidence.json").exists())

    def test_invalid_zonal_config(self):
        with self.assertRaises(ValueError):
            Scenario(quorum_max_count_delta=-1)
        with self.assertRaises(ValueError):
            Scenario(observer_capture_miss=.9)
        with self.assertRaises(ValueError):
            zonal_features([], observer_root_key=b"o", cu_root_key=b"c",
                           min_peers=1)


class ProbeStudyTests(unittest.TestCase):
    def test_small_multi_seed_sensitivity_and_labels(self):
        result = probe_study(
            seeds=(42, 43), capture_miss_rates=(0.0, .05),
            tolerances=(0, 2), cohorts=("none", "legacy_5g"),
        )
        self.assertEqual(len(result["runs"]), 16)
        self.assertEqual(len(result["node_records"]), 16 * 6)
        self.assertEqual(len(result["groups"]), 4)
        baseline = next(x for x in result["groups"]
                        if x["capture_miss_rate"] == 0
                        and x["tolerance"] == 0)
        self.assertEqual((baseline["tp"], baseline["fp"], baseline["fn"]),
                         (4, 0, 0))
        self.assertGreater(baseline["mean_zonal_features"], 0)

    def test_sensitivity_validation_rejects_unknown_cohorts(self):
        with self.assertRaises(ValueError):
            probe_study(cohorts=("invented",))
        with self.assertRaises(ValueError):
            probe_study(tolerances=(True,))


if __name__ == "__main__":
    unittest.main()
