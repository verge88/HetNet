"""Stage 9: held-out synthetic source evaluation of zonal detectors."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from hetnet.cli import main
from hetnet.fault_domains import MONITORED_NODES
from hetnet.zonal_detection import (
    SourceProfile, TRAIN_PROFILES, TEST_PROFILES, DETECTORS,
    _node_pair_scores, _metrics, fit_zonal_thresholds, heldout_comparison,
)


class TailScoreTests(unittest.TestCase):
    def test_two_consecutive_epochs_required_not_one_spike(self):
        features = [
            {"node": "msc2", "time_ms": 13500, "excess_ratio": .04,
             "delta_from_peer_median": .03},
            {"node": "msc2", "time_ms": 15000, "excess_ratio": .06,
             "delta_from_peer_median": .02},
            {"node": "msc2", "time_ms": 16500, "excess_ratio": .01,
             "delta_from_peer_median": None},
            {"node": "amf5", "time_ms": 13500, "excess_ratio": .90,
             "delta_from_peer_median": .90},
            {"node": "amf5", "time_ms": 16500, "excess_ratio": .90,
             "delta_from_peer_median": .90},
        ]
        scores = _node_pair_scores({"features": features}, start_ms=13500)
        self.assertAlmostEqual(scores["msc2"]["zone_absolute"], .04)
        self.assertAlmostEqual(scores["msc2"]["zone_peer"], .02)
        self.assertIsNone(scores["amf5"]["zone_absolute"])
        self.assertIsNone(scores["amf5"]["zone_peer"])
        self.assertIsNone(scores["sgsn3"]["zone_absolute"])

    def test_pre_window_abnormality_is_not_scored(self):
        score = _node_pair_scores({"features": [
            {"node": "dra", "time_ms": 9000, "excess_ratio": 1.0,
             "delta_from_peer_median": 1.0},
            {"node": "dra", "time_ms": 10500, "excess_ratio": 1.0,
             "delta_from_peer_median": 1.0},
            {"node": "dra", "time_ms": 13500, "excess_ratio": 0.0,
             "delta_from_peer_median": 0.0},
            {"node": "dra", "time_ms": 15000, "excess_ratio": 0.0,
             "delta_from_peer_median": 0.0},
        ]}, start_ms=13500)
        self.assertEqual(score["dra"]["zone_absolute"], 0)
        self.assertEqual(score["dra"]["zone_peer"], 0)

    def test_abstentions_are_not_counted_as_correct_decisions(self):
        records = [
            {"ground_truth": True, "detected": False, "abstained": True},
            {"ground_truth": False, "detected": False, "abstained": True},
            {"ground_truth": False, "detected": False, "abstained": False},
        ]
        summary = _metrics(records)
        self.assertEqual(summary["fn"], 1)
        self.assertEqual(summary["tn"], 2)
        self.assertEqual(summary["abstained"], 2)
        self.assertEqual(summary["abstained_positive"], 1)
        self.assertAlmostEqual(summary["coverage"], 1/3)


class TrainingIsolationTests(unittest.TestCase):
    def test_thresholds_fit_only_clean_training_sources(self):
        model = fit_zonal_thresholds(
            profiles=TRAIN_PROFILES, seeds=(21,), duration_s=18)
        self.assertEqual(set(model["thresholds"]),
                         {"zone_absolute", "zone_peer"})
        self.assertEqual(model["training_seeds"], [21])
        self.assertEqual(
            set(model["training_source_ids"]),
            {"synthetic_fit_nominal", "synthetic_fit_capture"})
        self.assertTrue(all(value > 0 for value in model["thresholds"].values()))
        self.assertTrue(all(row["valid_score_counts"]["zone_absolute"] > 0
                            for row in model["per_source"]))

    def test_training_rejects_non_clean_sources_and_missing_observations(self):
        with self.assertRaises(ValueError):
            fit_zonal_thresholds(profiles=(
                SourceProfile("train_outage", shared_zone_case="all_outage"),),
                seeds=(21,))
        with self.assertRaises(ValueError):
            fit_zonal_thresholds(profiles=(
                SourceProfile("identical"), SourceProfile("identical")),
                seeds=(21,))
        with self.assertRaises(ValueError):
            fit_zonal_thresholds(seeds=(21, 21))
        with self.assertRaises(ValueError):
            fit_zonal_thresholds(duration_s=8, seeds=(21,))

    def test_profile_validation_rejects_malformed_data(self):
        for profile in (
            SourceProfile("ab"),
            SourceProfile("contains space"),
            SourceProfile("invalid/", 0),
            SourceProfile("new_profile", float("nan")),
            SourceProfile("new_profile", -.1),
            SourceProfile("new_profile", 1),
            SourceProfile("new_profile", 0.05, True),
            SourceProfile("new_profile", 0.05, -1),
            SourceProfile("new_profile", 0.05, 1, "invented"),
        ):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                profile.validate()


class HoldoutComparisonTests(unittest.TestCase):
    def study(self):
        return heldout_comparison(
            train_seeds=(21,), test_seeds=(42,),
            cohort_names=("none", "legacy_5g"),
            training_profiles=TRAIN_PROFILES,
            test_profiles=TEST_PROFILES,
        )

    def test_per_source_metrics_counts_and_disjointness(self):
        report = self.study()
        self.assertEqual(report["training"]["training_seeds"], [21])
        self.assertEqual(report["test_seeds"], [42])
        self.assertEqual(len(report["per_source"]), 4*3)
        self.assertEqual(len(report["overall"]), 3)
        self.assertEqual(len(report["records"]), 4*1*2*6*3)
        for summary in report["per_source"]:
            self.assertEqual(summary["samples"], 12)
            self.assertEqual(summary["positive_samples"], 2)
            self.assertEqual(summary["negative_samples"], 10)
            self.assertEqual(
                summary["tp"] + summary["fp"] + summary["fn"] + summary["tn"],
                summary["samples"])
            self.assertTrue(0 <= summary["coverage"] <= 1)
        self.assertEqual(
            set(report["training"]["training_source_ids"]) &
            {source["source_id"] for source in report["test_sources"]}, set())
        self.assertEqual(report["detectors"], list(DETECTORS))

    def test_outage_reduces_coverage_in_all_three_detectors(self):
        report = self.study()
        clean = {s["detector"]: s for s in report["per_source"]
                 if s["source_id"] == "synthetic_holdout_nominal"}
        outage = {s["detector"]: s for s in report["per_source"]
                  if s["source_id"] == "synthetic_holdout_outage"}
        self.assertTrue(all(clean[d]["coverage"] > outage[d]["coverage"]
                            for d in DETECTORS))
        self.assertTrue(all(outage[d]["abstained_positive"] > 0
                            for d in DETECTORS))

    def test_collusion_is_reported_as_failure_not_proof_of_security(self):
        report = self.study()
        collusion = [s for s in report["per_source"]
                     if s["source_id"] == "synthetic_holdout_collusion"]
        self.assertEqual(len(collusion), 3)
        self.assertTrue(all(s["tp"] == 0 for s in collusion))
        self.assertTrue(all(s["fn"] == 2 for s in collusion))
        self.assertTrue(all(s["fp"] > 0 for s in collusion))
        self.assertTrue(any("colluding" in x for x in report["limitations"]))

    def test_clean_thresholds_do_not_change_when_test_sources_change(self):
        common = dict(
            train_seeds=(21,), test_seeds=(42,),
            cohort_names=("none", "legacy_5g"),
            training_profiles=TRAIN_PROFILES)
        first = heldout_comparison(
            **common, test_profiles=(TEST_PROFILES[0],))
        shifted = heldout_comparison(
            **common, test_profiles=(TEST_PROFILES[1],))
        self.assertEqual(first["training"], shifted["training"])

    def test_overlap_and_invalid_source_partition_rejected(self):
        base = dict(
            train_seeds=(21,), test_seeds=(42,),
            cohort_names=("none", "legacy_5g"),
            training_profiles=TRAIN_PROFILES,
            test_profiles=(TEST_PROFILES[0],),
        )
        for replacement in (
            {"test_seeds": (21,)},
            {"test_profiles": (TRAIN_PROFILES[0],)},
            {"cohort_names": ("none",)},
            {"cohort_names": ("legacy_5g",)},
            {"cohort_names": ("other",)},
            {"train_seeds": (21, 21)},
            {"test_seeds": (42, 42)},
        ):
            with self.subTest(replacement=replacement), self.assertRaises(
                    ValueError):
                heldout_comparison(**{**base, **replacement})

    def test_json_does_not_claim_real_operator_independence(self):
        report = heldout_comparison(
            train_seeds=(21,), test_seeds=(42,),
            training_profiles=(TRAIN_PROFILES[0],),
            test_profiles=(TEST_PROFILES[0],),
            cohort_names=("none", "legacy_5g"),
        )
        self.assertEqual(json.loads(json.dumps(report)), report)
        self.assertTrue(any("synthetic" in x.lower()
                            for x in report["limitations"]))
        self.assertTrue(any("physical independence" in x.lower()
                            for x in report["limitations"]))


class CliTests(unittest.TestCase):
    def test_cli_outputs_structured_json(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "comparison"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["zonal-compare", "--duration", "18", "--subscribers", "8",
                      "--train-start-seed", "21", "--train-runs", "1",
                      "--test-start-seed", "42", "--test-runs", "1",
                      "--output", str(target)])
            data = json.loads((target / "zonal_comparison.json").read_text())
            self.assertEqual(len(data["overall"]), 3)
            self.assertEqual(len(data["per_source"]), 12)
            self.assertEqual(data["training"]["training_seeds"], [21])

    def test_cli_rejects_overlapping_seeds_without_export(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "invalid"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["zonal-compare", "--train-start-seed", "42",
                          "--train-runs", "1", "--test-start-seed", "42",
                          "--test-runs", "1", "--output", str(out)])
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
