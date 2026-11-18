"""Stage 11: causal unknown-onset episode detection with disjoint lineage."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from hetnet.cli import main
from hetnet.labeled_aggregates import load_labeled
from hetnet.temporal_episodes import (
    DETECTORS, audit_episodic, capture_digest, evaluate_temporal,
    load_episodic, run_temporal_eval, scan_alarms, validate_episodic,
)

ROOT = Path(__file__).resolve().parents[1] / "examples"
ALPHA_TRAIN = ROOT / "labeled" / "lab_clean_alpha.json"
BETA_TRAIN = ROOT / "labeled" / "lab_clean_beta.json"
EPISODE_DIR = ROOT / "episodic"
EPISODIC = tuple(EPISODE_DIR / ("episodic_holdout_" + p + ".json")
                 for p in ("alpha", "beta", "gamma"))


def training():
    return [load_labeled(p) for p in (ALPHA_TRAIN, BETA_TRAIN)]


def holdout():
    return [load_episodic(p) for p in EPISODIC]


def fitting():
    return {"zone_absolute": 1e-12, "zone_peer": 1e-12}


class SchemaTests(unittest.TestCase):
    def test_fixtures_have_unknown_onset_intervals(self):
        files = holdout()
        self.assertEqual([len(f["episodes"]) for f in files], [2, 2, 2])
        self.assertTrue(all(len(f["measurements"]) == 72 for f in files))
        self.assertEqual(files[0]["episodes"][0],
                         {"node": "amf5", "start_interval": 8,
                          "end_interval": 11})
        self.assertEqual(audit_episodic(files[1])["annotation_count"], 2)
        self.assertEqual(len(audit_episodic(files[0])
                             ["measurement_fingerprint_sha256"]), 64)

    def test_no_individual_fields_in_data_or_annotations(self):
        item = holdout()[0]
        for field in ("imsi", "supi", "ip_address", "payload", "subscriber"):
            modified = copy.deepcopy(item)
            modified["measurements"][0][field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_episodic(modified)
        modified = copy.deepcopy(item)
        modified["episodes"][0]["subscriber_id"] = "private"
        with self.assertRaises(ValueError):
            validate_episodic(modified)
        modified = copy.deepcopy(item)
        modified["operator_site"] = "private"
        with self.assertRaises(ValueError):
            validate_episodic(modified)

    def test_episode_bounds_validation(self):
        original = holdout()[0]
        variants = (
            {"node": "msc2", "start_interval": 2, "end_interval": 2},
            {"node": "msc2", "start_interval": 2, "end_interval": 1},
            {"node": "msc2", "start_interval": True, "end_interval": 4},
            {"node": "msc2", "start_interval": 3, "end_interval": 13},
            {"node": "missing", "start_interval": 2, "end_interval": 4},
            {"node": "msc2", "start_interval": -1, "end_interval": 2},
        )
        for episode in variants:
            modified = copy.deepcopy(original)
            modified["episodes"] = [episode]
            with self.subTest(episode=episode), self.assertRaises(ValueError):
                validate_episodic(modified)

    def test_overlapping_and_touching_intervals_rejected(self):
        original = holdout()[0]
        for starts in ((2, 4, 3, 8), (2, 4, 4, 8)):
            modified = copy.deepcopy(original)
            modified["episodes"] = [
                {"node": "msc2", "start_interval": starts[0],
                 "end_interval": starts[1]},
                {"node": "msc2", "start_interval": starts[2],
                 "end_interval": starts[3]},
            ]
            with self.assertRaises(ValueError):
                validate_episodic(modified)

    def test_zero_episodes_is_valid_for_external_clean_holdout(self):
        data = holdout()[0]
        data["episodes"] = []
        verified = validate_episodic(data)
        self.assertEqual(verified["episodes"], [])
        report = evaluate_temporal(training(), [verified])
        for row in report["overall"]:
            self.assertEqual(row["attack_episodes"], 0)
            self.assertIsNone(row["episode_recall"])

    def test_provenance_and_lineage_cannot_be_invented_shapes(self):
        original = holdout()[0]
        modifications = (
            ("source_id", "private site/something"),
            ("lineage_id", []),
            ("provenance", "operator_verified"),
            ("annotation_basis", "unverified_expert_review"),
            ("schema_version", 1),
            ("schema_version", True),
        )
        for key, val in modifications:
            d = copy.deepcopy(original)
            d[key] = val
            with self.subTest(key=key, val=val), self.assertRaises(ValueError):
                validate_episodic(d)

    def test_json_duplicate_properties_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "not_valid.json"
            p.write_text('{"schema_version":2,"schema_version":2}',
                         encoding="utf-8")
            with self.assertRaises(ValueError):
                load_episodic(p)
            p.write_text('{"example":Infinity}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_episodic(p)
            p.write_bytes(b"X" * (1_048_576 + 1))
            with self.assertRaises(ValueError):
                load_episodic(p)

    def test_claimed_real_provenance_is_not_verified(self):
        d = holdout()[0]
        d["provenance"] = "supplied_aggregate"
        d["annotation_basis"] = "expert_review_claimed"
        accepted = validate_episodic(d)
        self.assertEqual(accepted["annotation_basis"], "expert_review_claimed")
        self.assertIn("unverified", audit_episodic(accepted)["warning"])


class CausalScannerTests(unittest.TestCase):
    def test_first_alert_is_after_second_attacked_interval(self):
        d = holdout()[0]
        result = scan_alarms(d["measurements"], fitting())
        for detector in DETECTORS:
            alarms = result["alarms"][detector]
            self.assertIn({"node": "msc2", "interval_index": 4}, alarms)
            self.assertIn({"node": "amf5", "interval_index": 9}, alarms)
            self.assertFalse(any(a["node"] == "msc2" and
                                 a["interval_index"] < 4 for a in alarms))

    def test_append_future_data_cannot_change_past_alerts(self):
        d = holdout()[0]
        cutoff = 6
        past = [row for row in d["measurements"]
                if row["interval_index"] <= cutoff]
        first = scan_alarms(past, fitting())
        full = scan_alarms(d["measurements"], fitting())
        for detector in DETECTORS:
            same_past = [a for a in full["alarms"][detector]
                         if a["interval_index"] <= cutoff]
            self.assertEqual(first["alarms"][detector], same_past)

    def test_annotation_changes_do_not_change_detector_alarms(self):
        d = holdout()[1]
        base = scan_alarms(d["measurements"], fitting())
        mutated = copy.deepcopy(d)
        mutated["episodes"] = []
        mutated["source_id"] = "changed_source"
        mutated["lineage_id"] = "changed_lineage"
        self.assertEqual(base, scan_alarms(mutated["measurements"], fitting()))

    def test_single_interval_attack_is_unconfirmable(self):
        d = holdout()[1]
        result = evaluate_temporal(training(), [d])
        for row in result["per_source"]:
            self.assertEqual(row["short_episodes_unconfirmable"], 1)
            self.assertEqual(row["attack_episodes"], 2)
            self.assertLess(row["detected_episodes"], 2)

    def test_shared_benign_counter_bias_creates_fewer_peer_false_alerts(self):
        d = holdout()[1]
        result = evaluate_temporal(training(), [d])
        per = {row["detector"]: row for row in result["per_source"]}
        self.assertGreater(
            per["cu_claimed_baseline"]["false_alerts_outside_episodes"],
            per["zone_peer"]["false_alerts_outside_episodes"])
        self.assertGreater(
            per["zone_absolute"]["false_alerts_outside_episodes"],
            per["zone_peer"]["false_alerts_outside_episodes"])

    def test_quorum_gap_resets_two_interval_confirmation(self):
        d = holdout()[2]
        results = scan_alarms(d["measurements"], fitting())
        for detector in DETECTORS:
            self.assertFalse(any(a["node"] == "sgsn3" for a in
                                 results["alarms"][detector]))
        model = evaluate_temporal(training(), [d])
        for row in model["per_source"]:
            self.assertLess(row["eligible_pairs"], row["total_possible_pairs"])
            self.assertGreater(row["attack_confirmation_opportunities"],
                               row["eligible_attack_confirmation_pairs"])

    def test_strict_threshold_validation(self):
        d = holdout()[0]
        for thresholds in (
            {"zone_absolute": 0},
            {"zone_absolute": 0, "zone_peer": -1},
            {"zone_absolute": 0, "zone_peer": float("nan")},
            {"zone_absolute": 0, "zone_peer": True},
        ):
            with self.subTest(thresholds=thresholds), self.assertRaises(ValueError):
                scan_alarms(d["measurements"], thresholds)

    def test_alarm_output_does_not_include_truth_or_source(self):
        result = scan_alarms(holdout()[0]["measurements"], fitting())
        text = json.dumps(result)
        self.assertNotIn("episode", text)
        self.assertNotIn("source_id", text)
        self.assertNotIn("attack_label", text)


class SplitAndEvaluationTests(unittest.TestCase):
    def test_three_holdouts_and_metrics_are_source_level(self):
        report = evaluate_temporal(training(), holdout())
        self.assertEqual(len(report["per_source"]), 9)
        self.assertEqual(len(report["overall"]), 3)
        self.assertTrue(all(row["attack_episodes"] == 6
                            for row in report["overall"]))
        for row in report["overall"]:
            self.assertEqual(
                row["detected_episodes"] + row["missed_episodes"]
                if "missed_episodes" in row else row["detected_episodes"] +
                (row["attack_episodes"] - row["detected_episodes"]), 6)
            self.assertLessEqual(row["matched_alerts"], row["alerts"])
            self.assertTrue(0 <= row["pair_coverage"] <= 1)
        self.assertEqual(len(report["holdout_sources"]), 3)

    def test_train_holdout_lineage_source_and_exact_capture_overlap_rejected(self):
        train = training()
        d = holdout()[0]
        for field, duplicate in (
            ("source_id", train[0]["source_id"]),
            ("lineage_id", train[1]["lineage_id"]),
        ):
            bad = copy.deepcopy(d)
            bad[field] = duplicate
            with self.subTest(field=field), self.assertRaises(ValueError):
                evaluate_temporal(train, [bad])
        duplicate = copy.deepcopy(d)
        duplicate["source_id"] = "another_source"
        duplicate["lineage_id"] = "another_lineage"
        with self.assertRaises(ValueError):
            evaluate_temporal(train, [d, duplicate])

    def test_train_attack_labels_not_allowed(self):
        train = training()
        train[0]["labels"][0]["attack_label"] = True
        with self.assertRaises(ValueError):
            evaluate_temporal(train, holdout())

    def test_permuting_episode_labels_changes_scores_not_alarms(self):
        train, sources = training(), holdout()
        original = evaluate_temporal(train, sources)
        changed = copy.deepcopy(sources)
        changed[0]["episodes"] = []
        recalc = evaluate_temporal(train, changed)
        self.assertEqual(original["training"], recalc["training"])
        self.assertNotEqual(original["overall"], recalc["overall"])

    def test_no_raw_measurements_or_per_node_annotations_exported(self):
        report = evaluate_temporal(training(), holdout())
        output = json.dumps(report)
        for field in ('"measurements"', '"episodes"', '"node"',
                      '"reference_count"', '"reported_count"'):
            self.assertNotIn(field, output)
        self.assertIn("not verified", output.lower())

    def test_cli_audit_and_eval_roundtrip(self):
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            main(["episode-audit", "--input", str(EPISODIC[0])])
        audit = json.loads(stream.getvalue())
        self.assertEqual(audit["annotation_count"], 2)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "test"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["episode-eval", "--train", str(ALPHA_TRAIN),
                      str(BETA_TRAIN), "--holdout",
                      *map(str, EPISODIC), "--output", str(out)])
            written = json.loads((out / "episode_comparison.json").read_text())
            self.assertEqual(len(written["overall"]), 3)
            self.assertEqual(len(written["holdout_sources"]), 3)

    def test_cli_rejects_leakage_before_creating_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "should_not_exist"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["episode-eval", "--train", str(ALPHA_TRAIN),
                          "--holdout", str(ALPHA_TRAIN),
                          "--output", str(out)])
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
