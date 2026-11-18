"""Stage 10: honest labeled-aggregate evaluation without raw subscriber data."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from hetnet.cli import main
from hetnet.labeled_aggregates import (
    DETECTORS, audit_labeled, aggregate_features, evaluate_labeled,
    fit_thresholds, load_labeled, run_labeled_eval, validate_labeled,
)

ROOT = Path(__file__).resolve().parents[1] / "examples" / "labeled"
ALPHA = ROOT / "lab_clean_alpha.json"
BETA = ROOT / "lab_clean_beta.json"
GAMMA = ROOT / "lab_holdout_gamma.json"
DELTA = ROOT / "lab_holdout_delta.json"


def samples():
    return [load_labeled(path) for path in (ALPHA, BETA, GAMMA, DELTA)]


class InputSchemaTests(unittest.TestCase):
    def test_example_fixtures_strict_and_consistently_annotated(self):
        clean_a, clean_b, attacked, degraded = samples()
        self.assertEqual(len(clean_a["measurements"]), 36)
        self.assertEqual(len(clean_a["labels"]), 6)
        self.assertTrue(all(not x["attack_label"] for x in clean_a["labels"]))
        self.assertEqual(sum(x["attack_label"] for x in attacked["labels"]), 2)
        self.assertEqual(sum(x["attack_label"] for x in degraded["labels"]), 2)
        self.assertEqual(audit_labeled(clean_b)["relative_intervals"], 6)

    def test_rejects_personal_fields_and_unapproved_keys(self):
        source = samples()[0]
        for name in ("imsi", "supi", "msisdn", "phone_number", "ip", "payload"):
            with self.subTest(field=name):
                mutated = copy.deepcopy(source)
                mutated["measurements"][0][name] = "sensitive"
                with self.assertRaises(ValueError):
                    validate_labeled(mutated)
        mutated = copy.deepcopy(source)
        mutated["subscriber_id"] = "not allowed"
        with self.assertRaises(ValueError):
            validate_labeled(mutated)

    def test_annotation_must_be_boolean_and_complete(self):
        source = samples()[0]
        for row in (
            {"node": "msc2", "attack_label": 0},
            {"node": "msc2", "attack_label": "false"},
            {"node": "not-an-operator-node", "attack_label": False},
        ):
            mutated = copy.deepcopy(source)
            mutated["labels"][0] = row
            with self.assertRaises(ValueError):
                validate_labeled(mutated)
        mutated = copy.deepcopy(source)
        mutated["labels"].pop()
        with self.assertRaises(ValueError):
            validate_labeled(mutated)

    def test_rejects_invalid_provenance_pair_and_non_slug_lineage(self):
        source = samples()[0]
        for key, value in (
            ("provenance", "unknown"),
            ("annotation_basis", "expert_review_claimed"),
            ("source_id", "personal name"),
            ("lineage_id", "place/site/1"),
            ("source_id", []),
        ):
            mutated = copy.deepcopy(source)
            mutated[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_labeled(mutated)
        claimed = copy.deepcopy(source)
        claimed["provenance"] = "supplied_aggregate"
        claimed["annotation_basis"] = "expert_review_claimed"
        self.assertEqual(validate_labeled(claimed)["provenance"],
                         "supplied_aggregate")

    def test_duplicate_measurements_and_bad_counter_types(self):
        source = samples()[0]
        mutated = copy.deepcopy(source)
        mutated["measurements"].append(copy.deepcopy(mutated["measurements"][0]))
        with self.assertRaises(ValueError):
            validate_labeled(mutated)
        for key, value in (
            ("reference_count", True), ("reported_count", -1),
            ("reported_count", 1_000_001), ("interval_index", 1.3),
            ("cu_verified_claim", 1), ("quorum_verified_claim", None),
        ):
            mutated = copy.deepcopy(source)
            mutated["measurements"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_labeled(mutated)

    def test_json_duplicate_fields_nan_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bad.json"
            path.write_text('{"schema_version":1,"schema_version":2}',
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                load_labeled(path)
            path.write_text('{"count":NaN}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_labeled(path)
            path.write_bytes(b"_" * (1_048_576 + 1))
            with self.assertRaises(ValueError):
                load_labeled(path)

    def test_relative_interval_and_size_guards(self):
        source = samples()[0]
        mutated = copy.deepcopy(source)
        mutated["measurements"][0]["interval_index"] = -1
        with self.assertRaises(ValueError):
            validate_labeled(mutated)
        mutated = copy.deepcopy(source)
        mutated["measurements"][0]["reference_count"] = 19
        with self.assertRaises(ValueError):
            validate_labeled(mutated)

    def test_audit_has_no_raw_labels_or_measurements(self):
        audit = audit_labeled(samples()[0])
        text = json.dumps(audit)
        for secret in ('"measurements"', '"attack_label"',
                       '"reference_count"', '"reported_count"'):
            self.assertNotIn(secret, text)
        self.assertEqual(len(audit["measurement_fingerprint_sha256"]), 64)
        self.assertIn("not externally verified", audit["warning"])


class DetectionTests(unittest.TestCase):
    def test_projections_ignore_attack_labels_and_source_ids(self):
        source = samples()[2]
        prior = aggregate_features(source)
        swapped = copy.deepcopy(source)
        swapped["source_id"] = "new_claimed_name"
        swapped["lineage_id"] = "new_claimed_lineage"
        for row in swapped["labels"]:
            row["attack_label"] = not row["attack_label"]
        self.assertEqual(prior, aggregate_features(swapped))

    def test_consecutive_nonadjacent_or_missing_evidence_abstains(self):
        source = samples()[2]
        with_gaps = copy.deepcopy(source)
        for row in with_gaps["measurements"]:
            if row["node"] == "amf5" and row["interval_index"] % 2:
                row["quorum_verified_claim"] = False
        self.assertIsNone(aggregate_features(with_gaps)["amf5"]
                          ["cu_claimed_baseline"])
        self.assertIsNone(aggregate_features(with_gaps)["amf5"]
                          ["zone_absolute"])

    def test_peer_scores_need_at_least_two_other_valid_nodes(self):
        source = samples()[2]
        reduced = copy.deepcopy(source)
        for row in reduced["measurements"]:
            if row["node"] not in ("msc2", "amf5"):
                row["cu_verified_claim"] = False
        scored = aggregate_features(reduced)
        self.assertIsNone(scored["msc2"]["zone_peer"])
        self.assertIsNotNone(scored["msc2"]["zone_absolute"])

    def test_normal_only_training_refuses_positive_labels(self):
        a, b, gamma, _ = samples()
        with self.assertRaises(ValueError):
            fit_thresholds([a, gamma])
        fit = fit_thresholds([a, b])
        self.assertTrue(fit["thresholds"]["zone_absolute"] >= 1e-12)
        self.assertTrue(fit["thresholds"]["zone_peer"] >= 1e-12)
        self.assertEqual(fit["train_score_counts"]["zone_peer"], 12)

    def test_train_and_holdout_lineage_are_disjoint(self):
        a, b, gamma, _ = samples()
        report = evaluate_labeled([a, b], [gamma])
        self.assertEqual(set(report["training"]["train_source_ids"]),
                         {"lab_clean_alpha", "lab_clean_beta"})
        repeat = copy.deepcopy(gamma)
        repeat["lineage_id"] = a["lineage_id"]
        with self.assertRaises(ValueError):
            evaluate_labeled([a, b], [repeat])
        repeat = copy.deepcopy(gamma)
        repeat["source_id"] = a["source_id"]
        with self.assertRaises(ValueError):
            evaluate_labeled([a, b], [repeat])

    def test_exact_copied_capture_rejected_when_renamed(self):
        a, b, _, _ = samples()
        repeated = copy.deepcopy(a)
        repeated["source_id"] = "renamed_same_capture"
        repeated["lineage_id"] = "renamed_lineage"
        with self.assertRaises(ValueError):
            evaluate_labeled([a, b], [repeated])

    def test_holdout_labels_cannot_change_training_thresholds(self):
        a, b, gamma, _ = samples()
        changed = copy.deepcopy(gamma)
        for label in changed["labels"]:
            label["attack_label"] = not label["attack_label"]
        self.assertEqual(evaluate_labeled([a, b], [gamma])["training"],
                         evaluate_labeled([a, b], [changed])["training"])

    def test_full_heldout_reports_metrics_and_abstention(self):
        report = run_labeled_eval([ALPHA, BETA], [GAMMA, DELTA])
        self.assertEqual(len(report["per_source"]), 6)
        self.assertEqual(len(report["overall"]), 3)
        self.assertEqual({x["detector"] for x in report["overall"]},
                         set(DETECTORS))
        for record in report["per_source"]:
            self.assertEqual(record["samples"], 6)
            self.assertEqual(record["positive_samples"], 2)
            self.assertEqual(record["negative_samples"], 4)
            self.assertEqual(record["samples"],
                             record["decided_samples"] + record["abstained"])
            self.assertEqual(record["decided_samples"],
                             record["tp"] + record["fp"] +
                             record["fn"] + record["tn"])
        degraded = [r for r in report["per_source"]
                    if r["source_id"] == "lab_holdout_delta"]
        self.assertTrue(all(r["abstained_positive"] == 2
                            for r in degraded))
        self.assertTrue(all(r["coverage"] < 1 for r in degraded))
        clean = [r for r in report["per_source"]
                 if r["source_id"] == "lab_holdout_gamma"]
        self.assertTrue(all(r["tp"] == 2 for r in clean))
        distorted = {r["detector"]: r for r in degraded}
        self.assertEqual(distorted["cu_claimed_baseline"]["fp"], 3)
        self.assertEqual(distorted["zone_absolute"]["fp"], 3)
        self.assertEqual(distorted["zone_peer"]["fp"], 0)
        self.assertEqual(distorted["zone_peer"]["tn"], 3)

    def test_export_omits_individual_rows_and_labels(self):
        report = run_labeled_eval([ALPHA, BETA], [GAMMA, DELTA])
        export = json.dumps(report)
        for column in ('"measurements"', '"labels"', '"attack_label"',
                       '"reported_count"', '"reference_count"'):
            self.assertNotIn(column, export)
        self.assertIn("NOT verified", export)
        self.assertEqual(json.loads(export), report)


class CliTests(unittest.TestCase):
    def test_labeled_audit_and_holdout_cli(self):
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            main(["labeled-audit", "--input", str(ALPHA)])
        info = json.loads(stream.getvalue())
        self.assertEqual(info["measurement_rows"], 36)
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "labeled"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["labeled-eval", "--train", str(ALPHA), str(BETA),
                      "--holdout", str(GAMMA), str(DELTA),
                      "--output", str(out)])
            report = json.loads((out / "labeled_comparison.json").read_text())
            self.assertEqual(len(report["per_source"]), 6)

    def test_cli_rejects_overlapping_sources_before_writing_results(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "blocked"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["labeled-eval", "--train", str(ALPHA),
                          "--holdout", str(ALPHA), "--output", str(out)])
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
