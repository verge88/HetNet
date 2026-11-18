"""Stage 8: strict no-PII aggregates, source isolation, reproducible holdout."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from hetnet.cli import main
from hetnet.external_aggregates import (
    MAX_FILE_BYTES, evaluate_holdout, fingerprint, fit_capture_rates,
    load_dataset, run_external_eval, source_summary, validate_dataset,
)

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "external"
ALPHA = FIXTURES / "lab_training_alpha.json"
BETA = FIXTURES / "lab_training_beta.json"
GAMMA = FIXTURES / "lab_holdout_gamma.json"


def minimal(source="alpha_source", miss=3):
    rows = []
    for observer in ("tap-legacy", "tap-epc", "tap-5gc"):
        rows.append({
            "observer": observer, "node": "msc2",
            "operation_class": "MAP", "interval_index": 0,
            "reference_count": 100, "observed_count": 100 - miss,
        })
    return {
        "schema_version": 1, "source_id": source,
        "provenance": "synthetic", "reference_basis": "synthetic_truth",
        "measurements": rows,
    }


class SchemaSecurityTests(unittest.TestCase):
    def test_synthetic_fixture_loading_and_source_fingerprints(self):
        alpha, beta, gamma = [load_dataset(p) for p in (ALPHA, BETA, GAMMA)]
        self.assertEqual(len(alpha["measurements"]), 36)
        self.assertEqual(len({x["source_id"] for x in (alpha, beta, gamma)}), 3)
        self.assertEqual(source_summary(alpha)["observer_count"], 3)
        self.assertEqual(source_summary(alpha)["node_count"], 3)
        self.assertEqual(len(fingerprint(alpha)), 64)
        changed_order = copy.deepcopy(alpha)
        changed_order["measurements"].reverse()
        self.assertEqual(fingerprint(changed_order), fingerprint(alpha))

    def test_rejects_individual_identifier_and_unknown_payload_fields(self):
        for field in ("imsi", "supi", "phone", "raw_packet", "subscriber_id"):
            with self.subTest(field=field):
                row = minimal()
                row["measurements"][0][field] = "unacceptable"
                with self.assertRaises(ValueError):
                    validate_dataset(row)
        root = minimal()
        root["customer_metadata"] = {"phone": "123"}
        with self.assertRaises(ValueError):
            validate_dataset(root)

    def test_rejects_invalid_source_slug_and_provenance(self):
        for slug in ("ab", "Company/Site", "évaluation", "has space", "x"*100):
            with self.subTest(slug=slug):
                item = minimal()
                item["source_id"] = slug
                with self.assertRaises(ValueError):
                    validate_dataset(item)
        for origin, basis in (
            ("synthetic", "claimed_independent_aggregate"),
            ("supplied_aggregate", "synthetic_truth"),
            ("invented", "synthetic_truth"),
        ):
            row = minimal()
            row["provenance"] = origin
            row["reference_basis"] = basis
            with self.assertRaises(ValueError):
                validate_dataset(row)

    def test_rejects_duplicate_snapshot_and_ambiguous_intervals(self):
        item = minimal()
        item["measurements"].append(copy.deepcopy(item["measurements"][0]))
        with self.assertRaises(ValueError):
            validate_dataset(item)
        item = minimal()
        item["measurements"][0]["interval_index"] = -1
        with self.assertRaises(ValueError):
            validate_dataset(item)

    def test_rejects_unhashable_field_values(self):
        candidates = (("provenance", ["synthetic"]),
                      ("observer", ["tap-legacy"]),
                      ("operation_class", ["MAP"]))
        for field, value in candidates:
            with self.subTest(field=field):
                item = minimal()
                if field == "provenance":
                    item[field] = value
                else:
                    item["measurements"][0][field] = value
                with self.assertRaises(ValueError):
                    validate_dataset(item)

    def test_duplicate_json_keys_are_rejected_before_validation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bad.json"
            path.write_text('{"schema_version":1,"schema_version":1}',
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                load_dataset(path)

    def test_rejects_small_groups_and_invalid_counts(self):
        for field, value in (
            ("reference_count", 19), ("reference_count", True),
            ("reference_count", 1_000_001), ("observed_count", -1),
            ("observed_count", 101), ("observed_count", True),
            ("interval_index", 1.3),
        ):
            with self.subTest(field=field, value=value):
                item = minimal()
                item["measurements"][0][field] = value
                with self.assertRaises(ValueError):
                    validate_dataset(item)

    def test_rejects_unknown_sensor_node_and_class(self):
        for field, value in (
            ("observer", "tap-unknown"), ("node", "private-operator-node"),
            ("operation_class", "IMSI"),
        ):
            item = minimal()
            item["measurements"][0][field] = value
            with self.assertRaises(ValueError):
                validate_dataset(item)

    def test_rejects_missing_rows_and_schema_version(self):
        item = minimal()
        item["measurements"] = []
        with self.assertRaises(ValueError):
            validate_dataset(item)
        item = minimal()
        item["schema_version"] = True
        with self.assertRaises(ValueError):
            validate_dataset(item)

    def test_file_size_limit_and_valid_zero_observed(self):
        example = minimal()
        for item in example["measurements"]:
            item["observed_count"] = 0
        self.assertEqual(load_dataset(self._dump(example))["measurements"][0]
                         ["observed_count"], 0)
        with tempfile.TemporaryDirectory() as root:
            large = Path(root) / "too_large.json"
            large.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                load_dataset(large)

    def _dump(self, item):
        # Local temp path survives within the test suite session.
        if not hasattr(self, "_temp"):
            self._temp = tempfile.TemporaryDirectory()
            self.addCleanup(self._temp.cleanup)
        result = Path(self._temp.name) / "aggregate.json"
        result.write_text(json.dumps(item), encoding="utf-8")
        return result

    def test_declared_external_provenance_not_presented_as_verified(self):
        item = minimal()
        item["source_id"] = "supplied_one"
        item["provenance"] = "supplied_aggregate"
        item["reference_basis"] = "claimed_independent_aggregate"
        self.assertEqual(
            validate_dataset(item)["reference_basis"],
            "claimed_independent_aggregate")


class CalibrationTests(unittest.TestCase):
    def test_count_weighted_training_and_no_holdout_fit(self):
        fitted = fit_capture_rates([load_dataset(ALPHA), load_dataset(BETA)])
        self.assertEqual(fitted["training_source_ids"], [
            "lab_training_alpha", "lab_training_beta"])
        totals = [r for data in (load_dataset(ALPHA), load_dataset(BETA))
                  for r in data["measurements"] if r["observer"] == "tap-epc"]
        expected = (sum(r["reference_count"] - r["observed_count"]
                        for r in totals) / sum(r["reference_count"]
                                             for r in totals))
        self.assertAlmostEqual(
            fitted["per_observer"]["tap-epc"]["miss_probability"], expected)
        self.assertEqual(len(fitted["per_observer"]), 3)
        self.assertEqual(fitted["per_observer"]["tap-epc"]["training_rows"], 24)

    def test_holdout_source_separation(self):
        alpha = load_dataset(ALPHA)
        calibration = fit_capture_rates([alpha])
        with self.assertRaises(ValueError):
            evaluate_holdout(calibration, alpha)
        with self.assertRaises(ValueError):
            fit_capture_rates([alpha, copy.deepcopy(alpha)])

    def test_requires_all_three_sensors_in_training(self):
        data = minimal()
        data["measurements"] = data["measurements"][:2]
        with self.assertRaises(ValueError):
            fit_capture_rates([data])
        with self.assertRaises(ValueError):
            fit_capture_rates([])

    def test_holdout_metrics_and_no_security_rate_claims(self):
        report = run_external_eval([ALPHA, BETA], GAMMA)
        hold = report["holdout"]
        self.assertEqual(hold["holdout_source"]["source_id"],
                         "lab_holdout_gamma")
        self.assertEqual(hold["overall"]["rows"], 36)
        self.assertEqual(hold["coverage"]["complete_three_observer_windows"], 12)
        self.assertEqual(hold["coverage"]["all_windows"], 12)
        self.assertEqual(hold["per_observer"]["tap-5gc"]["rows"], 12)
        self.assertGreater(hold["overall"]["mae_naive_no_loss"], 0)
        self.assertLess(hold["overall"]["mae_calibrated"],
                        hold["overall"]["mae_naive_no_loss"])
        for forbidden in ("precision", "recall", "fpr", "auc", "measurements"):
            self.assertNotIn(forbidden, json.dumps(report).lower()
                             if forbidden == "measurements" else hold["overall"])
        self.assertTrue(any("No attack labels" in x for x in hold["cannot_infer"]))

    def test_missing_sensor_window_is_reported_as_incomplete(self):
        fit = fit_capture_rates([minimal("train_one")])
        hold = minimal("test_two")
        hold["measurements"] = hold["measurements"][:2]
        metric = evaluate_holdout(fit, hold)
        self.assertEqual(metric["coverage"]["all_windows"], 1)
        self.assertEqual(metric["coverage"]["complete_three_observer_windows"], 0)
        self.assertIsNone(metric["coverage"]["mean_relative_capture_ratio_spread"])

    def test_zero_observation_is_not_omitted(self):
        train = minimal("zero_train", miss=100)
        hold = minimal("zero_test", miss=100)
        fitted = fit_capture_rates([train])
        metric = evaluate_holdout(fitted, hold)
        self.assertEqual(metric["overall"]["mae_calibrated"], 0.0)
        self.assertEqual(metric["overall"]["mae_naive_no_loss"], 100.0)

    def test_report_has_no_raw_rows_or_identifiers(self):
        report = run_external_eval([ALPHA, BETA], GAMMA)
        text = json.dumps(report, sort_keys=True)
        self.assertNotIn('"measurements"', text)
        self.assertNotIn('"reference_count"', text)
        self.assertNotIn('"observed_count"', text)
        self.assertIn('"fingerprint_sha256"', text)
        self.assertIn("Declared source provenance", text)


class CliTests(unittest.TestCase):
    def test_aggregate_audit_and_heldout_cli(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            main(["aggregate-audit", "--input", str(ALPHA)])
        self.assertEqual(json.loads(buffer.getvalue())["rows"], 36)
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "result"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["external-eval", "--train", str(ALPHA), str(BETA),
                      "--holdout", str(GAMMA), "--output", str(out)])
            stored = json.loads((out / "external_eval.json").read_text())
            self.assertEqual(stored["holdout"]["overall"]["rows"], 36)

    def test_cli_rejects_overlap_without_creating_results(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "should_not_exist"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["external-eval", "--train", str(ALPHA),
                          "--holdout", str(ALPHA),
                          "--output", str(destination)])
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
