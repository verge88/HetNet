"""Stage 12: source-bound HMAC aggregate attestation and clock-bin sensitivity."""
from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest

from hetnet.aggregate_attestation import (
    ReplayGuard, TrustedIdentity, create_envelope, evaluate_attested_episodes,
    load_envelope, load_trust_file, run_attested_eval, verify_envelope,
)
from hetnet.cli import main
from hetnet.clock_sensitivity import (
    CLOCK_CASES, clock_sensitivity, shift_interval_bins, validate_offsets,
)
from hetnet.labeled_aggregates import load_labeled
from hetnet.temporal_episodes import load_episodic, evaluate_temporal

ROOT = Path(__file__).resolve().parents[1] / "examples"
TRAIN = [ROOT / "labeled" / f"lab_clean_{x}.json" for x in ("alpha", "beta")]
HOLDOUT = [ROOT / "episodic" / f"episodic_holdout_{x}.json"
           for x in ("alpha", "beta", "gamma")]


def datasets():
    return [load_labeled(p) for p in TRAIN], [load_episodic(p) for p in HOLDOUT]


def signed_inputs():
    trains, holds = datasets()
    identities, signed = {}, []
    for index, data in enumerate([*trains, *holds]):
        secret = secrets.token_bytes(32)
        key = "lab_key_" + str(index)
        identities[key] = TrustedIdentity(
            data["source_id"], data["lineage_id"], secret)
        signed.append(create_envelope(data, key_id=key,
                                      sequence=1, secret=secret))
    return signed[:len(trains)], signed[len(trains):], identities


class AttestationTests(unittest.TestCase):
    def test_valid_v1_and_v2_signatures_are_verified_over_full_payload(self):
        train, holdout, trust = signed_inputs()
        for envelope in [*train, *holdout]:
            d, audit = verify_envelope(envelope, trust)
            self.assertTrue(audit["hmac_verified"])
            self.assertIn("annotations", audit["scope"])
            self.assertEqual(d["source_id"], audit["source_id"])
        self.assertEqual(train[0]["dataset"]["schema_version"], 1)
        self.assertEqual(holdout[0]["dataset"]["schema_version"], 2)

    def test_tampered_report_count_fails_even_if_claimed_good(self):
        train, holdout, trust = signed_inputs()
        corrupted = copy.deepcopy(holdout[0])
        corrupted["dataset"]["measurements"][0]["reported_count"] += 1
        corrupted["dataset"]["measurements"][0]["cu_verified_claim"] = True
        with self.assertRaisesRegex(ValueError, "MAC mismatch"):
            verify_envelope(corrupted, trust)

    def test_tampered_attack_annotation_fails_even_without_measurement_change(self):
        _, holdout, trust = signed_inputs()
        mutated = copy.deepcopy(holdout[0])
        mutated["dataset"]["episodes"][0]["start_interval"] -= 1
        with self.assertRaisesRegex(ValueError, "MAC mismatch"):
            verify_envelope(mutated, trust)

    def test_tampered_source_key_sequence_and_mac_fail_closed(self):
        _, holdout, trust = signed_inputs()
        original = holdout[0]
        tests = [
            ("key_id", "unknown_key"),
            ("key_id", "lab_key_0"),
            ("sequence", original["sequence"] + 1),
            ("sequence", True),
            ("sequence", 0),
            ("mac_sha256", "0" * 64),
            ("mac_sha256", "NOT-HEX"),
            ("envelope_version", 2),
        ]
        for field, value in tests:
            with self.subTest(field=field, value=value):
                copy = dict(original)
                copy[field] = value
                with self.assertRaises(ValueError):
                    verify_envelope(copy, trust)

    def test_untrusted_lineage_rejected_before_mac_acceptance(self):
        train, _, trust = signed_inputs()
        new_data = copy.deepcopy(train[0]["dataset"])
        new_data["lineage_id"] = "lab_another_lineage"
        secret = trust[train[0]["key_id"]].secret
        valid_mac_wrong_policy = create_envelope(
            new_data, key_id=train[0]["key_id"], sequence=1,
            secret=secret)
        with self.assertRaisesRegex(ValueError, "source/lineage"):
            verify_envelope(valid_mac_wrong_policy, trust)

    def test_strict_schema_and_hmac_secret_strength(self):
        train, _, trust = signed_inputs()
        with self.assertRaises(ValueError):
            TrustedIdentity("a_source", "a_lineage", b"short")
        with self.assertRaises(ValueError):
            create_envelope(train[0]["dataset"], key_id="bad ID",
                            sequence=1, secret=secrets.token_bytes(32))
        with self.assertRaises(ValueError):
            create_envelope(train[0]["dataset"], key_id="test_key",
                            sequence=True, secret=secrets.token_bytes(32))
        extra = dict(train[0])
        extra["trusted"] = True
        with self.assertRaises(ValueError):
            verify_envelope(extra, trust)

    def test_replay_guard_monotonic_and_bad_signature_does_not_consume_nonce(self):
        train, _, trust = signed_inputs()
        guard = ReplayGuard()
        first = train[0]
        verify_envelope(first, trust, guard=guard)
        with self.assertRaisesRegex(ValueError, "replay"):
            verify_envelope(first, trust, guard=guard)
        secret = trust[first["key_id"]].secret
        another = create_envelope(
            first["dataset"], key_id=first["key_id"],
            sequence=3, secret=secret)
        forged = dict(another, mac_sha256="f"*64)
        with self.assertRaises(ValueError):
            verify_envelope(forged, trust, guard=guard)
        verify_envelope(another, trust, guard=guard)
        older = create_envelope(
            first["dataset"], key_id=first["key_id"], sequence=2,
            secret=secret)
        with self.assertRaisesRegex(ValueError, "replay"):
            verify_envelope(older, trust, guard=guard)

    def test_full_batch_attestation_preserves_temporal_detector_metrics(self):
        train, holds, trust = signed_inputs()
        signed = evaluate_attested_episodes(train, holds, trust)
        normal = evaluate_temporal(*datasets())
        self.assertEqual(signed["overall"], normal["overall"])
        self.assertEqual(signed["per_source"], normal["per_source"])
        self.assertEqual(len(signed["attestation"]["verified_inputs"]), 5)
        self.assertEqual(signed["attestation"]["hmac_verified_in_this_process"],
                         True)
        exported = json.dumps(signed)
        self.assertNotIn('"secret_b64"', exported)
        self.assertNotIn('"secret"', exported)
        self.assertNotIn('"measurements"', exported)
        self.assertNotIn('"episodes"', exported)

    def test_batch_fails_before_computing_metrics_when_one_mac_invalid(self):
        train, holds, trust = signed_inputs()
        tampered = copy.deepcopy(holds)
        tampered[-1]["dataset"]["measurements"][0]["reference_count"] += 1
        with self.assertRaises(ValueError):
            evaluate_attested_episodes(train, tampered, trust)

    def test_batch_rejects_duplicate_sequence_and_wrong_partition(self):
        train, holds, trust = signed_inputs()
        with self.assertRaises(ValueError):
            evaluate_attested_episodes(train + train[:1], holds, trust)
        with self.assertRaises(ValueError):
            evaluate_attested_episodes(holds, train, trust)

    def _write_trust(self, root: Path, identities: dict, *, mode: int = 0o600):
        path = root / "trust_private.json"
        payload = {
            "schema_version": 1,
            "identities": [
                {"key_id": key, "source_id": identity.source_id,
                 "lineage_id": identity.lineage_id,
                 "secret_b64": base64.b64encode(identity.secret).decode()}
                for key, identity in identities.items()
            ],
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_trust_policy_kept_private_and_has_no_duplicate_keys(self):
        train, holds, identities = signed_inputs()
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            path = self._write_trust(folder, identities)
            parsed = load_trust_file(path)
            self.assertEqual(set(parsed), set(identities))
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "0600"):
                    load_trust_file(path)
                path.chmod(0o600)
            repeated = {
                "schema_version": 1,
                "identities": [
                    {"key_id": "dup_one", "source_id": "source_one",
                     "lineage_id": "lineage_one",
                     "secret_b64": base64.b64encode(
                         secrets.token_bytes(32)).decode()},
                ],
            }
            repeated["identities"].append({
                **repeated["identities"][0], "key_id": "dup_two",
            })
            path.write_text(json.dumps(repeated), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_trust_file(path)

    def test_local_envelope_parsing_rejects_duplicate_json_headers(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "evil.json"
            p.write_text('{"envelope_version":1,"envelope_version":2}',
                         encoding="utf-8")
            with self.assertRaises(ValueError):
                load_envelope(p)
            p.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_envelope(p)

    def test_attested_cli_with_private_ephemeral_keys_in_temp_dir(self):
        train, holds, identities = signed_inputs()
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            policy = self._write_trust(folder, identities)
            trainfiles, holdfiles = [], []
            for i, env in enumerate(train + holds):
                path = folder / ("aggregate_" + str(i) + ".json")
                path.write_text(json.dumps(env), encoding="utf-8")
                (trainfiles if i < len(train) else holdfiles).append(path)
            output = folder / "result"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["attested-episode-eval", "--train",
                      *(str(p) for p in trainfiles),
                      "--holdout", *(str(p) for p in holdfiles),
                      "--trust-config", str(policy), "--output", str(output)])
            result = json.loads(
                (output / "attested_episode_comparison.json").read_text())
            self.assertTrue(result["attestation"]["hmac_verified_in_this_process"])
            self.assertEqual(result["overall"][0]["attack_episodes"], 6)

    def test_ephemeral_self_attested_demo_cannot_be_mistaken_for_external(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "demo"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["attestation-demo", "--output", str(out)])
            report = json.loads((out / "attestation_demo.json").read_text())
            self.assertTrue(report["attestation"]["self_signed_synthetic_demo"])
            self.assertNotIn('"mac_sha256"', json.dumps(report))
            self.assertNotIn('"secret_b64"', json.dumps(report))


class ClockBinTests(unittest.TestCase):
    def test_zero_offset_is_identity_without_mutation(self):
        _, sources = datasets()
        original = copy.deepcopy(sources[0])
        changed, details = shift_interval_bins(sources[0], {})
        self.assertEqual(changed, original)
        self.assertEqual(sources[0], original)
        self.assertEqual(details["dropped_rows"], 0)

    def test_offset_boundary_drops_rows_and_does_not_edit_labels(self):
        _, sources = datasets()
        source = sources[0]
        shifted, report = shift_interval_bins(source, {"msc2": 2, "amf5": -2})
        self.assertEqual(shifted["episodes"], source["episodes"])
        self.assertEqual(report["dropped_rows"], 4)
        self.assertEqual(report["retained_rows"], len(source["measurements"]) - 4)
        self.assertEqual(shifted["source_id"], source["source_id"])

    def test_invalid_offsets_rejected(self):
        for offset in (
            {"msc2": True}, {"msc2": 3}, {"amf5": -3},
            {"not_a_node": 1}, {1: 1}, {"mme4": 1.0}
        ):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                validate_offsets(offset)

    def test_clock_study_uses_same_training_thresholds_for_all_cases(self):
        train, holds = datasets()
        result = clock_sensitivity(train, holds)
        self.assertEqual(len(result["cases"]), len(CLOCK_CASES))
        for scenario in result["cases"]:
            self.assertEqual(len(scenario["overall"]), 3)
            self.assertEqual(len(scenario["per_source"]), 9)
            for measure in scenario["overall"]:
                self.assertTrue(0 <= measure["pair_coverage"] <= 1)
                self.assertEqual(measure["attack_episodes"], 6)
        baseline = evaluate_temporal(train, holds)
        aligned = result["cases"][0]
        self.assertEqual(aligned["case"], "aligned")
        self.assertEqual(aligned["overall"], baseline["overall"])
        self.assertEqual(result["training"], baseline["training"])

    def test_repeated_study_is_deterministic_and_reports_coverage_loss(self):
        train, holds = datasets()
        cases = {"aligned": {}, "test_offset": {"msc2": 2, "amf5": -2}}
        a = clock_sensitivity(train, holds, cases=cases)
        b = clock_sensitivity(train, holds, cases=cases)
        self.assertEqual(a, b)
        perturbed = a["cases"][1]
        self.assertGreater(
            sum(row["dropped_rows"] for row in perturbed["per_source_coverage"]),
            0)
        self.assertLess(
            perturbed["overall"][0]["pair_coverage"],
            a["cases"][0]["overall"][0]["pair_coverage"])

    def test_changing_episode_annotations_does_not_change_shifted_measurements(self):
        _, holds = datasets()
        modified = copy.deepcopy(holds[0])
        modified["episodes"] = []
        shifted_a, _ = shift_interval_bins(
            holds[0], {"msc2": 1, "amf5": -1})
        shifted_b, _ = shift_interval_bins(
            modified, {"msc2": 1, "amf5": -1})
        self.assertEqual(shifted_a["measurements"], shifted_b["measurements"])

    def test_clock_cli_export_has_no_node_rows_or_attack_spans(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "clock_results"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["clock-study", "--train", *map(str, TRAIN),
                      "--holdout", *map(str, HOLDOUT), "--output", str(path)])
            data = json.loads((path / "clock_study.json").read_text())
            self.assertEqual(len(data["cases"]), 4)
            exported = json.dumps(data)
            self.assertNotIn('"measurements"', exported)
            self.assertNotIn('"episodes"', exported)
            self.assertNotIn('"reported_count"', exported)


if __name__ == "__main__":
    unittest.main()
