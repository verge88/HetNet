"""Stage 13: durable SQLite replay, key revocation and safe key-ID rotation."""
from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest

from hetnet.aggregate_attestation import (
    TrustedIdentity, create_envelope,
)
from hetnet.cli import main
from hetnet.durable_attestation import (
    DurableReplayStore, evaluate_durable_episodes,
    run_durable_eval, synthetic_durable_demo,
)
from hetnet.labeled_aggregates import load_labeled
from hetnet.temporal_episodes import load_episodic

ROOT = Path(__file__).resolve().parents[1] / "examples"
TRAIN = [ROOT / "labeled" / ("lab_clean_" + x + ".json")
         for x in ("alpha", "beta")]
TEST = [ROOT / "episodic" / ("episodic_holdout_" + x + ".json")
        for x in ("alpha", "beta", "gamma")]


def signed_sources():
    data = [*[load_labeled(p) for p in TRAIN],
            *[load_episodic(p) for p in TEST]]
    trust = {}
    for index, item in enumerate(data):
        kid = "test_key_" + str(index)
        trust[kid] = TrustedIdentity(
            item["source_id"], item["lineage_id"], secrets.token_bytes(32))
    return data, trust


def envelopes(data, trust, sequence=1, rotated_first=None):
    records = []
    for i, item in enumerate(data):
        kid = "rotated_key_0" if i == 0 and rotated_first else "test_key_" + str(i)
        current = trust[kid]
        records.append(create_envelope(
            item, key_id=kid,
            sequence=1 if i == 0 and rotated_first else sequence,
            secret=current.secret))
    return records[:2], records[2:]


def save_policy(folder, trust, *, mode=0o600):
    path = folder / "trust.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "identities": [
            {"key_id": kid, "source_id": item.source_id,
             "lineage_id": item.lineage_id,
             "secret_b64": base64.b64encode(item.secret).decode("ascii")}
            for kid, item in trust.items()
        ],
    }), encoding="utf-8")
    path.chmod(mode)
    return path


class PersistenceTests(unittest.TestCase):
    def test_accept_then_deny_exact_replay_across_connections(self):
        sources, trust = signed_sources()
        train, holdout = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            db_path = Path(root) / "replay.sqlite3"
            DurableReplayStore(db_path).initialize()
            first = evaluate_durable_episodes(train, holdout, trust, db_path)
            self.assertTrue(first["durable_attestation"]["atomic_batch_committed"])
            self.assertEqual(
                first["durable_attestation"]["verified_envelopes_committed"], 5)
            second = DurableReplayStore(db_path)
            self.assertEqual(len(second.summary()["keys"]), 5)
            with self.assertRaisesRegex(ValueError, "replay"):
                evaluate_durable_episodes(train, holdout, trust, db_path)
            self.assertTrue(all(r["highest_sequence"] == 1 for r in
                                second.summary()["keys"]))
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(db_path.stat().st_mode), 0o600)

    def test_independent_python_process_rejects_replayed_envelope(self):
        sources, trust = signed_sources()
        train, holdout = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            policy = save_policy(folder, trust)
            paths = []
            for i, record in enumerate([*train, *holdout]):
                path = folder / ("aggregate_" + str(i) + ".json")
                path.write_text(json.dumps(record), encoding="utf-8")
                paths.append(path)
            db_path = folder / "persist.sqlite3"
            with contextlib.redirect_stdout(io.StringIO()) as buffer:
                main(["attestation-init-state", "--state-db", str(db_path)])
            self.assertTrue(json.loads(buffer.getvalue())["initialized"])
            args = [
                sys.executable, "-m", "hetnet", "durable-attested-eval",
                "--train", str(paths[0]), str(paths[1]),
                "--holdout", *map(str, paths[2:]),
                "--trust-config", str(policy), "--state-db", str(db_path),
            ]
            first = subprocess.run(
                args + ["--output", str(folder / "first")],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = subprocess.run(
                args + ["--output", str(folder / "should_not_exist")],
                capture_output=True, text=True, timeout=20)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("replay", second.stderr.lower())
            self.assertFalse((folder / "should_not_exist").exists())
            self.assertEqual(len(DurableReplayStore(db_path).summary()["keys"]), 5)

    def test_monotonic_sequence_accepts_fresh_signed_claim_and_rejects_old(self):
        sources, trust = signed_sources()
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            a, b = envelopes(sources, trust, 1)
            evaluate_durable_episodes(a, b, trust, p)
            fresh_a, fresh_b = envelopes(sources, trust, 2)
            evaluate_durable_episodes(fresh_a, fresh_b, trust, p)
            self.assertTrue(all(x["highest_sequence"] == 2 for x in
                                DurableReplayStore(p).summary()["keys"]))
            with self.assertRaises(ValueError):
                evaluate_durable_episodes(a, b, trust, p)

    def test_bad_mac_cannot_create_db_or_consume_sequence(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        forged = copy.deepcopy(b)
        forged[0]["dataset"]["measurements"][0]["reported_count"] += 1
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            with self.assertRaisesRegex(ValueError, "MAC mismatch"):
                evaluate_durable_episodes(a, forged, trust, p)
            self.assertFalse(p.exists())
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            self.assertTrue(p.exists())

    def test_invalid_scientific_training_fails_before_db_commit(self):
        sources, trust = signed_sources()
        sources[0]["labels"][0]["attack_label"] = True
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            with self.assertRaises(ValueError):
                evaluate_durable_episodes(a, b, trust, p)
            self.assertFalse(p.exists())

    def test_revocation_is_durable_and_not_reversible_by_replaying_key(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            store = DurableReplayStore(p)
            self.assertTrue(store.revoke("test_key_0")["revoked"])
            with self.assertRaisesRegex(ValueError, "already revoked"):
                DurableReplayStore(p).revoke("test_key_0")
            new_a, new_b = envelopes(sources, trust, 2)
            with self.assertRaisesRegex(ValueError, "revoked"):
                evaluate_durable_episodes(new_a, new_b, trust, p)
            states = {k["key_id"]: k for k in store.summary()["keys"]}
            self.assertTrue(states["test_key_0"]["revoked"])
            self.assertTrue(all(state["highest_sequence"] == 1 for state
                                in states.values()))

    def test_revoked_batch_rolls_back_other_keys_that_were_processed_first(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            DurableReplayStore(p).revoke("test_key_3")
            fresh_a, fresh_b = envelopes(sources, trust, 2)
            with self.assertRaisesRegex(ValueError, "revoked"):
                evaluate_durable_episodes(fresh_a, fresh_b, trust, p)
            states = DurableReplayStore(p).summary()["keys"]
            self.assertTrue(all(x["highest_sequence"] == 1 for x in states))

    def test_rotation_requires_fresh_key_id_and_secret_and_keeps_revocation(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            DurableReplayStore(p).revoke("test_key_0")
            old = trust.pop("test_key_0")
            trust["rotated_key_0"] = TrustedIdentity(
                old.source_id, old.lineage_id, secrets.token_bytes(32))
            fresh_a, fresh_b = envelopes(sources, trust, 2, rotated_first=True)
            result = evaluate_durable_episodes(fresh_a, fresh_b, trust, p)
            self.assertEqual(result["overall"][0]["attack_episodes"], 6)
            state = {x["key_id"]: x for x in
                     DurableReplayStore(p).summary()["keys"]}
            self.assertTrue(state["test_key_0"]["revoked"])
            self.assertFalse(state["rotated_key_0"]["revoked"])
            self.assertEqual(state["rotated_key_0"]["highest_sequence"], 1)
            self.assertEqual(len(state), 6)

    def test_reuse_of_key_id_with_different_key_material_is_forbidden(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            old = trust["test_key_0"]
            trust["test_key_0"] = TrustedIdentity(
                old.source_id, old.lineage_id, secrets.token_bytes(32))
            fresh_a, fresh_b = envelopes(sources, trust, 2)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                evaluate_durable_episodes(fresh_a, fresh_b, trust, p)
            self.assertEqual(
                DurableReplayStore(p).summary()["keys"][0]["highest_sequence"], 1)

    def test_reuse_key_id_with_different_lineage_is_forbidden(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust, 1)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "db.sqlite3"
            DurableReplayStore(p).initialize()
            evaluate_durable_episodes(a, b, trust, p)
            sources[0]["lineage_id"] = "other_lineage"
            old = trust["test_key_0"]
            trust["test_key_0"] = TrustedIdentity(
                old.source_id, "other_lineage", old.secret)
            fresh_a, fresh_b = envelopes(sources, trust, 2)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                evaluate_durable_episodes(fresh_a, fresh_b, trust, p)

    def test_unknown_revocation_and_state_read_do_not_create_db(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "new.sqlite3"
            for fn in (
                lambda: DurableReplayStore(p).summary(),
                lambda: DurableReplayStore(p).revoke("unknown_key"),
            ):
                with self.assertRaisesRegex(ValueError, "does not exist"):
                    fn()
            self.assertFalse(p.exists())

    def test_deleted_db_fails_closed_and_requires_explicit_reinitialization(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "guard.sqlite3"
            store = DurableReplayStore(path)
            with self.assertRaisesRegex(ValueError, "does not exist"):
                evaluate_durable_episodes(a, b, trust, path)
            store.initialize()
            evaluate_durable_episodes(a, b, trust, path)
            with self.assertRaisesRegex(ValueError, "refusing reset"):
                store.initialize()
            path.unlink()
            with self.assertRaisesRegex(ValueError, "does not exist"):
                evaluate_durable_episodes(a, b, trust, path)
            self.assertFalse(path.exists())

    def test_read_only_not_private_state_and_symlink_are_rejected(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            nonprivate = folder / "unsafe"
            nonprivate.mkdir(mode=0o755)
            if os.name == "posix":
                with self.assertRaisesRegex(ValueError, "0700"):
                    evaluate_durable_episodes(
                        a, b, trust, nonprivate / "state.sqlite3")
            safe = folder / "safe"
            safe.mkdir(mode=0o700)
            db_path = safe / "state.sqlite3"
            DurableReplayStore(db_path).initialize()
            evaluate_durable_episodes(a, b, trust, db_path)
            if os.name == "posix":
                db_path.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "0600"):
                    DurableReplayStore(db_path).summary()
                db_path.chmod(0o600)
            alias = safe / "linked.sqlite3"
            alias.symlink_to(db_path)
            with self.assertRaises(ValueError):
                DurableReplayStore(alias).summary()

    def test_competing_threads_cannot_both_commit_same_batch(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "shared.sqlite3"
            DurableReplayStore(path).initialize()
            def submit():
                try:
                    evaluate_durable_episodes(a, b, trust, path)
                    return "accepted"
                except ValueError as error:
                    return str(error)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(submit) for _ in range(2)]
                outcomes = [future.result(timeout=20) for future in futures]
            self.assertEqual(outcomes.count("accepted"), 1)
            self.assertEqual(
                sum("replay" in item for item in outcomes), 1)
            self.assertEqual(len(DurableReplayStore(path).summary()["keys"]), 5)

    def test_export_and_state_reports_never_contain_secret_or_raw_rows(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "sqlite.db"
            DurableReplayStore(path).initialize()
            report = evaluate_durable_episodes(a, b, trust, path)
            output = json.dumps(report) + json.dumps(
                DurableReplayStore(path).summary())
            for forbidden in (
                '"secret"', '"secret_b64"', '"secret_sha256"',
                '"mac_sha256"', '"measurements"', '"episodes"',
                '"reported_count"', '"attack_label"'
            ):
                self.assertNotIn(forbidden, output)
            self.assertIn("rollback", output.lower())

    def test_revocation_command_then_state_command_without_secret_output(self):
        sources, trust = signed_sources()
        a, b = envelopes(sources, trust)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "sqlite.db"
            DurableReplayStore(path).initialize()
            evaluate_durable_episodes(a, b, trust, path)
            with contextlib.redirect_stdout(io.StringIO()) as buffer:
                main(["attestation-revoke", "--state-db", str(path),
                      "--key-id", "test_key_1"])
            self.assertTrue(json.loads(buffer.getvalue())["revoked"])
            with contextlib.redirect_stdout(io.StringIO()) as buffer:
                main(["attestation-state", "--state-db", str(path)])
            statuses = json.loads(buffer.getvalue())
            self.assertEqual(len(statuses["keys"]), 5)
            self.assertEqual(
                {i["key_id"]: i for i in statuses["keys"]}
                ["test_key_1"]["revoked"], True)

    def test_ephemeral_demo_shows_replay_revoke_and_new_key(self):
        report = synthetic_durable_demo()
        self.assertTrue(report["self_signed_synthetic_demo"])
        self.assertTrue(report["durable_reopen_replay_rejected"])
        self.assertTrue(report["revoked_key_rejected"])
        self.assertTrue(report["new_key_id_rotation_succeeded"])
        self.assertTrue(report["private_temp_database_discarded"])
        self.assertFalse(report["secret_and_state_db_exported"])
        self.assertEqual(len(report["final_state"]["keys"]), 6)

    def test_demo_cli_writes_only_aggregate_metrics(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "results"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["durable-replay-demo", "--output", str(out)])
            data = json.loads((out / "durable_replay_demo.json").read_text())
            self.assertTrue(data["durable_reopen_replay_rejected"])
            serialized = json.dumps(data)
            for forbidden in (
                '"secret_b64"', '"secret_sha256"', '"mac_sha256"',
                '"measurements"', '"episodes"',
            ):
                self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
