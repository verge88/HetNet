"""Durable, local anti-replay state and irreversible key-id revocation.

SQLite BEGIN IMMEDIATE serializes competing writers. Sequences are committed
only after *all* HMACs, identity bindings and scientific input constraints pass.

Security boundary: the database, its private directory and local trust file
must be protected by the host. A filesystem rollback, DB deletion, backup
restore, compromised trusted signer, or signer re-signing old measurements
with a *new* sequence is NOT detected. No HSM/PKI/secure timestamp exists.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from .aggregate_attestation import (
    TrustedIdentity, evaluate_attested_episodes, load_envelope, load_trust_file,
)
from .labeled_aggregates import _slug


def _private_db_path(path: Path) -> Path:
    p = Path(path)
    if not p.name or not p.parent.is_dir() or p.is_symlink():
        raise ValueError("State database parent must exist; symlinks are disallowed")
    if os.name == "posix":
        parent_mode = stat.S_IMODE(p.parent.stat().st_mode)
        if parent_mode & 0o077:
            raise ValueError("State database parent must be private (0700)")
    if p.exists():
        if not p.is_file() or p.is_symlink():
            raise ValueError("State database must be a regular non-symlink file")
        info = p.stat()
        if info.st_nlink != 1:
            raise ValueError("State database hard links are not supported")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("State database file must be private (0600)")
    return p


class DurableReplayStore:
    """One protected SQLite database for monotonic key counters and revocations.

    Transactions cover the ENTIRE envelope batch, so a failed signature,
    bad scientific sample, replay or revoked key does not consume any
    sequence. The caller must maintain the DB across process restarts.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        p = _private_db_path(self.path)
        # sqlite3 creates 0666 & umask; set 077 before opening to ensure
        # private DB and short-lived SQLite rollback journal files.
        original = os.umask(0o077) if os.name == "posix" else None
        try:
            db = sqlite3.connect(str(p), timeout=10, isolation_level=None)
        finally:
            if original is not None:
                os.umask(original)
        try:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("PRAGMA user_version").fetchone()[0]
            if current not in (0, 1):
                raise ValueError("Unsupported durable-state schema version")
            db.execute(
                "CREATE TABLE IF NOT EXISTS key_state ("
                "key_id TEXT PRIMARY KEY NOT NULL, "
                "source_id TEXT NOT NULL, lineage_id TEXT NOT NULL, "
                "secret_sha256 TEXT NOT NULL, highest_sequence INTEGER NOT NULL "
                "CHECK(highest_sequence >= 1), "
                "revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)))"
            )
            db.execute("PRAGMA user_version=1")
            db.execute("COMMIT")
        except BaseException:
            db.rollback()
            db.close()
            raise
        return db

    def commit_verified_batch(
        self, audits: list[dict[str, Any]],
        trust: dict[str, TrustedIdentity],
    ) -> dict:
        """Atomic persistent acceptance of previously verified signed audits.

        Use via evaluate_durable_episodes(): calling this with unauthenticated
        audits directly is unsafe; the method does not validate HMAC bytes.
        """
        if not audits:
            raise ValueError("Verified batch cannot be empty")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            for audit in audits:
                key_id = audit["key_id"]
                sequence = audit["sequence"]
                identity = trust.get(key_id)
                if (not isinstance(identity, TrustedIdentity)
                        or audit.get("hmac_verified") is not True
                        or audit["source_id"] != identity.source_id
                        or audit["lineage_id"] != identity.lineage_id
                        or type(sequence) is not int or sequence < 1):
                    raise ValueError("Untrusted or malformed verified audit")
                fp = hashlib.sha256(identity.secret).hexdigest()
                state = db.execute(
                    "SELECT source_id, lineage_id, secret_sha256, "
                    "highest_sequence, revoked FROM key_state WHERE key_id=?",
                    (key_id,),
                ).fetchone()
                if state is not None:
                    if state[4]:
                        raise ValueError("Attestation key revoked: " + key_id)
                    if (state[0], state[1], state[2]) != (
                            identity.source_id, identity.lineage_id, fp):
                        raise ValueError("Attestation key identity changed; rotate key_id")
                    if sequence <= state[3]:
                        raise ValueError("Persistent attestation replay/out-of-order")
                    db.execute(
                        "UPDATE key_state SET highest_sequence=? WHERE key_id=?",
                        (sequence, key_id),
                    )
                else:
                    db.execute(
                        "INSERT INTO key_state "
                        "(key_id,source_id,lineage_id,secret_sha256,highest_sequence,revoked) "
                        "VALUES (?,?,?,?,?,0)",
                        (key_id, identity.source_id, identity.lineage_id,
                         fp, sequence),
                    )
            db.execute("COMMIT")
            return {
                "database": "local SQLite, private file",
                "verified_envelopes_committed": len(audits),
                "atomic_batch_committed": True,
                "persistent_replay": "strict monotonic sequence per key ID",
                "key_binding": "source, lineage, and secret fingerprint cannot change",
                "rollback_warning": (
                    "Database deletion or restoration from old backup defeats "
                    "durable anti-replay without external monotonic storage"
                ),
            }
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def revoke(self, key_id: str) -> dict:
        """Persistently reject all future uses of this already admitted key ID.

        There is intentionally no un-revoke operation; rotate to a NEW key ID.
        """
        if not _slug(key_id):
            raise ValueError("Invalid key identifier")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revoked FROM key_state WHERE key_id=?", (key_id,)
            ).fetchone()
            if row is None:
                raise ValueError("Cannot revoke an unknown key ID")
            if row[0]:
                raise ValueError("Key ID already revoked")
            db.execute(
                "UPDATE key_state SET revoked=1 WHERE key_id=?", (key_id,)
            )
            db.execute("COMMIT")
            return {"key_id": key_id, "revoked": True,
                    "rotation_instruction": "Issue distinct key ID and new secret"}
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def summary(self) -> dict:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT key_id,source_id,lineage_id,highest_sequence,revoked "
                "FROM key_state ORDER BY key_id"
            ).fetchall()
            return {
                "keys": [{
                    "key_id": row[0], "source_id": row[1],
                    "lineage_id": row[2], "highest_sequence": row[3],
                    "revoked": bool(row[4]),
                } for row in rows],
                "warning": (
                    "Local writable database only; no signed history, "
                    "rollback resistance or global cross-site consensus"
                ),
            }
        finally:
            db.close()


def evaluate_durable_episodes(
    train_envelopes: list[dict], holdout_envelopes: list[dict],
    trust: dict[str, TrustedIdentity], state_db: Path,
) -> dict:
    """Verify all sources, fit clean-only, then atomically consume sequences."""
    # Stage 12 checks *all* signatures and batch replay, and Stage 11 checks
    # clean-only training, label split, and duplicate capture before DB writes.
    report = evaluate_attested_episodes(
        train_envelopes, holdout_envelopes, trust)
    audits = report["attestation"]["verified_inputs"]
    state = DurableReplayStore(state_db).commit_verified_batch(audits, trust)
    report["durable_attestation"] = state
    report["durable_attestation"]["warning"] = (
        "HMAC authenticates trusted key-holder statements, NOT "
        "sensor physics, truthful labels or externally verified provenance"
    )
    return report


def run_durable_eval(
    train_paths: list[Path], holdout_paths: list[Path],
    trust_path: Path, state_db: Path,
) -> dict:
    trust = load_trust_file(trust_path)
    return evaluate_durable_episodes(
        [load_envelope(path) for path in train_paths],
        [load_envelope(path) for path in holdout_paths],
        trust, state_db,
    )
