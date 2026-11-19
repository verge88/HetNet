"""Experimental source-bound HMAC envelopes for *aggregate* CU datasets.

A valid HMAC proves that the locally trusted key signed these exact bytes'
canonical contents; it cannot prove sensor independence, reference accuracy,
physical provenance, lawful collection, or expert annotation truth.

No secret is included in reports or repository fixtures. ReplayGuard only
remembers sequences within its Python process: persistent replay protection
requires trusted external state and is NOT supplied by this demonstration.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from dataclasses import dataclass
from typing import Any

from .external_aggregates import MAX_FILE_BYTES, _strict_pairs
from .labeled_aggregates import _slug, validate_labeled
from .temporal_episodes import validate_episodic, capture_digest

DOMAIN = b"HetNet/laboratory-aggregate-envelope/v1\x00"
MAX_SEQUENCE = 2**53 - 1
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ENVELOPE_FIELDS = frozenset((
    "envelope_version", "key_id", "sequence", "dataset", "mac_sha256",
))
TRUST_FIELDS = frozenset(("schema_version", "identities"))
IDENTITY_FIELDS = frozenset((
    "key_id", "source_id", "lineage_id", "secret_b64",
))


@dataclass(frozen=True)
class TrustedIdentity:
    """Explicit local trust-policy binding for exactly one source/lineage."""
    source_id: str
    lineage_id: str
    secret: bytes

    def __post_init__(self):
        if not _slug(self.source_id) or not _slug(self.lineage_id):
            raise ValueError("Trusted identity requires anonymous source and lineage")
        if (type(self.secret) is not bytes
                or not 32 <= len(self.secret) <= 64):
            raise ValueError("Attestation secret must be 32..64 private bytes")


def _dataset(data: Any) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Envelope dataset must be an aggregate object")
    version = data.get("schema_version")
    if type(version) is not int:
        raise ValueError("Dataset schema version must be integer")
    if version == 1:
        return validate_labeled(data)
    if version == 2:
        return validate_episodic(data)
    raise ValueError("Only labeled v1 and episodic v2 datasets are supported")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _signed_payload(key_id: str, sequence: int, data: dict) -> bytes:
    return DOMAIN + _canonical({
        "envelope_version": 1, "key_id": key_id,
        "sequence": sequence, "dataset": data,
    })


def _valid_counter(sequence: Any) -> bool:
    return type(sequence) is int and 1 <= sequence <= MAX_SEQUENCE


def create_envelope(dataset: dict, *, key_id: str, sequence: int,
                    secret: bytes) -> dict:
    """Sign a validated aggregate object; never write secret into envelope."""
    data = _dataset(dataset)
    if not _slug(key_id) or not _valid_counter(sequence):
        raise ValueError("Invalid attestation key ID or positive sequence")
    if type(secret) is not bytes or not 32 <= len(secret) <= 64:
        raise ValueError("Invalid laboratory HMAC key length")
    mac = hmac.new(secret, _signed_payload(key_id, sequence, data),
                   hashlib.sha256).hexdigest()
    return {
        "envelope_version": 1, "key_id": key_id,
        "sequence": sequence, "dataset": data,
        "mac_sha256": mac,
    }


class ReplayGuard:
    """Nonpersistent monotonic per-key sequence tracking for one batch/process."""

    def __init__(self):
        self._highest: dict[str, int] = {}

    def accept(self, key_id: str, sequence: int) -> None:
        highest = self._highest.get(key_id, 0)
        if sequence <= highest:
            raise ValueError("Attestation sequence replay/out-of-order")
        self._highest[key_id] = sequence


def verify_envelope(envelope: Any, trust: dict[str, TrustedIdentity],
                    *, guard: ReplayGuard | None = None) -> tuple[dict, dict]:
    """Verify source-bound HMAC BEFORE making an authenticated-data claim.

    No state is consumed on failure. Replay checking is optional and ephemeral;
    evaluations always pass a common guard for the input batch.
    """
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("Invalid attestation envelope fields")
    if type(envelope["envelope_version"]) is not int or envelope["envelope_version"] != 1:
        raise ValueError("Unsupported attestation envelope version")
    key_id = envelope["key_id"]
    sequence = envelope["sequence"]
    mac = envelope["mac_sha256"]
    if (not _slug(key_id) or not _valid_counter(sequence)
            or type(mac) is not str or not DIGEST.fullmatch(mac)):
        raise ValueError("Invalid attestation header or signature format")
    identity = trust.get(key_id)
    if not isinstance(identity, TrustedIdentity):
        raise ValueError("Untrusted attestation key ID")
    data = _dataset(envelope["dataset"])
    if (data["source_id"] != identity.source_id
            or data["lineage_id"] != identity.lineage_id):
        raise ValueError("Attestation source/lineage not allowed by key policy")
    reference = hmac.new(
        identity.secret, _signed_payload(key_id, sequence, data),
        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, reference):
        raise ValueError("Aggregate attestation MAC mismatch")
    if guard is not None:
        guard.accept(key_id, sequence)
    # Even verified flags/labels remain source assertions, NOT physical truth.
    return data, {
        "key_id": key_id, "source_id": data["source_id"],
        "lineage_id": data["lineage_id"], "sequence": sequence,
        "hmac_verified": True,
        "measurement_fingerprint_sha256": capture_digest(data["measurements"]),
        "scope": "complete canonical aggregate AND node/episode annotations",
    }


def _strict_json(path: Path, *, max_bytes: int) -> dict:
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > max_bytes:
        raise ValueError("Input file is missing, symlinked or exceeds size limit")
    result = json.loads(p.read_text(encoding="utf-8"),
                        object_pairs_hook=_strict_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(
                            ValueError("Nonfinite JSON value")))
    if not isinstance(result, dict):
        raise ValueError("Root JSON object required")
    return result


def load_envelope(path: Path) -> dict:
    return _strict_json(path, max_bytes=MAX_FILE_BYTES)


def load_trust_file(path: Path) -> dict[str, TrustedIdentity]:
    """Read private local policy, reject group/world-readable files on POSIX.

    Keep trust files outside git. This does not implement an HSM/key lifecycle.
    """
    p = Path(path)
    if os.name == "posix" and stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise ValueError("Trust file must have mode 0600 or stricter")
    obj = _strict_json(p, max_bytes=32 * 1024)
    if set(obj) != TRUST_FIELDS or type(obj["schema_version"]) is not int \
            or obj["schema_version"] != 1:
        raise ValueError("Invalid trust policy version/fields")
    entries = obj["identities"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise ValueError("Trust policy must list 1..128 explicit identities")
    trust = {}
    observed_keys: set[bytes] = set()
    source_lineage: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != IDENTITY_FIELDS:
            raise ValueError("Invalid trust policy identity")
        key_id = entry["key_id"]
        if not _slug(key_id) or key_id in trust:
            raise ValueError("Duplicate/invalid trust-policy key ID")
        raw = entry["secret_b64"]
        if not isinstance(raw, str) or len(raw) > 90:
            raise ValueError("Invalid secret encoding")
        try:
            secret = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("Invalid secret base64") from error
        identity = TrustedIdentity(
            entry["source_id"], entry["lineage_id"], secret)
        pair = (identity.source_id, identity.lineage_id)
        digest = hashlib.sha256(secret).digest()
        if pair in source_lineage or digest in observed_keys:
            raise ValueError("Trust identities must have distinct bindings and keys")
        source_lineage.add(pair)
        observed_keys.add(digest)
        trust[key_id] = identity
    return trust


def evaluate_attested_episodes(
    training_envelopes: list[dict], holdout_envelopes: list[dict],
    trust: dict[str, TrustedIdentity],
) -> dict:
    """Validate ALL HMACs/lineages before fitting or scoring any dataset."""
    if not training_envelopes or not holdout_envelopes:
        raise ValueError("Need nonempty training and holdout envelopes")
    guard = ReplayGuard()
    trusted_train, trusted_holdout, audits = [], [], []
    for phase, envelopes in (
        ("train", training_envelopes), ("holdout", holdout_envelopes)
    ):
        for envelope in envelopes:
            data, audit = verify_envelope(envelope, trust, guard=guard)
            if phase == "train" and data["schema_version"] != 1:
                raise ValueError("Only labeled clean v1 training envelopes accepted")
            if phase == "holdout" and data["schema_version"] != 2:
                raise ValueError("Only episode v2 holdout envelopes accepted")
            (trusted_train if phase == "train" else trusted_holdout).append(data)
            audits.append({"partition": phase, **audit})
    from .temporal_episodes import evaluate_temporal
    report = evaluate_temporal(trusted_train, trusted_holdout)
    report["attestation"] = {
        "method": "source/lineage-bound full-payload HMAC-SHA256",
        "verified_inputs": audits,
        "hmac_verified_in_this_process": True,
        "batch_replay_guard": "monotonic per key, process-local only",
        "warning": (
            "HMAC verifies a trusted key holder's statement, NOT independent "
            "sensors, verified labels, trustworthy counters or lawful provenance"
        ),
    }
    return report


def run_attested_eval(train_paths: list[Path], holdout_paths: list[Path],
                      trust_path: Path) -> dict:
    trusted = load_trust_file(trust_path)
    return evaluate_attested_episodes(
        [load_envelope(path) for path in train_paths],
        [load_envelope(path) for path in holdout_paths], trusted,
    )
