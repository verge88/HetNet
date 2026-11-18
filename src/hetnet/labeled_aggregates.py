"""Labeled, aggregate-only CU comparison with train/test source isolation.

No packet captures, subscriber IDs, contact with operators, or source-attestation
occur. Verification flags and annotations supplied in files are CLAIMS, not
cryptographic proof. Reports contain metrics, never source measurement rows.

This module is intentionally separate from the synthetic Scenario benchmark:
neither fabricated simulation attack flags nor stage-8 unlabeled inputs are
silently repurposed as external security annotations.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, median
from typing import Any

from .external_aggregates import MAX_FILE_BYTES, SOURCE_ID, _strict_pairs
from .fault_domains import MONITORED_NODES
from .zonal_detection import DETECTORS, _metrics

FIELDS = frozenset((
    "schema_version", "source_id", "lineage_id", "provenance",
    "annotation_basis", "measurements", "labels",
))
ROW_FIELDS = frozenset((
    "node", "interval_index", "operation_class", "reference_count",
    "reported_count", "cu_verified_claim", "quorum_verified_claim",
))
LABEL_FIELDS = frozenset(("node", "attack_label"))
CLASSES = frozenset(("MAP", "Diameter", "GTPv2-C", "SIP", "SBI"))
MAX_ROWS = 20000
MAX_COUNT = 1_000_000
DEFAULT_TINY = 1e-12


def _slug(value: Any) -> bool:
    return isinstance(value, str) and SOURCE_ID.fullmatch(value) is not None


def _whole(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def validate_labeled(data: Any) -> dict[str, Any]:
    """Validate a strictly bounded, no-individual-identifiers input format."""
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError("Labeled input has missing or unknown top-level fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported labeled schema version")
    if not _slug(data["source_id"]) or not _slug(data["lineage_id"]):
        raise ValueError("Use anonymous ASCII source_id and lineage_id")
    origin, basis = data["provenance"], data["annotation_basis"]
    if (type(origin) is not str or type(basis) is not str or
            (origin, basis) not in (
                ("synthetic", "synthetic_injection"),
                ("supplied_aggregate", "expert_review_claimed"),
            )):
        raise ValueError("Invalid provenance and annotation basis")
    labels = data["labels"]
    if (not isinstance(labels, list)
            or len(labels) != len(MONITORED_NODES)):
        raise ValueError("Labels must cover each of six monitored nodes")
    known = {}
    for label in labels:
        if not isinstance(label, dict) or set(label) != LABEL_FIELDS:
            raise ValueError("Only node and boolean attack_label are allowed")
        node, truth = label["node"], label["attack_label"]
        if (not isinstance(node, str) or node not in MONITORED_NODES
                or type(truth) is not bool or node in known):
            raise ValueError("Invalid or duplicated node label")
        known[node] = truth
    if set(known) != set(MONITORED_NODES):
        raise ValueError("All monitored node annotations required")
    rows = data["measurements"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
        raise ValueError("Expected a bounded nonempty aggregate measurement list")
    seen: set[tuple] = set()
    clean = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW_FIELDS:
            raise ValueError("Unexpected aggregate field; no subscriber data allowed")
        node, op, interval = (row["node"], row["operation_class"],
                              row["interval_index"])
        if (not isinstance(node, str) or node not in MONITORED_NODES
                or not isinstance(op, str) or op not in CLASSES):
            raise ValueError("Invalid monitored node or coarse class")
        if not _whole(interval, 0, 10_000_000):
            raise ValueError("Only nonnegative relative interval indices allowed")
        ref, reported = row["reference_count"], row["reported_count"]
        if not _whole(ref, 20, MAX_COUNT) or not _whole(reported, 0, MAX_COUNT):
            raise ValueError("Only bounded aggregate integer counters allowed")
        if (type(row["cu_verified_claim"]) is not bool
                or type(row["quorum_verified_claim"]) is not bool):
            raise ValueError("Verification-claim flags must be boolean")
        key = (interval, node, op)
        if key in seen:
            raise ValueError("Duplicate interval/node/class aggregate")
        seen.add(key)
        clean.append(dict(row))
    clean.sort(key=lambda x: (x["interval_index"], x["node"],
                               x["operation_class"]))
    return {
        "schema_version": 1,
        "source_id": data["source_id"], "lineage_id": data["lineage_id"],
        "provenance": origin, "annotation_basis": basis,
        "measurements": clean,
        "labels": [{"node": node, "attack_label": known[node]}
                   for node in sorted(known)],
    }


def load_labeled(path: Path) -> dict[str, Any]:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Labeled aggregate file exceeds 1 MiB")
    return validate_labeled(json.loads(
        p.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(
            ValueError("Nonfinite JSON number"))))


def _measurement_digest(data: dict) -> str:
    """Spot literal duplicate measurements even when IDs are renamed."""
    normalized = validate_labeled(data)
    payload = json.dumps(normalized["measurements"], sort_keys=True,
                         separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def audit_labeled(data: dict) -> dict:
    d = validate_labeled(data)
    return {
        "source_id": d["source_id"],
        "lineage_id": d["lineage_id"],
        "provenance": d["provenance"],
        "annotation_basis": d["annotation_basis"],
        "measurement_rows": len(d["measurements"]),
        "relative_intervals": len({
            row["interval_index"] for row in d["measurements"]}),
        "annotated_nodes": len(d["labels"]),
        "measured_nodes": len({
            row["node"] for row in d["measurements"]}),
        "measurement_fingerprint_sha256": _measurement_digest(d),
        "warning": ("Metadata and signatures are not externally verified; "
                    "source lineage and expert annotations are input claims."),
    }


def aggregate_features(data: dict) -> dict[str, dict[str, float | None]]:
    """Create predictions from WHITELISTED aggregate features ONLY.

    The labels and source names are intentionally never accessed. A claimed
    verification flag merely gates usability; we do not invent a true MAC.
    Returns pairs of node-level scores with explicit null for abstention.
    """
    rows = data["measurements"]
    grouped: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["interval_index"], row["node"])].append(row)
    epochs: dict[int, dict[str, float | None]] = defaultdict(dict)
    for (interval, node), group in grouped.items():
        if not all(r["cu_verified_claim"] and r["quorum_verified_claim"]
                   for r in group):
            epochs[interval][node] = None
            continue
        total = sum(r["reference_count"] for r in group)
        difference = sum(abs(r["reported_count"] - r["reference_count"])
                         for r in group)
        epochs[interval][node] = difference / total
    derived: dict[int, dict[str, dict[str, float | None]]] = {}
    for interval, values in epochs.items():
        valid = {node: value for node, value in values.items()
                 if value is not None}
        derived[interval] = {}
        for node, value in valid.items():
            peers = [x for n, x in valid.items() if n != node]
            derived[interval][node] = {
                "zone_absolute": value,
                "zone_peer": (
                    max(0.0, value - median(peers)) if len(peers) >= 2
                    else None),
            }
    result = {}
    for node in MONITORED_NODES:
        candidate = {"cu_signed_baseline": [],
                     "zone_absolute": [], "zone_peer": []}
        intervals = sorted(t for t in derived if node in derived[t])
        for first, second in zip(intervals, intervals[1:]):
            if second != first + 1:
                continue
            a, b = derived[first][node], derived[second][node]
            for field in ("zone_absolute", "zone_peer"):
                if a[field] is not None and b[field] is not None:
                    candidate[field].append(
                        max(0.0, min(a[field], b[field])))
            candidate["cu_signed_baseline"].append(
                float(a["zone_absolute"] > 0 and b["zone_absolute"] > 0))
        result[node] = {
            key: (max(values) if values else None)
            for key, values in candidate.items()
        }
    return result


def fit_thresholds(train: list[dict]) -> dict:
    if not train:
        raise ValueError("At least one training dataset required")
    checked = [validate_labeled(d) for d in train]
    if any(any(row["attack_label"] for row in d["labels"]) for d in checked):
        raise ValueError("Training labels must all be clean")
    candidates = {"zone_absolute": [], "zone_peer": []}
    for d in checked:
        node_scores = aggregate_features(d)
        for field in candidates:
            candidates[field].extend(
                node_scores[node][field] for node in MONITORED_NODES
                if node_scores[node][field] is not None)
    if any(not arr for arr in candidates.values()):
        raise ValueError("Training must yield verified consecutive scores")
    return {
        "method": "max clean verified consecutive node residual + epsilon",
        "thresholds": {
            key: max(vals) + DEFAULT_TINY
            for key, vals in candidates.items()},
        "train_source_ids": sorted(d["source_id"] for d in checked),
        "train_lineage_ids": sorted(d["lineage_id"] for d in checked),
        "train_score_counts": {k: len(v) for k, v in candidates.items()},
    }


def evaluate_labeled(train: list[dict], holdout: list[dict]) -> dict:
    """Fit only on training sources; score labels on disjoint holdout sources."""
    if not train or not holdout:
        raise ValueError("Nonempty train and holdout sources required")
    all_sources = [validate_labeled(d) for d in (*train, *holdout)]
    ids = [d["source_id"] for d in all_sources]
    lineages = [d["lineage_id"] for d in all_sources]
    fingerprints = [_measurement_digest(d) for d in all_sources]
    if (len(set(ids)) != len(ids) or len(set(lineages)) != len(lineages)
            or len(set(fingerprints)) != len(fingerprints)):
        raise ValueError(
            "Duplicate source ID, lineage ID, or identical measurement capture")
    training = all_sources[:len(train)]
    testing = all_sources[len(train):]
    model = fit_thresholds(training)
    by_source: list[dict] = []
    pooled = {detector: [] for detector in DETECTORS}
    for d in testing:
        prediction = aggregate_features(d)
        # Only THIS scoring section reads the ground truth label.
        truth = {label["node"]: label["attack_label"] for label in d["labels"]}
        for detector in DETECTORS:
            records = []
            for node in MONITORED_NODES:
                score = prediction[node][detector]
                available = score is not None
                if detector == "cu_signed_baseline":
                    detected = available and score > 0
                else:
                    detected = (available and score >
                                model["thresholds"][detector])
                records.append({
                    "ground_truth": truth[node],
                    "detected": bool(detected),
                    "abstained": not available,
                })
            pooled[detector].extend(records)
            by_source.append({
                "source_id": d["source_id"], "detector": detector,
                **_metrics(records),
            })
    return {
        "method": "claimed-provenance labeled aggregate holdout (no raw data)",
        "training": model,
        "train_sources": [audit_labeled(d) for d in training],
        "holdout_sources": [audit_labeled(d) for d in testing],
        "per_source": by_source,
        "overall": [{"detector": name, **_metrics(pooled[name])}
                    for name in DETECTORS],
        "limitations": [
            "External provenance, independent ground truth, labels and flags are NOT verified",
            "Labels never feed detectors, but training clean status is user asserted",
            "Source IDs, lineages and fingerprints cannot prove no physical overlap",
            "Unsigned aggregate comparison is not cryptographically verified CU",
            "Raw measurements and per-node ground truths are never exported",
            "No real operator data present in repository demonstration",
            "No standalone 3GPP conformance or production ML claim",
        ],
    }


def run_labeled_eval(train_paths: list[Path],
                     test_paths: list[Path]) -> dict:
    return evaluate_labeled([load_labeled(p) for p in train_paths],
                            [load_labeled(p) for p in test_paths])
