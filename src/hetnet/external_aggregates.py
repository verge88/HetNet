"""Strict, privacy-minimising ingestion of *aggregate* observer counter snapshots.

No raw signaling packets, subscriber identifiers, remote connections or
operator telemetry are provided by this module. A source ID is a user claim
about provenance, not proof of physically independent instrumentation.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
from statistics import mean, median
from typing import Any

from .consensus import OBSERVER_DOMAINS
from .fault_domains import MONITORED_NODES

MAX_FILE_BYTES = 1_048_576
MAX_ROWS = 20_000
SOURCE_ID = re.compile(r"^[a-z][a-z0-9_-]{2,47}$", re.ASCII)
OPERATION_CLASSES = frozenset(("MAP", "Diameter", "GTPv2-C", "SIP", "SBI"))
PROVENANCE = {
    "synthetic": "synthetic_truth",
    "supplied_aggregate": "claimed_independent_aggregate",
}
REQUIRED_TOP = {
    "schema_version", "source_id", "provenance",
    "reference_basis", "measurements",
}
REQUIRED_ROW = {
    "observer", "node", "operation_class", "interval_index",
    "reference_count", "observed_count",
}


def _safe_int(number: Any, low: int, high: int) -> bool:
    return type(number) is int and low <= number <= high


def validate_dataset(data: Any) -> dict[str, Any]:
    """Reject unknown fields, individual identifiers and duplicate measurements.

    Only relative interval indices and coarse operation classes are accepted.
    An independent *reference_count* is an explicit input assumption.
    """
    if not isinstance(data, dict) or set(data) != REQUIRED_TOP:
        raise ValueError("Dataset must contain exactly the aggregate schema fields")
    if data["schema_version"] != 1 or type(data["schema_version"]) is not int:
        raise ValueError("Unsupported aggregate schema version")
    source = data["source_id"]
    if not isinstance(source, str) or not SOURCE_ID.fullmatch(source):
        raise ValueError("source_id must be an anonymous ASCII source slug")
    origin = data["provenance"]
    if origin not in PROVENANCE or data["reference_basis"] != PROVENANCE[origin]:
        raise ValueError("Invalid provenance/reference basis combination")
    rows = data["measurements"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
        raise ValueError("measurements must be a nonempty bounded array")
    seen = set()
    normalized = []
    for item in rows:
        if not isinstance(item, dict) or set(item) != REQUIRED_ROW:
            raise ValueError("Every row must contain only approved aggregate counters")
        observer, node, operation = (item["observer"], item["node"],
                                     item["operation_class"])
        if (observer not in OBSERVER_DOMAINS or node not in MONITORED_NODES
                or operation not in OPERATION_CLASSES):
            raise ValueError("Unknown observer, node or coarse operation class")
        idx, reference, observed = (item["interval_index"],
                                    item["reference_count"],
                                    item["observed_count"])
        if not _safe_int(idx, 0, 10_000_000):
            raise ValueError("interval_index must be a nonnegative relative index")
        if not _safe_int(reference, 20, 1_000_000):
            raise ValueError("Aggregate reference_count must be >=20 and <=1000000")
        if not _safe_int(observed, 0, reference):
            raise ValueError("observed_count must be within [0, reference_count]")
        key = (idx, node, operation, observer)
        if key in seen:
            raise ValueError("Duplicate interval/node/class/observer measurement")
        seen.add(key)
        normalized.append({
            "observer": observer, "node": node, "operation_class": operation,
            "interval_index": idx,
            "reference_count": reference, "observed_count": observed,
        })
    normalized.sort(key=lambda r: (
        r["interval_index"], r["node"], r["operation_class"], r["observer"]))
    return {
        "schema_version": 1, "source_id": source,
        "provenance": origin, "reference_basis": data["reference_basis"],
        "measurements": normalized,
    }


def load_dataset(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Aggregate input exceeds 1 MiB size limit")
    data = json.loads(path.read_text(encoding="utf-8"))
    return validate_dataset(data)


def fingerprint(data: dict[str, Any]) -> str:
    """Digest canonical validated aggregate data, not a secret or signature."""
    checked = validate_dataset(data)
    canonical = json.dumps(checked, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def source_summary(data: dict[str, Any]) -> dict[str, Any]:
    d = validate_dataset(data)
    return {
        "source_id": d["source_id"], "provenance": d["provenance"],
        "reference_basis": d["reference_basis"],
        "rows": len(d["measurements"]),
        "observer_count": len({r["observer"] for r in d["measurements"]}),
        "node_count": len({r["node"] for r in d["measurements"]}),
        "intervals": len({r["interval_index"] for r in d["measurements"]}),
        "fingerprint_sha256": fingerprint(d),
    }


def fit_capture_rates(train: list[dict[str, Any]]) -> dict[str, Any]:
    """Fit capture-miss rates by observer from training sources ONLY."""
    if not train:
        raise ValueError("At least one training source is required")
    datasets = [validate_dataset(item) for item in train]
    ids = [item["source_id"] for item in datasets]
    if len(set(ids)) != len(ids):
        raise ValueError("Training source IDs must be distinct")
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for dataset in datasets:
        for row in dataset["measurements"]:
            stats = totals[row["observer"]]
            stats[0] += row["reference_count"] - row["observed_count"]
            stats[1] += row["reference_count"]
            stats[2] += 1
    if set(totals) != set(OBSERVER_DOMAINS):
        raise ValueError("Training requires coverage of all three observers")
    rates = {
        observer: {
            "miss_probability": values[0] / values[1],
            "missed_events": values[0],
            "reference_events": values[1],
            "training_rows": values[2],
        }
        for observer, values in sorted(totals.items())
    }
    return {
        "schema_version": 1,
        "method": "count-weighted missing/reference per observer; training only",
        "training_source_ids": sorted(ids),
        "training_sources": [source_summary(d) for d in
                             sorted(datasets, key=lambda x: x["source_id"])],
        "per_observer": rates,
        "disclaimer": (
            "Declared source provenance and reference independence are not verified. "
            "A per-observer rate is not a measured physical independence guarantee."
        ),
    }


def evaluate_holdout(calibration: dict[str, Any],
                     test: dict[str, Any]) -> dict[str, Any]:
    """Evaluate heldout prediction of *observed counts*, not attack detection.

    Zero-loss baseline predicts observed=reference. Calibrated predictor
    uses the training-only observer miss probability. No labels or fit to test.
    """
    d = validate_dataset(test)
    if d["source_id"] in calibration["training_source_ids"]:
        raise ValueError("Held-out source must not appear in training sources")
    rates = calibration["per_observer"]
    rows = []
    by_observer: dict[str, list[dict]] = defaultdict(list)
    # Per interval/node/class records can also give inter-observer disagreement;
    # absence of the three rows is *coverage loss*, not proof of agreement.
    windows: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for item in d["measurements"]:
        obs = item["observer"]
        if obs not in rates:
            raise ValueError("Test observer missing from calibration")
        rate = rates[obs]["miss_probability"]
        reference = item["reference_count"]
        actual = item["observed_count"]
        expected = reference * (1 - rate)
        sample = {
            "observed": actual,
            "naive_abs_error": abs(reference - actual),
            "calibrated_abs_error": abs(expected - actual),
            "calibrated_signed_error": expected - actual,
        }
        rows.append(sample)
        by_observer[obs].append(sample)
        windows[(item["interval_index"], item["node"],
                 item["operation_class"])].append(item)

    def metrics(values: list[dict]) -> dict[str, Any]:
        return {
            "rows": len(values),
            "mae_naive_no_loss": mean(v["naive_abs_error"] for v in values),
            "mae_calibrated": mean(v["calibrated_abs_error"] for v in values),
            "bias_calibrated_predicted_minus_actual":
                mean(v["calibrated_signed_error"] for v in values),
        }

    complete = [group for group in windows.values() if
                {v["observer"] for v in group} == set(OBSERVER_DOMAINS)]
    disagreement = []
    for group in complete:
        ratios = [item["observed_count"] / item["reference_count"]
                  for item in group]
        disagreement.append(max(ratios) - min(ratios))
    return {
        "method": "source-disjoint out-of-source aggregate count prediction",
        "training_source_ids": list(calibration["training_source_ids"]),
        "holdout_source": source_summary(d),
        "overall": metrics(rows),
        "per_observer": {
            name: metrics(group) for name, group in sorted(by_observer.items())
        },
        "coverage": {
            "complete_three_observer_windows": len(complete),
            "all_windows": len(windows),
            "mean_relative_capture_ratio_spread":
                mean(disagreement) if disagreement else None,
            "median_relative_capture_ratio_spread":
                median(disagreement) if disagreement else None,
        },
        "cannot_infer": [
            "No attack labels: precision, recall, FPR and ROC AUC not defined",
            "Source IDs only enforce a split; they do not prove physical independence",
            "No externally verified provenance, reference counter or lawful consent",
            "Calibration rates do not imply actual packet loss probabilities",
        ],
    }


def run_external_eval(train_files: list[Path], test_file: Path) -> dict[str, Any]:
    training = [load_dataset(path) for path in train_files]
    heldout = load_dataset(test_file)
    fitted = fit_capture_rates(training)
    evaluated = evaluate_holdout(fitted, heldout)
    return {"calibration": fitted, "holdout": evaluated}
