"""Synthetic clock-bin misalignment sensitivity for Stage-11 episode scoring.

A deterministic *fixed integer interval-label offset* changes only the
reported node interval. Neither attack labels nor absolute clocks change.
No operational clock drift in seconds, sync protocol, jitter distribution,
or physical channel independence is represented.

This experiment is entirely offline and writes only aggregate summaries.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .fault_domains import MONITORED_NODES
from .labeled_aggregates import load_labeled
from .temporal_episodes import evaluate_temporal, load_episodic, validate_episodic

CLOCK_CASES: dict[str, dict[str, int]] = {
    "aligned": {},
    "opposing_one_bin": {"msc2": 1, "amf5": -1, "sgsn3": 1, "pcscf": -1},
    "opposing_two_bins": {"msc2": 2, "amf5": -2, "sgsn3": 2, "pcscf": -2},
    "epc_ims_one_bin": {"mme4": 1, "dra": -1, "pcscf": 1},
}


def validate_offsets(offsets: dict[str, int]) -> None:
    if not isinstance(offsets, dict):
        raise ValueError("Clock offsets must be a node to integer mapping")
    for node, offset in offsets.items():
        if (not isinstance(node, str) or node not in MONITORED_NODES
                or type(offset) is not int or not -2 <= offset <= 2):
            raise ValueError("Clock offsets must be known nodes and -2..2 bins")


def shift_interval_bins(data: dict, offsets: dict[str, int]) -> tuple[dict, dict]:
    """Shift relative interval indices and drop observations outside window.

    No source IDs, labels, episode annotations or measured counts are edited.
    Source data is copied and untouched. No post-shift label leakage into
    time alignment is permitted. Dropped rows are counted for coverage.
    """
    d = validate_episodic(data)
    validate_offsets(offsets)
    lower = min(row["interval_index"] for row in d["measurements"])
    upper = max(row["interval_index"] for row in d["measurements"])
    shifted = deepcopy(d)
    new_rows = []
    dropped = 0
    for row in d["measurements"]:
        new_t = row["interval_index"] + offsets.get(row["node"], 0)
        if new_t < lower or new_t > upper:
            dropped += 1
            continue
        new_rows.append({**row, "interval_index": new_t})
    if not new_rows:
        raise ValueError("Clock offsets discarded every aggregate observation")
    shifted["measurements"] = new_rows
    # Recheck the entire measurement schema and the label interval framing.
    shifted = validate_episodic(shifted)
    return shifted, {
        "shifted_nodes": len([v for v in offsets.values() if v != 0]),
        "dropped_rows": dropped,
        "retained_rows": len(new_rows),
        "original_rows": len(d["measurements"]),
        "max_abs_offset_bins": max(map(abs, offsets.values()), default=0),
    }


def clock_sensitivity(
    train: list[dict], holdout: list[dict],
    *, cases: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Keep source-disjoint training constant while perturbing holdout clocks.

    Repeated cases are *paired* synthetic transformations of the SAME data,
    not independent trials or new external sources.
    """
    if cases is None:
        cases = CLOCK_CASES
    if not isinstance(cases, dict) or not cases:
        raise ValueError("Need a nonempty set of clock perturbation scenarios")
    validated = [validate_episodic(source) for source in holdout]
    if not validated or not train:
        raise ValueError("Both clean training and episodic holdout are needed")
    per_case = []
    aligned_calibration = None
    for name, offsets in cases.items():
        if not isinstance(name, str) or not name.isascii() or len(name) > 48:
            raise ValueError("Scenario names must be short ASCII labels")
        validate_offsets(offsets)
        perturbations = [shift_interval_bins(data, offsets)
                         for data in validated]
        perturbed = [data for data, _ in perturbations]
        report = evaluate_temporal(train, perturbed)
        if aligned_calibration is None:
            aligned_calibration = report["training"]
        elif report["training"] != aligned_calibration:
            raise AssertionError("Clock stress changed training-only calibration")
        per_case.append({
            "case": name,
            "offsets_in_relative_bins": dict(sorted(offsets.items())),
            "per_source_coverage": [
                {"source_id": data["source_id"], **stats}
                for data, stats in zip(validated,
                                       [stats for _, stats in perturbations])
            ],
            "overall": report["overall"],
            "per_source": report["per_source"],
        })
    return {
        "method": "fixed per-node integer interval-label offsets; no real clock model",
        "training": aligned_calibration,
        "cases": per_case,
        "limitations": [
            "Every case is a paired deterministic modification of the same synthetic sources",
            "Offsets are interval bins, not milliseconds or real hardware clock drift",
            "Labels are unchanged and can become misaligned with shifted observations",
            "Boundary observations may be dropped and are included in coverage",
            "No physical clock, PTP/NTP, network delay or real trace validation",
            "Claimed CU/quorum flags are not cryptographic proof",
            "No 3GPP timing conformance or real operator accuracy implied",
        ],
    }


def run_clock_study(train_paths: list, holdout_paths: list) -> dict:
    return clock_sensitivity(
        [load_labeled(path) for path in train_paths],
        [load_episodic(path) for path in holdout_paths],
    )
