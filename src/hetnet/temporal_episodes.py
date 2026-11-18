"""Onset-agnostic episode evaluation over aggregate-only labeled CU windows.

The detector receives strictly *measurements*, never episode annotations.
Alarms are raised causally at the second of two adjacent eligible intervals.
Annotations are used only afterwards for one-to-one episode matching.

External CU/quorum verification flags, lineages and expert labels are CLAIMS.
This is not live network interception, a wire-protocol implementation,
cryptographic authentication or proof of operator-grade independence.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
from statistics import mean, median
from typing import Any

from .external_aggregates import MAX_FILE_BYTES, _strict_pairs
from .fault_domains import MONITORED_NODES
from .labeled_aggregates import (
    CLASSES, DETECTORS, ROW_FIELDS, _slug, _whole,
    fit_thresholds, validate_labeled,
)

TOP_FIELDS = frozenset((
    "schema_version", "source_id", "lineage_id", "provenance",
    "annotation_basis", "measurements", "episodes",
))
EPISODE_FIELDS = frozenset(("node", "start_interval", "end_interval"))
MAX_EPISODES = 2000


def validate_episodic(data: Any) -> dict[str, Any]:
    """Strict version-2 schema; attack spans are half-open [start,end)."""
    if not isinstance(data, dict) or set(data) != TOP_FIELDS:
        raise ValueError("Unexpected or missing episodic aggregate fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 2:
        raise ValueError("Episodic aggregate schema_version must be 2")
    if not _slug(data["source_id"]) or not _slug(data["lineage_id"]):
        raise ValueError("Anonymous source and lineage ASCII slugs required")
    synthetic = ("synthetic", "synthetic_injection")
    claimed = ("supplied_aggregate", "expert_review_claimed")
    if (type(data["provenance"]) is not str
            or type(data["annotation_basis"]) is not str
            or (data["provenance"], data["annotation_basis"])
            not in (synthetic, claimed)):
        raise ValueError("Unsupported provenance and claimed annotation basis")

    # Reuse Stage-10 strict row schema; placeholder CLEAN labels are a
    # validation adapter only, NEVER inferred event ground truth.
    shadow = {
        "schema_version": 1,
        "source_id": data["source_id"],
        "lineage_id": data["lineage_id"],
        "provenance": data["provenance"],
        "annotation_basis": data["annotation_basis"],
        "measurements": data["measurements"],
        "labels": [{"node": node, "attack_label": False}
                   for node in MONITORED_NODES],
    }
    normalized = validate_labeled(shadow)
    intervals = [item["interval_index"] for item in normalized["measurements"]]
    lower, upper = min(intervals), max(intervals) + 1
    original_episodes = data["episodes"]
    if (not isinstance(original_episodes, list)
            or len(original_episodes) > MAX_EPISODES):
        raise ValueError("Expected a bounded episode annotation list")
    episodes = []
    for item in original_episodes:
        if not isinstance(item, dict) or set(item) != EPISODE_FIELDS:
            raise ValueError("Episode has unexpected fields or missing annotation")
        node = item["node"]
        start, end = item["start_interval"], item["end_interval"]
        if not isinstance(node, str) or node not in MONITORED_NODES:
            raise ValueError("Unknown episode node")
        if (not _whole(start, lower, upper - 1)
                or not _whole(end, start + 1, upper)):
            raise ValueError("Invalid half-open episode interval")
        episodes.append({"node": node, "start_interval": start,
                         "end_interval": end})
    episodes.sort(key=lambda x: (x["node"], x["start_interval"]))
    previous_end: dict[str, int] = {}
    for episode in episodes:
        node = episode["node"]
        if node in previous_end and episode["start_interval"] <= previous_end[node]:
            raise ValueError("Episode spans overlap or touch without a normal gap")
        previous_end[node] = episode["end_interval"]
    return {
        "schema_version": 2, "source_id": data["source_id"],
        "lineage_id": data["lineage_id"],
        "provenance": data["provenance"],
        "annotation_basis": data["annotation_basis"],
        "measurements": normalized["measurements"],
        "episodes": episodes,
    }


def load_episodic(path: Path) -> dict[str, Any]:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Episodic input exceeds 1 MiB")
    return validate_episodic(json.loads(
        p.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("Nonfinite JSON value"))))


def capture_digest(rows: list[dict]) -> str:
    """Detect literal duplicate measurement captures across both schema types."""
    canonical = json.dumps(rows, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def audit_episodic(data: dict) -> dict:
    d = validate_episodic(data)
    return {
        "source_id": d["source_id"], "lineage_id": d["lineage_id"],
        "provenance": d["provenance"],
        "annotation_basis": d["annotation_basis"],
        "measurement_rows": len(d["measurements"]),
        "relative_intervals": len({
            row["interval_index"] for row in d["measurements"]}),
        "measurement_fingerprint_sha256": capture_digest(d["measurements"]),
        "annotation_count": len(d["episodes"]),
        "warning": (
            "Source lineage, verification flags and expert labels are unverified input claims."
        ),
    }


def _instant_features(rows: list[dict]) -> dict[int, dict[str, dict[str, float | None]]]:
    """Same-interval features from approved counters; no labels anywhere."""
    grouped: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for r in rows:
        grouped[(r["interval_index"], r["node"])].append(r)
    valid_by_epoch: dict[int, dict[str, float]] = defaultdict(dict)
    for (t, node), group in grouped.items():
        if not all(r["cu_verified_claim"] and r["quorum_verified_claim"]
                   for r in group):
            continue
        total = sum(r["reference_count"] for r in group)
        residual = sum(abs(r["reported_count"] - r["reference_count"])
                       for r in group) / total
        valid_by_epoch[t][node] = residual
    features: dict[int, dict[str, dict[str, float | None]]] = {}
    for t, known in valid_by_epoch.items():
        features[t] = {}
        for node, value in known.items():
            peers = [v for other, v in known.items() if other != node]
            contrast = (max(0., value - median(peers))
                        if len(peers) >= 2 else None)
            features[t][node] = {
                "cu_claimed_baseline": value,
                "zone_absolute": value,
                "zone_peer": contrast,
            }
    return features


def scan_alarms(measurements: list[dict],
                thresholds: dict[str, float]) -> dict:
    """Perform a time-ordered causal scan, no episodes/labels/source IDs.

    A rising alarm at t requires positive exceedance at both t-1 and t.
    Missing data resets the state; persistent conditions create one alert.
    """
    if set(thresholds) != {"zone_absolute", "zone_peer"}:
        raise ValueError("Expected two frozen zonal thresholds")
    if any(type(v) not in (int, float) or not 0 <= v < float("inf")
           for v in thresholds.values()):
        raise ValueError("Thresholds must be finite and nonnegative")
    instant = _instant_features(measurements)
    timeline = sorted({r["interval_index"] for r in measurements})
    alarms = {name: [] for name in DETECTORS}
    coverage = {name: 0 for name in DETECTORS}
    total_pairs = max(0, len(timeline) - 1) * len(MONITORED_NODES)
    for detector in DETECTORS:
        for node in MONITORED_NODES:
            previous: tuple[int, float] | None = None
            was_active = False
            for t in timeline:
                point = instant.get(t, {}).get(node, {}).get(detector)
                if point is None:
                    previous, was_active = None, False
                    continue
                if previous is None or t != previous[0] + 1:
                    was_active = False
                    previous = (t, point)
                    continue
                coverage[detector] += 1
                threshold = (
                    0. if detector == "cu_claimed_baseline"
                    else thresholds[detector])
                active = min(previous[1], point) > threshold
                if active and not was_active:
                    alarms[detector].append({"node": node, "interval_index": t})
                was_active = active
                previous = (t, point)
    return {
        "alarms": alarms,
        "eligible_pairs": coverage,
        "total_possible_pairs": total_pairs,
    }


def _episode_metrics(data: dict, scan: dict, detector: str) -> dict:
    annotations = data["episodes"]
    alarms = scan["alarms"][detector]
    found: set[int] = set()
    matched = 0
    detection_delays: list[int] = []
    false_outside = 0
    duplicate_inside = 0
    for alarm in alarms:
        possible = [
            (i, episode) for i, episode in enumerate(annotations)
            if episode["node"] == alarm["node"]
            # Both confirming points must lie WITHIN the labeled episode.
            and episode["start_interval"] + 1 <= alarm["interval_index"]
            < episode["end_interval"]
        ]
        unmatched = [pair for pair in possible if pair[0] not in found]
        if unmatched:
            idx, episode = unmatched[0]
            found.add(idx)
            matched += 1
            detection_delays.append(
                alarm["interval_index"] - episode["start_interval"])
        elif possible:
            duplicate_inside += 1
        else:
            false_outside += 1
    n = len(annotations)
    possible_pairs = sum(max(0, item["end_interval"] - item["start_interval"] - 1)
                         for item in annotations)
    covered_pairs = 0
    # Exposure calculation is based on VERIFIED data availability, not
    # episode labels during scanning. Avoid retrieving per-node raw rows in output.
    valid = _instant_features(data["measurements"])
    for episode in annotations:
        for t in range(episode["start_interval"] + 1,
                       episode["end_interval"]):
            if (valid.get(t - 1, {}).get(episode["node"], {}).get(detector) is not None
                    and valid.get(t, {}).get(episode["node"], {}).get(detector)
                    is not None):
                covered_pairs += 1
    return {
        "attack_episodes": n,
        "detected_episodes": matched,
        "missed_episodes": n - matched,
        "episode_recall": matched / n if n else None,
        "alerts": len(alarms),
        "matched_alerts": matched,
        "false_alerts_outside_episodes": false_outside,
        "duplicate_alerts_inside_episodes": duplicate_inside,
        "unmatched_alerts": len(alarms) - matched,
        "alert_precision": matched / len(alarms) if alarms else None,
        "mean_delay_intervals": mean(detection_delays)
        if detection_delays else None,
        "median_delay_intervals": median(detection_delays)
        if detection_delays else None,
        "max_delay_intervals": max(detection_delays)
        if detection_delays else None,
        "short_episodes_unconfirmable": sum(
            item["end_interval"] - item["start_interval"] < 2
            for item in annotations),
        "attack_confirmation_opportunities": possible_pairs,
        "eligible_attack_confirmation_pairs": covered_pairs,
        "eligible_pairs": scan["eligible_pairs"][detector],
        "total_possible_pairs": scan["total_possible_pairs"],
        "pair_coverage": (scan["eligible_pairs"][detector]
                          / scan["total_possible_pairs"]
                          if scan["total_possible_pairs"] else None),
    }


def evaluate_temporal(train: list[dict], holdout: list[dict]) -> dict:
    """Train on clean Stage-10 sources and evaluate Stage-11 episode annotations."""
    if not train or not holdout:
        raise ValueError("At least one train and holdout source required")
    clean_train = [validate_labeled(x) for x in train]
    testing = [validate_episodic(x) for x in holdout]
    combined = [*clean_train, *testing]
    source_ids = [x["source_id"] for x in combined]
    lineages = [x["lineage_id"] for x in combined]
    fingerprints = [capture_digest(x["measurements"]) for x in combined]
    if (len(set(source_ids)) != len(source_ids)
            or len(set(lineages)) != len(lineages)
            or len(set(fingerprints)) != len(fingerprints)):
        raise ValueError("Reused source, lineage or identical measurement capture")
    calibration = fit_thresholds(clean_train)
    rows = []
    pooled = {name: [] for name in DETECTORS}
    for data in testing:
        # The SCANNER gets only an ALLOWLIST of measurement rows and
        # already fitted thresholds; no source identity, time of attack
        # or episode annotations are available during detection.
        scan = scan_alarms(data["measurements"], calibration["thresholds"])
        for detector in DETECTORS:
            result = _episode_metrics(data, scan, detector)
            rows.append({
                "source_id": data["source_id"], "detector": detector,
                **result,
            })
            pooled[detector].append(result)
    summary = []
    for detector, group in pooled.items():
        episodes = sum(x["attack_episodes"] for x in group)
        detected = sum(x["detected_episodes"] for x in group)
        alarms = sum(x["alerts"] for x in group)
        matched = sum(x["matched_alerts"] for x in group)
        eligible = sum(x["eligible_pairs"] for x in group)
        possible = sum(x["total_possible_pairs"] for x in group)
        # Delay aggregation requires weights; per-source mean delay * n.
        delays = [x["mean_delay_intervals"] for x in group
                  if x["mean_delay_intervals"] is not None]
        weighted_delays = sum(x["mean_delay_intervals"] *
                              x["detected_episodes"] for x in group
                              if x["mean_delay_intervals"] is not None)
        summary.append({
            "detector": detector,
            "attack_episodes": episodes,
            "detected_episodes": detected,
            "episode_recall": detected / episodes if episodes else None,
            "alerts": alarms,
            "matched_alerts": matched,
            "unmatched_alerts": alarms - matched,
            "false_alerts_outside_episodes": sum(
                x["false_alerts_outside_episodes"] for x in group),
            "duplicate_alerts_inside_episodes": sum(
                x["duplicate_alerts_inside_episodes"] for x in group),
            "alert_precision": matched / alarms if alarms else None,
            "mean_delay_intervals": (weighted_delays / detected
                                     if detected else None),
            "pair_coverage": eligible / possible if possible else None,
            "eligible_pairs": eligible,
            "total_possible_pairs": possible,
            "short_episodes_unconfirmable": sum(
                x["short_episodes_unconfirmable"] for x in group),
            "attack_confirmation_opportunities": sum(
                x["attack_confirmation_opportunities"] for x in group),
            "eligible_attack_confirmation_pairs": sum(
                x["eligible_attack_confirmation_pairs"] for x in group),
        })
    return {
        "method": "causal onset-agnostic 2-epoch alert onset; one-to-one matching",
        "training": calibration,
        "train_sources": [{"source_id": x["source_id"],
                           "lineage_id": x["lineage_id"],
                           "fingerprint_sha256": capture_digest(x["measurements"])}
                          for x in clean_train],
        "holdout_sources": [audit_episodic(x) for x in testing],
        "per_source": rows, "overall": summary,
        "limitations": [
            "All committed examples are synthetic and do not validate operator security",
            "Unknown onset is supplied only to the evaluator, never the detector",
            "Verification flags, provenance and expert labels are asserted, not verified",
            "A 2-interval confirmation cannot detect a 1-interval episode",
            "Only the first alarm for each episode can count as a matched alarm",
            "Metrics measure episode detection and interval delay, not packet-level rates",
            "Differences in source and lineage IDs do not prove physical independence",
            "No 3GPP conformance, cryptographic evidence or learned ML implied",
        ],
    }


def run_temporal_eval(train_paths: list[Path],
                      holdout_paths: list[Path]) -> dict:
    return evaluate_temporal(
        [validate_labeled(load_labeled_file(p)) for p in train_paths],
        [load_episodic(p) for p in holdout_paths],
    )


def load_labeled_file(path: Path) -> dict:
    # Delay imports to retain a small, dependency-free command surface.
    from .labeled_aggregates import load_labeled
    return load_labeled(path)
