"""Source-held-out *synthetic* zonal alert benchmark.

Three intentionally different detection policies are evaluated on exactly the
same held-out node cases:
  1. existing signed-CU repeated-disagreement rule,
  2. trained absolute residual (two consecutive verified zone measurements),
  3. trained leave-one-node-out peer contrast (two consecutive measurements).

All thresholds are fitted on CLEAN synthetic training source profiles only.
Labels are read only by the scoring loop from scenario configuration, NEVER
by the detectors. A source ID and a distinct seed do not imply an independent
operator, physical measurement or true-world distribution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from math import isfinite
from statistics import mean, stdev
from typing import Any

from .cohort_validation import COHORTS
from .control import inspect_cu_events
from .experiment import rates
from .fault_domains import FAULT_CASES, MONITORED_NODES
from .simulator import Scenario, Simulator

DETECTORS = ("cu_signed_baseline", "zone_absolute", "zone_peer")
TINY = 1e-12


@dataclass(frozen=True)
class SourceProfile:
    source_id: str
    capture_miss: float = 0.0
    quorum_tolerance: int = 1
    shared_zone_case: str = "none"

    def validate(self) -> None:
        if (not isinstance(self.source_id, str) or len(self.source_id) < 3
                or len(self.source_id) > 48
                or not self.source_id.isascii()
                or not self.source_id.replace("_", "").replace("-", "").isalnum()
                or not self.source_id[0].isalpha()):
            raise ValueError("source_id must be an anonymous ASCII source slug")
        if (type(self.capture_miss) not in (int, float)
                or not isfinite(self.capture_miss)
                or not 0 <= self.capture_miss <= .5):
            raise ValueError("capture_miss must be finite and between 0 and 0.5")
        if (type(self.quorum_tolerance) is not int
                or not 0 <= self.quorum_tolerance <= 100):
            raise ValueError("quorum_tolerance must be integer 0..100")
        if self.shared_zone_case not in FAULT_CASES:
            raise ValueError("Invalid shared-zone scenario")


TRAIN_PROFILES = (
    SourceProfile("synthetic_fit_nominal", 0.0, 1),
    SourceProfile("synthetic_fit_capture", 0.05, 1),
)
TEST_PROFILES = (
    SourceProfile("synthetic_holdout_nominal", 0.0, 1),
    SourceProfile("synthetic_holdout_shift", 0.15, 1),
    SourceProfile("synthetic_holdout_outage", 0.05, 1, "epc_5gc_outage"),
    SourceProfile("synthetic_holdout_collusion", 0.0, 1, "epc_5gc_collude"),
)


def _tail_start(duration_s: int) -> int:
    # Predeclare the final-quarter observation window. CU compromises in the
    # benchmark begin at 72% by Scenario design, i.e. before this tail.
    return int(duration_s * 1000 * .75)


def _node_pair_scores(zonal: dict, *, start_ms: int,
                      interval_ms: int = 1500) -> dict[str, dict[str, float | None]]:
    """Aggregate consecutive verified *tail* epochs to one node-level score.

    A missing quorum, invalid CU signature or missing peer observations
    prevents a pair rather than becoming a fabricated score of zero.
    """
    if interval_ms < 1:
        raise ValueError("interval_ms must be positive")
    history: dict[str, list[dict]] = {node: [] for node in MONITORED_NODES}
    for item in zonal["features"]:
        if item["time_ms"] >= start_ms and item["node"] in history:
            history[item["node"]].append(item)
    result = {}
    for node, frames in history.items():
        ordered = sorted(frames, key=lambda x: x["time_ms"])
        possible = {"zone_absolute": [], "zone_peer": []}
        for first, second in zip(ordered, ordered[1:]):
            if second["time_ms"] - first["time_ms"] != interval_ms:
                continue
            absolute = (first["excess_ratio"], second["excess_ratio"])
            possible["zone_absolute"].append(max(0.0, min(absolute)))
            peer = (first["delta_from_peer_median"],
                    second["delta_from_peer_median"])
            if all(x is not None for x in peer):
                possible["zone_peer"].append(max(0.0, min(peer)))
        result[node] = {
            key: max(values) if values else None
            for key, values in possible.items()
        }
    return result


def _simulate(profile: SourceProfile, seed: int, cohort: str,
              duration_s: int, subscribers: int) -> tuple[dict, dict]:
    # The scenario settings and target labels are never passed to
    # inspect_cu_events() or to _node_pair_scores().
    simulator = Simulator(Scenario(
        seed=seed, duration_s=duration_s, subscribers=subscribers,
        inject_attacks=False, node_case="none",
        report_fault_nodes=COHORTS[cohort],
        observer_capture_miss=profile.capture_miss,
        quorum_max_count_delta=profile.quorum_tolerance,
        shared_zone_case=profile.shared_zone_case,
        cu_interval_ms=1500,
    ))
    result = simulator.run()
    start_ms = _tail_start(duration_s)
    tail_events = [event for event in result["events"]
                   if event["protocol"] == "CU"
                   and event["time_ms"] >= start_ms]
    cu = inspect_cu_events(
        tail_events, observer_root_key=simulator._observer_key,
        cu_root_key=simulator._cu_key,
        max_count_delta=profile.quorum_tolerance,
    )
    verified_cu = {n["node"]: n for n in cu["nodes"]}
    scores = _node_pair_scores(
        result["zonal_evidence"], start_ms=start_ms)
    return verified_cu, scores


def fit_zonal_thresholds(
    *, profiles: tuple[SourceProfile, ...] = TRAIN_PROFILES,
    seeds: tuple[int, ...] = (21, 22, 23, 24),
    duration_s: int = 18, subscribers: int = 8,
) -> dict[str, Any]:
    if not profiles or not seeds or len(set(seeds)) != len(seeds):
        raise ValueError("Training profiles and unique seeds required")
    if duration_s < 12:
        raise ValueError("At least 12s required for consecutive final-quarter CU observations")
    if len({p.source_id for p in profiles}) != len(profiles):
        raise ValueError("Training source IDs must be distinct")
    samples = {"zone_absolute": [], "zone_peer": []}
    per_source = []
    for profile in profiles:
        profile.validate()
        if profile.shared_zone_case != "none":
            raise ValueError("Training clean profiles cannot inject common-zone attacks/outages")
        count = {"zone_absolute": 0, "zone_peer": 0}
        for seed in seeds:
            _, scores = _simulate(profile, seed, "none", duration_s, subscribers)
            for node in MONITORED_NODES:
                for name in samples:
                    value = scores[node][name]
                    if value is not None:
                        samples[name].append(value)
                        count[name] += 1
        per_source.append({
            "source_id": profile.source_id,
            "capture_miss": profile.capture_miss,
            "quorum_tolerance": profile.quorum_tolerance,
            "valid_score_counts": count,
        })
    if any(not values for values in samples.values()):
        raise ValueError("No verified consecutive training measurements")
    # A deliberately conservative, explicitly documented "maximum clean"
    # rule, not a fitted FPR guarantee or held-out threshold optimization.
    thresholds = {name: max(values) + TINY for name, values in samples.items()}
    return {
        "method": "maximum clean source score plus epsilon; no attack labels",
        "training_source_ids": [p.source_id for p in profiles],
        "training_seeds": list(seeds),
        "tail_start_fraction": 0.75,
        "consecutive_interval_ms": 1500,
        "thresholds": thresholds,
        "per_source": per_source,
        "disclaimer": (
            "Thresholds are fitted on synthetic clean sources only; "
            "no guarantees on unseen sources or real networks."
        ),
    }


def _metrics(records: list[dict]) -> dict[str, Any]:
    scored = rates(records)
    missing = sum(row["abstained"] for row in records)
    positives = sum(row["ground_truth"] for row in records)
    negatives = len(records) - positives
    return {
        **scored,
        "samples": len(records),
        "positive_samples": positives,
        "negative_samples": negatives,
        "abstained": missing,
        "abstained_positive": sum(row["abstained"] and row["ground_truth"]
                                  for row in records),
        "abstained_negative": sum(row["abstained"] and not row["ground_truth"]
                                  for row in records),
        "coverage": 1 - missing / len(records) if records else None,
        "scoring_note": (
            "Abstentions conservatively count as not detected in confusion "
            "matrix; coverage reported separately."
        ),
    }


def heldout_comparison(
    *, training_profiles: tuple[SourceProfile, ...] = TRAIN_PROFILES,
    test_profiles: tuple[SourceProfile, ...] = TEST_PROFILES,
    train_seeds: tuple[int, ...] = (21, 22, 23, 24),
    test_seeds: tuple[int, ...] = (42, 43, 44, 45),
    cohort_names: tuple[str, ...] = ("none", "legacy_5g", "epc_ims"),
    duration_s: int = 18, subscribers: int = 8,
) -> dict[str, Any]:
    if (not training_profiles or not test_profiles or not train_seeds
            or not test_seeds or not cohort_names):
        raise ValueError("Nonempty training, holdout, seeds and cohorts required")
    if len(set(train_seeds)) != len(train_seeds) or len(set(test_seeds)) != len(test_seeds):
        raise ValueError("Seeds within each partition must be unique")
    if set(train_seeds) & set(test_seeds):
        raise ValueError("Training and holdout seeds must be disjoint")
    all_profiles = (*training_profiles, *test_profiles)
    if len({p.source_id for p in all_profiles}) != len(all_profiles):
        raise ValueError("Training and test source IDs must be disjoint")
    if any(name not in COHORTS for name in cohort_names):
        raise ValueError("Unknown node cohort")
    if "none" not in cohort_names or not any(COHORTS[name] for name in cohort_names):
        raise ValueError("Need both clean and attacked cohorts for scoring")
    for profile in all_profiles:
        profile.validate()
    calibration = fit_zonal_thresholds(
        profiles=training_profiles, seeds=train_seeds,
        duration_s=duration_s, subscribers=subscribers,
    )
    rows = []
    for profile in test_profiles:
        for seed in test_seeds:
            for cohort in cohort_names:
                checked, scores = _simulate(
                    profile, seed, cohort, duration_s, subscribers)
                for node in MONITORED_NODES:
                    truth = node in COHORTS[cohort]
                    for detector in DETECTORS:
                        if detector == "cu_signed_baseline":
                            # Gate the baseline to the same 2-consecutive
                            # verified tail observations as the zone detector.
                            available = scores[node]["zone_absolute"] is not None
                            detected = (available and node in checked
                                        and checked[node]["classification"] ==
                                        "persistent_report_divergence")
                            score = None
                            threshold = None
                        else:
                            score = scores[node][detector]
                            threshold = calibration["thresholds"][detector]
                            available = score is not None
                            detected = available and score > threshold
                        rows.append({
                            "source_id": profile.source_id,
                            "capture_miss": profile.capture_miss,
                            "shared_zone_case": profile.shared_zone_case,
                            "seed": seed, "cohort": cohort, "node": node,
                            "detector": detector,
                            "ground_truth": truth,
                            "detected": bool(detected),
                            "abstained": not available,
                            "score": score,
                            "threshold": threshold,
                        })
    tables = []
    for profile in test_profiles:
        for detector in DETECTORS:
            group = [row for row in rows if
                     row["source_id"] == profile.source_id
                     and row["detector"] == detector]
            tables.append({
                "source_id": profile.source_id,
                "capture_miss": profile.capture_miss,
                "shared_zone_case": profile.shared_zone_case,
                "detector": detector, **_metrics(group),
            })
    overall = [
        {"detector": detector, **_metrics([
            row for row in rows if row["detector"] == detector])}
        for detector in DETECTORS
    ]
    # Per-seed descriptive variability; source/scenario clusters are
    # correlated, so no unqualified confidence interval or p-value.
    for item in overall:
        detector = item["detector"]
        seed_recalls = [rates([
            row for row in rows if row["detector"] == detector
            and row["seed"] == seed])["recall"] for seed in test_seeds]
        item["per_seed_recall_mean"] = mean(seed_recalls)
        item["per_seed_recall_sample_sd"] = (
            stdev(seed_recalls) if len(seed_recalls) > 1 else 0.0)
    return {
        "method": "source/seed-disjoint synthetic comparison; node-level labels",
        "training": calibration,
        "test_sources": [asdict(profile) for profile in test_profiles],
        "test_seeds": list(test_seeds),
        "cohorts": {name: list(COHORTS[name]) for name in cohort_names},
        "detectors": list(DETECTORS),
        "per_source": tables,
        "overall": overall,
        "records": rows,
        "limitations": [
            "All sources are synthetic parameter settings, not independent operators",
            "Differences of source_id and seed cannot prove physical independence",
            "Known 72%-of-horizon attack onset informs predeclared final-quarter scoring",
            "Zonal scores use the same signed CU/observer inputs as the baseline",
            "Tail abstentions counted as negative for recall; coverage separately reported",
            "Two colluding observers can fabricate a majority and fool all rules",
            "No external attack labels, ML generalization or 3GPP conformance implied",
            "Repeated observations across scenarios and seeds are not independent sites",
        ],
    }
