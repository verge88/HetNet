"""Synthetic probe-miss and tolerant-quorum sensitivity experiments.

Truth labels are scenario-selected node cohorts; the CU/zone algorithms
receive only signed simulated measurements. Accuracy is *not* external.
"""
from __future__ import annotations

from statistics import mean, stdev
from typing import Any

from .cohort_validation import COHORTS
from .experiment import rates
from .fault_domains import MONITORED_NODES
from .simulator import Scenario, Simulator


def probe_study(
    *, seeds: tuple[int, ...] = (42, 43, 44, 45, 46, 47),
    capture_miss_rates: tuple[float, ...] = (0.0, 0.05, 0.15),
    tolerances: tuple[int, ...] = (0, 1, 2),
    cohorts: tuple[str, ...] = ("none", "legacy_5g"),
    duration_s: int = 18,
    subscribers: int = 8,
) -> dict[str, Any]:
    if not seeds or not capture_miss_rates or not tolerances or not cohorts:
        raise ValueError("Expected nonempty seed, miss, tolerance and cohort lists")
    if len(set(seeds)) != len(seeds):
        raise ValueError("Seeds must be unique")
    if any(name not in COHORTS for name in cohorts):
        raise ValueError("Unknown cohort")
    if any(type(rate) not in (int, float) or not 0 <= rate <= .5
           for rate in capture_miss_rates):
        raise ValueError("Capture-miss probabilities must be between 0 and .5")
    if any(type(v) is not int or not 0 <= v <= 100 for v in tolerances):
        raise ValueError("Tolerance must be integer 0..100")

    records = []
    runs = []
    for seed in seeds:
        for miss in capture_miss_rates:
            for tolerance in tolerances:
                for cohort in cohorts:
                    compromised = COHORTS[cohort]
                    result = Simulator(Scenario(
                        seed=seed, duration_s=duration_s,
                        subscribers=subscribers, inject_attacks=False,
                        node_case="none",
                        report_fault_nodes=compromised,
                        observer_capture_miss=miss,
                        quorum_max_count_delta=tolerance,
                    )).run()
                    findings = {x["node"]: x for x in
                                result["node_evidence"]["nodes"]}
                    coverage = result["zonal_evidence"]["summary"]
                    runs.append({
                        "seed": seed, "capture_miss_rate": miss,
                        "tolerance": tolerance, "cohort": cohort,
                        "valid_zonal_features": coverage["node_features"],
                        "sufficient_peer_epochs":
                            coverage["epochs_with_sufficient_peers"],
                        "missing_quorum_comparisons": sum(
                            row["observer_quorum_missing"]
                            for row in findings.values()),
                        "confirmed_quorum_comparisons": sum(
                            row["observer_quorum_present"]
                            for row in findings.values()),
                    })
                    for node in MONITORED_NODES:
                        state = findings[node]
                        records.append({
                            "seed": seed, "capture_miss_rate": miss,
                            "tolerance": tolerance, "cohort": cohort,
                            "node": node, "ground_truth": node in compromised,
                            "detected": state["classification"] ==
                            "persistent_report_divergence",
                            "classification": state["classification"],
                            "quorum_confirmed": state["observer_quorum_present"],
                            "quorum_missing": state["observer_quorum_missing"],
                        })
    groups = []
    for miss in capture_miss_rates:
        for tolerance in tolerances:
            observed = [r for r in records
                        if r["capture_miss_rate"] == miss
                        and r["tolerance"] == tolerance]
            scores = rates(observed)
            seed_scores = [
                rates([r for r in observed if r["seed"] == seed])
                for seed in seeds
            ]
            matched = [r for r in runs if r["capture_miss_rate"] == miss
                       and r["tolerance"] == tolerance]
            groups.append({
                "capture_miss_rate": miss,
                "tolerance": tolerance,
                **scores,
                "node_samples": len(observed),
                "mean_zonal_features":
                    mean(r["valid_zonal_features"] for r in matched),
                "mean_sufficient_peer_epochs":
                    mean(r["sufficient_peer_epochs"] for r in matched),
                "mean_missing_quorum_comparisons":
                    mean(r["missing_quorum_comparisons"] for r in matched),
                "seed_recall_mean":
                    mean(r["recall"] for r in seed_scores),
                "seed_recall_sample_sd":
                    stdev(r["recall"] for r in seed_scores)
                    if len(seed_scores) > 1 else 0.0,
            })
    return {
        "method": "synthetic per-observer Bernoulli missed counts and bounded quorum",
        "seeds": list(seeds),
        "capture_miss_rates": list(capture_miss_rates),
        "tolerances": list(tolerances),
        "cohorts": {name: list(COHORTS[name]) for name in cohorts},
        "runs": runs, "node_records": records, "groups": groups,
        "limitations": [
            "Measurement errors are independently sampled conditional on a SHARED synthetic truth stream",
            "No physical sensor independence, independent operator traces or calibrated real error law",
            "Tolerance is an assumed fixed absolute per-operation threshold",
            "High tolerance may hide signed forged counts of similar magnitude",
            "Detector is rule-based; zonal features are descriptive, not trained ML",
        ],
    }
