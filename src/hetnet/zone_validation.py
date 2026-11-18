"""Reproducible fault-assumption study of multi-domain CU observers.

Scenario truth is used ONLY to score predictions. The detector receives
simulated signed CU and monitor-vote records, never a scenario label.
"""
from __future__ import annotations

from statistics import mean
from typing import Any

from .experiment import rates
from .simulator import Scenario, Simulator

OBSERVER_CASES = (
    "none", "one_faulty", "two_colluding", "outage", "mixed", "bad_mac", "stale",
)


def zone_study(
    seeds: tuple[int, ...] = (42, 43, 44, 45, 46, 47),
    observer_loss_rates: tuple[float, ...] = (0.0, 0.2, 0.45),
    observer_cases: tuple[str, ...] = OBSERVER_CASES,
    duration_s: int = 18,
    subscribers: int = 8,
) -> dict[str, Any]:
    if not seeds or not observer_cases or not observer_loss_rates:
        raise ValueError("At least one seed, observer case and loss rate required")
    if any(case not in OBSERVER_CASES for case in observer_cases):
        raise ValueError("Unknown observer fault case")
    if any(not 0 <= rate <= 1 for rate in observer_loss_rates):
        raise ValueError("Invalid observer loss probability")
    records: list[dict[str, Any]] = []
    for seed in seeds:
        for loss in observer_loss_rates:
            for observer_case in observer_cases:
                for node_case in ("none", "report"):
                    result = Simulator(Scenario(
                        seed=seed, duration_s=duration_s,
                        subscribers=subscribers, inject_attacks=False,
                        node_case=node_case, observer_case=observer_case,
                        observer_loss_rate=loss,
                    )).run()
                    findings = {row["node"]: row
                                for row in result["node_evidence"]["nodes"]}
                    dra = findings["dra"]
                    records.append({
                        "seed": seed,
                        "observer_loss_rate": loss,
                        "observer_case": observer_case,
                        "node_case": node_case,
                        "target_node": "dra",
                        "report_truth": node_case == "report",
                        "report_detected":
                            dra["classification"] == "persistent_report_divergence",
                        "classification": dra["classification"],
                        "minority_observer_outliers": dra["observer_outliers"],
                        "observer_invalid": dra["observer_invalid"],
                        "observer_missing": dra["observer_missing"],
                        "quorum_present": dra["observer_quorum_present"],
                        "quorum_unavailable": dra["observer_quorum_missing"],
                        "cu_delivered": dra["delivered"],
                        "cu_missing": dra["missing"],
                    })
    groups = []
    for loss in observer_loss_rates:
        for case in observer_cases:
            batch = [r for r in records if r["observer_loss_rate"] == loss
                     and r["observer_case"] == case]
            classification_metrics = rates([{
                "ground_truth": r["report_truth"],
                "detected": r["report_detected"],
            } for r in batch])
            groups.append({
                "observer_loss_rate": loss,
                "observer_case": case,
                **classification_metrics,
                "avg_observer_quorum_present":
                    mean(r["quorum_present"] for r in batch),
                "avg_observer_quorum_unavailable":
                    mean(r["quorum_unavailable"] for r in batch),
                "avg_detected_minorities":
                    mean(sum(r["minority_observer_outliers"].values()) for r in batch),
            })
    return {
        "method": "fixed synthetic observer domains; 2-of-3 signed quorum",
        "scenario_truth_source": "explicit Scenario.node_case only",
        "seeds": list(seeds), "observer_loss_rates": list(observer_loss_rates),
        "observer_cases": list(observer_cases),
        "test_nodes": ["dra"],
        "records": records,
        "groups": groups,
        "key_limitations": [
            "Two colluding signed monitors can spoof the majority and frame an honest CU reporter",
            "A single outlier is a discrepancy, not proof of which observer is malicious",
            "Observer loss is independent of CU transport loss by model design",
            "Trust-domain topology is logical; no independent physical capture is demonstrated",
            "Reported metrics are not 3GPP conformance or operator-grade detection rates",
        ],
    }
