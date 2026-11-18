"""Benign domain-shift stress matrix for false alarm evaluation.

No attack injection occurs in stress conditions. A positive result is therefore
a false alarm; no recall/precision are reported for this all-negative dataset.
"""
from __future__ import annotations

from statistics import mean
from typing import Any

from .episode import OfflineDetector, evaluate_episodes
from .simulator import Scenario, Simulator


def benign_stress(
    training_seeds: tuple[int, ...] = (21, 22, 23, 24, 25),
    test_seeds: tuple[int, ...] = (42, 43, 44),
    duration_s: int = 18,
    subscribers: int = 8,
    traffic_scales: tuple[float, ...] = (1.0, 8.0, 20.0),
    loss_rates: tuple[float, ...] = (0.0, 0.03, 0.10),
    traffic_rates: dict[str, float] | None = None,
) -> dict[str, Any]:
    if (not training_seeds or not test_seeds
            or set(training_seeds) & set(test_seeds)):
        raise ValueError("Training and stress test seeds must be nonempty and disjoint")
    if not traffic_scales or not loss_rates:
        raise ValueError("At least one load and loss condition required")
    rates = traffic_rates or {}
    normal = [Simulator(Scenario(
        duration_s=duration_s, subscribers=subscribers, seed=seed,
        traffic_scale=1.0, loss_rate=0, inject_attacks=False,
        traffic_rates=rates,
    )).run() for seed in training_seeds]
    offline = OfflineDetector()
    offline.fit(normal, list(training_seeds))
    runs = []
    for scale in traffic_scales:
        for loss in loss_rates:
            for seed in test_seeds:
                result = Simulator(Scenario(
                    duration_s=duration_s, subscribers=subscribers, seed=seed,
                    traffic_scale=scale, loss_rate=loss,
                    traffic_rates=rates, inject_attacks=False,
                )).run()
                for detector, alarms in (
                    ("built_in", result["alerts"]),
                    ("offline", offline.detect(result["events"])),
                ):
                    evaluation = evaluate_episodes(result["events"], alarms)
                    if evaluation["positive_episodes"]:
                        raise AssertionError("Benign stress must have no attack labels")
                    runs.append({
                        "traffic_scale": scale, "loss_rate": loss,
                        "seed": seed, "detector": detector,
                        "false_positive_rate": evaluation["fpr"],
                        "false_positive_correlations": evaluation["fp"],
                        "negative_correlations": evaluation["negative_correlations"],
                        "queue_drops": result["summary"]["queue_drops"],
                        "lost_messages": result["summary"]["lost"],
                        "rejected_messages": result["summary"]["rejected"],
                    })
    grouped = {}
    for scale in traffic_scales:
        for loss in loss_rates:
            for detector in ("built_in", "offline"):
                group = [row for row in runs if
                         row["traffic_scale"] == scale
                         and row["loss_rate"] == loss
                         and row["detector"] == detector]
                grouped["{}:{}:{}".format(scale, loss, detector)] = {
                    "mean_fpr": mean(row["false_positive_rate"] for row in group),
                    "total_false_positive_correlations":
                        sum(row["false_positive_correlations"] for row in group),
                    "total_negative_correlations":
                        sum(row["negative_correlations"] for row in group),
                }
    return {
        "method": "all-benign load/loss domain shift vs nominal clean training",
        "training_seeds": list(training_seeds),
        "test_seeds": list(test_seeds),
        "traffic_scales": list(traffic_scales),
        "loss_rates": list(loss_rates),
        "offline_invite_threshold": offline.invite_threshold,
        "runs": runs,
        "conditions": grouped,
        "limitations": [
            "No attacks injected: recall and precision are not defined",
            "Rate/queue/timeout alarms may be expected effects of benign congestion",
            "Synthetic stress only; not validated against measured production traces",
        ],
    }
