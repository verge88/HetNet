"""Repeatable, protocol-stratified evaluation on synthetic event traces."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import csv
import json
from statistics import mean, stdev
from typing import Any

from .simulator import Scenario, Simulator


def classify_correlations(result: dict) -> dict[str, dict[str, Any]]:
    """Ground truth is isolated from detection; evaluate packet correlation IDs.

    CU and interworking are excluded because their alerts concern node state,
    not message-level ground truth. This is not a measured real-world ROC.
    """
    observations: dict[str, dict[str, Any]] = {}
    for event in result["events"]:
        if event["protocol"] in ("CU", "INTERWORKING"):
            continue
        key = event["correlation_id"]
        if not key:
            continue
        if key not in observations:
            observations[key] = {
                "ground_truth": False, "detected": False,
                "protocol": event["protocol"],
            }
        observations[key]["ground_truth"] |= bool(event["attack"])
    detected = {alert["correlation_id"] for alert in result["alerts"]}
    for corr, value in observations.items():
        value["detected"] = corr in detected
    return observations


def rates(rows: list[dict[str, Any]]) -> dict[str, float | int]:
    counts = Counter()
    for row in rows:
        actual, detected = row["ground_truth"], row["detected"]
        counts["tp" if actual and detected else
               "fn" if actual else
               "fp" if detected else "tn"] += 1
    tp, fp, fn, tn = (counts[name] for name in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "fpr": fpr, "f1": f1,
    }


def run_multiseed(duration_s: int = 18, subscribers: int = 8,
                  seeds: range | tuple[int, ...] = range(42, 52),
                  traffic_scale: float = 1.0,
                  inject_attacks: bool = True,
                  traffic_rates: dict[str, float] | None = None) -> dict[str, Any]:
    run_rows = []
    per_stack: dict[str, list[dict[str, float | int]]] = defaultdict(list)
    for seed in seeds:
        result = Simulator(Scenario(
            duration_s=duration_s, subscribers=subscribers, seed=seed,
            traffic_scale=traffic_scale, inject_attacks=inject_attacks,
            traffic_rates=traffic_rates or {},
        )).run()
        samples = list(classify_correlations(result).values())
        row = {"seed": seed, **rates(samples),
               "alerts": len(result["alerts"]),
               "messages": result["summary"]["total_messages"]}
        run_rows.append(row)
        by_stack: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sample in samples:
            by_stack[sample["protocol"]].append(sample)
        for name, stack_samples in by_stack.items():
            per_stack[name].append(rates(stack_samples))
    if not run_rows:
        raise ValueError("At least one seed is required")
    summary: dict[str, dict[str, float]] = {}
    for metric in ("precision", "recall", "fpr", "f1"):
        values = [float(row[metric]) for row in run_rows]
        summary[metric] = {
            "mean": mean(values),
            "sample_std": stdev(values) if len(values) > 1 else 0.0,
        }
    return {
        "method": "packet-correlation evaluation; CU/node anomalies excluded",
        "ground_truth_source": "simulated attack labels only",
        "seeds": [r["seed"] for r in run_rows],
        "runs": run_rows,
        "summary": summary,
        "per_stack": {
            stack: {
                metric: mean(float(row[metric]) for row in values)
                for metric in ("precision", "recall", "fpr", "f1")
            } for stack, values in sorted(per_stack.items())
        },
        "limitations": [
            "Synthetic, seeded inputs, not operator captures",
            "No ML model, training split, ROC/AUC or Wilcoxon comparison",
            "Benign losses/overloads may cause alarms",
            "Detection rates are for the included scenarios, not empirical deployment estimates",
        ],
    }


def export_experiment(result: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "experiment.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if result["runs"]:
        with (output / "experiment_runs.csv").open(
                "w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=result["runs"][0].keys())
            writer.writeheader()
            writer.writerows(result["runs"])
