"""Node-level experimental matrix: report tamper vs benign CU transport loss.

The detection algorithm receives CU event details only. Evaluation labels
come from the *selected scenario*, never from the detector input or alerts.
The test population is synthetic; this is not field validation.
"""
from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any

from .control import inspect_cu_events
from .experiment import rates
from .simulator import Scenario, Simulator

CASES = ("none", "report", "tamper", "both")
TARGETS = {"report": "dra", "tamper": "msc2"}


def node_study(seeds: tuple[int, ...] = (42, 43, 44, 45),
               loss_rates: tuple[float, ...] = (0.0, 0.1, 0.35),
               duration_s: int = 18, subscribers: int = 8,
               traffic_scale: float = 1.0,
               cases: tuple[str, ...] = CASES) -> dict[str, Any]:
    if not seeds or not loss_rates or not cases:
        raise ValueError("Nonempty seeds, losses and cases required")
    if any(case not in CASES for case in cases):
        raise ValueError("Unknown node_case")
    if any(not 0 <= loss <= 1 for loss in loss_rates):
        raise ValueError("Invalid CU/network loss probability")

    records = []
    for seed in seeds:
        for loss in loss_rates:
            for case in cases:
                simulated = Simulator(Scenario(
                    duration_s=duration_s, subscribers=subscribers,
                    seed=seed, loss_rate=loss, traffic_scale=traffic_scale,
                    inject_attacks=False, node_case=case,
                )).run()
                # Independent detector sees only CU event data.
                findings = inspect_cu_events(simulated["events"])["nodes"]
                for finding in findings:
                    node = finding["node"]
                    is_report_case = case in ("report", "both") and node == TARGETS["report"]
                    is_tamper_case = case in ("tamper", "both") and node == TARGETS["tamper"]
                    records.append({
                        "seed": seed, "loss_rate": loss, "case": case,
                        "node": node,
                        "classification": finding["classification"],
                        "delivered": finding["delivered"],
                        "missing": finding["missing"],
                        "observations": finding["observations"],
                        "coverage": finding["delivery_ratio"],
                        "report_truth": is_report_case,
                        "report_detected":
                            finding["classification"] == "persistent_report_divergence",
                        "tamper_truth": is_tamper_case,
                        "tamper_detected":
                            finding["classification"] == "report_integrity_failure",
                    })
    conditions = []
    for loss in loss_rates:
        group = [r for r in records if r["loss_rate"] == loss]
        for target in ("report", "tamper"):
            score = rates([{
                "ground_truth": r[target + "_truth"],
                "detected": r[target + "_detected"],
            } for r in group])
            conditions.append({
                "loss_rate": loss,
                "target": target,
                **score,
                "mean_cu_coverage": mean(r["coverage"] for r in group
                                         if r["coverage"] is not None),
                "uncertain_node_records": sum(
                    r["classification"] in (
                        "telemetry_degraded", "insufficient_evidence",
                        "unconfirmed_divergence")
                    for r in group),
            })
    return {
        "method": "CU/independent-transit classifier vs separately configured node-level truth",
        "seeds": list(seeds),
        "loss_rates": list(loss_rates),
        "cases": list(cases),
        "controls": {
            "reporting_node": TARGETS["report"],
            "on_path_tamper": TARGETS["tamper"],
            "inject_attacks": False,
            "min_report_confirmations": 2,
        },
        "node_records": records,
        "conditions": conditions,
        "limitations": [
            "Synthetic two-hop CU loss, not observed packet captures",
            "Authenticated divergence is not proof the reporting node is compromised",
            "Integrity failures are not attributed to node compromise",
            "Missing CUs mean uncertainty; high loss may prevent confirmations",
            "Only one report and one on-path tamper node are exercised",
            "Full 3GPP/ITU-T wire conformance and ML detection are outside scope",
        ],
    }
