"""Multi-generation node cohorts under common-cause monitoring domain faults.

Truth labels are selected by the experiment configuration and never passed to
the observer verifier or CU classifier. Results describe this synthetic setup,
not externally measured security or 3GPP protocol compliance.
"""
from __future__ import annotations

from collections import defaultdict
from statistics import mean, stdev
from typing import Any

from .experiment import rates
from .fault_domains import FAULT_CASES, MONITORED_NODES
from .simulator import Scenario, Simulator
from .domain_analysis import NODE_GENERATION

COHORTS: dict[str, tuple[str, ...]] = {
    "none": (),
    "legacy_5g": ("msc2", "amf5"),
    "epc_ims": ("mme4", "pcscf"),
    "four_generations": ("msc2", "sgsn3", "mme4", "amf5"),
}

UNCERTAIN = frozenset({
    "observer_quorum_unavailable", "unconfirmed_divergence",
    "insufficient_evidence", "telemetry_degraded",
})


def multi_node_study(
    *, seeds: tuple[int, ...] = (42, 43, 44, 45, 46, 47),
    fault_cases: tuple[str, ...] = (
        "none", "epc_outage", "epc_5gc_outage",
        "epc_corrupt", "epc_5gc_collude"),
    cohort_names: tuple[str, ...] = ("none", "legacy_5g", "epc_ims"),
    fault_probability: float = 1.0,
    duration_s: int = 18,
    subscribers: int = 8,
) -> dict[str, Any]:
    if (not seeds or not fault_cases or not cohort_names
            or len(set(seeds)) != len(seeds)):
        raise ValueError("Nonempty unique seeds, cases and cohorts required")
    if any(case not in FAULT_CASES for case in fault_cases):
        raise ValueError("Unknown correlated domain fault case")
    if any(name not in COHORTS for name in cohort_names):
        raise ValueError("Unknown compromised node cohort")
    if not 0 <= fault_probability <= 1:
        raise ValueError("fault_probability must be in [0,1]")

    records: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for seed in seeds:
        for case in fault_cases:
            for name in cohort_names:
                targets = COHORTS[name]
                result = Simulator(Scenario(
                    seed=seed, duration_s=duration_s, subscribers=subscribers,
                    inject_attacks=False, node_case="none",
                    report_fault_nodes=targets,
                    shared_zone_case=case,
                    shared_zone_probability=fault_probability,
                    loss_rate=0.0, observer_loss_rate=0.0,
                )).run()
                findings = {row["node"]: row for row in result["node_evidence"]["nodes"]}
                domain = result["domain_evidence"]["summary"]
                runs.append({
                    "seed": seed, "shared_zone_case": case,
                    "cohort": name, "target_count": len(targets),
                    "shared_missing_epochs": domain["epochs_with_shared_missing"],
                    "two_domain_missing_epochs":
                        domain["epochs_with_two_missing_domains"],
                    "correlated_quorum_loss_epochs":
                        domain["epochs_with_quorum_loss"],
                    "shared_outlier_epochs": domain["epochs_with_shared_outlier"],
                })
                for node in MONITORED_NODES:
                    row = findings[node]
                    records.append({
                        "seed": seed, "shared_zone_case": case, "cohort": name,
                        "node": node, "generation": NODE_GENERATION[node],
                        "ground_truth": node in targets,
                        "detected":
                            row["classification"] == "persistent_report_divergence",
                        "classification": row["classification"],
                        "quorum_confirmed": row["observer_quorum_present"],
                        "quorum_unavailable": row["observer_quorum_missing"],
                        "uncertain": row["classification"] in UNCERTAIN,
                    })

    groups = []
    for case in fault_cases:
        observations = [r for r in records if r["shared_zone_case"] == case]
        scores = rates(observations)
        seed_scores = []
        for seed in seeds:
            subset = [r for r in observations if r["seed"] == seed]
            seed_scores.append(rates(subset))
        filtered_runs = [run for run in runs if run["shared_zone_case"] == case]
        groups.append({
            "shared_zone_case": case, **scores,
            "records": len(observations),
            "uncertain_node_records": sum(r["uncertain"] for r in observations),
            "mean_quorum_confirmed":
                mean(r["quorum_confirmed"] for r in observations),
            "mean_quorum_unavailable":
                mean(r["quorum_unavailable"] for r in observations),
            "mean_correlated_quorum_loss_epochs":
                mean(row["correlated_quorum_loss_epochs"] for row in filtered_runs),
            "mean_shared_missing_epochs":
                mean(row["shared_missing_epochs"] for row in filtered_runs),
            "seed_recall_mean": mean(r["recall"] for r in seed_scores),
            "seed_recall_sd": stdev(r["recall"] for r in seed_scores)
            if len(seed_scores) > 1 else 0.0,
        })
    by_generation = []
    for gen in sorted(set(NODE_GENERATION.values())):
        selected = [row for row in records if row["generation"] == gen]
        by_generation.append({"generation": gen, **rates(selected)})
    return {
        "method": "multi-generation CU reports + cross-node signed-domain correlation",
        "truth_source": "configured report_fault_nodes, not detector event labels",
        "seeds": list(seeds), "fault_cases": list(fault_cases),
        "cohorts": {k: list(COHORTS[k]) for k in cohort_names},
        "fault_probability": fault_probability,
        "runs": runs, "node_records": records, "groups": groups,
        "by_generation": by_generation,
        "limitations": [
            "One shared synthetic transit count source under all virtual monitors",
            "No real physical monitoring independence or correlated operator traces",
            "Colluding majority can frame honest nodes or hide forged node reports",
            "Faults synchronized per polling epoch; no real inter-site propagation",
            "Independent seeds do not imply independent deployment populations",
            "Rates apply to seeded scenarios only, not network-wide threat prevalence",
        ],
    }
