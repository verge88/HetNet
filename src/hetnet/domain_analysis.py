"""Cross-node symptoms of shared monitoring-domain failures.

This correlates *verified* observer votes across multiple control targets.
It deliberately reports shared symptoms instead of attributing malicious
intent: an identical forged majority can make an honest minority look wrong.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .consensus import OBSERVER_DOMAINS, consensus_from_votes
from .fault_domains import MONITORED_NODES

NODE_GENERATION = {
    "msc2": "2G", "sgsn3": "3G", "mme4": "4G", "dra": "4G",
    "pcscf": "IMS", "amf5": "5G",
}


def analyze_domain_correlations(
    events: list[dict[str, Any]], observer_root_key: bytes,
    min_affected_nodes: int = 2,
    max_count_delta: int = 0,
) -> dict[str, Any]:
    """Find common absence/invalidity/outliers at the *same poll epoch*.

    Raw signed votes are reverified here. Precomputed quorum summaries,
    attack labels and scenario fault settings are intentionally ignored.
    Missing CU responses do not prevent observer-side vote assessment.
    """
    if not 2 <= min_affected_nodes <= len(MONITORED_NODES):
        raise ValueError("min_affected_nodes must be between 2 and monitored node count")
    if type(max_count_delta) is not int or not 0 <= max_count_delta <= 100:
        raise ValueError("max_count_delta must be an integer in [0,100]")
    epochs: dict[int, list[dict]] = defaultdict(list)
    for event in events:
        if (event.get("protocol") == "CU"
                and event.get("operation") == "CU.Reconciliation"
                and event.get("source") in MONITORED_NODES):
            epochs[event["time_ms"]].append(event)

    rows = []
    correlated_counts: Counter[str] = Counter()
    for epoch, batch in sorted(epochs.items()):
        # Duplicate node records cannot produce fake shared evidence.
        by_node = {event["source"]: event for event in batch}
        missing: dict[str, set[str]] = defaultdict(set)
        invalid: dict[str, set[str]] = defaultdict(set)
        outliers: dict[str, set[str]] = defaultdict(set)
        quorum_lost: set[str] = set()
        for node, event in sorted(by_node.items()):
            decision = consensus_from_votes(
                event.get("detail", {}).get("observer_votes", []),
                observer_root_key, node, event["correlation_id"], epoch,
                max_count_delta=max_count_delta)
            for observer in decision["missing_observers"]:
                if observer in OBSERVER_DOMAINS:
                    missing[observer].add(node)
            for observer in decision["invalid_observers"]:
                if observer in OBSERVER_DOMAINS:
                    invalid[observer].add(node)
            for observer in decision["outlier_observers"]:
                if observer in OBSERVER_DOMAINS:
                    outliers[observer].add(node)
            if not decision["quorum"]:
                quorum_lost.add(node)
        patterns = []
        for category, source in (
            ("shared_missing", missing), ("shared_invalid", invalid),
            ("shared_outlier", outliers),
        ):
            for observer in sorted(source):
                nodes = source[observer]
                if len(nodes) >= min_affected_nodes:
                    patterns.append({
                        "kind": category, "observer": observer,
                        "domain": OBSERVER_DOMAINS[observer],
                        "nodes": sorted(nodes),
                        "generations": sorted({NODE_GENERATION[n] for n in nodes}),
                        "affected_count": len(nodes),
                    })
                    correlated_counts[category] += 1
        down_observers = sorted(
            observer for observer, targets in missing.items()
            if len(targets) >= min_affected_nodes
        )
        bad_domains = [OBSERVER_DOMAINS[n] for n in down_observers]
        common_quorum_loss = len(quorum_lost) >= min_affected_nodes
        if common_quorum_loss:
            correlated_counts["cross_node_quorum_loss"] += 1
        rows.append({
            "time_ms": epoch, "monitored_nodes": len(by_node),
            "patterns": patterns,
            "missing_domains": bad_domains,
            "simultaneously_missing_domains": len(down_observers),
            "cross_node_quorum_loss": common_quorum_loss,
            "quorum_lost_nodes": sorted(quorum_lost),
            "quorum_lost_generations": sorted(
                {NODE_GENERATION[n] for n in quorum_lost}),
            "cross_generation_missing": any(
                len(p["generations"]) > 1 for p in patterns
                if p["kind"] == "shared_missing"),
        })
    return {
        "method": "same-epoch cross-node signed-witness symptom correlation",
        "min_affected_nodes": min_affected_nodes,
        "max_count_delta": max_count_delta,
        "epochs": rows,
        "summary": {
            "epochs_total": len(rows),
            "epochs_with_shared_missing": sum(
                any(p["kind"] == "shared_missing" for p in row["patterns"])
                for row in rows),
            "epochs_with_two_missing_domains": sum(
                row["simultaneously_missing_domains"] >= 2 for row in rows),
            "epochs_with_quorum_loss": sum(
                row["cross_node_quorum_loss"] for row in rows),
            "epochs_with_shared_outlier": sum(
                any(p["kind"] == "shared_outlier" for p in row["patterns"])
                for row in rows),
            "event_counts": dict(sorted(correlated_counts.items())),
        },
        "limitations": [
            "Correlated symptoms cannot attribute observer compromise",
            "All virtual observers are seeded from one simulated transit ground truth",
            "Shared fault injection is a synthetic administrative-domain assumption",
            "No geographic/physical independent taps, real clocks or key management",
        ],
    }
