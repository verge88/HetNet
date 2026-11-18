"""Descriptive CU zone features aligned with dissertation §§3.3.3, 3.4.4.

Each epoch is a logical zone of six heterogeneous monitored nodes. Only
delivered and independently reverified CU/observer reports contribute to
medians, means, z-scores, MAD, ranks or leave-one-out contrasts.

These features are DESCRIPTIVE. No trained model or 3GPP-compliant zone
security function is inferred from them. Similar traffic distributions across
2G/3G/4G/IMS/5G are NOT assumed; volume is normalized per node.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean, median, pstdev
from typing import Any

from .attestation import verify_cu_report
from .consensus import consensus_from_votes
from .domain_analysis import NODE_GENERATION
from .fault_domains import MONITORED_NODES


def _count_error(expected: dict[str, int], reported: dict[str, int],
                 tolerance: int) -> tuple[int, int]:
    deviations = [abs(reported.get(k, 0) - expected.get(k, 0))
                  for k in (reported.keys() | expected.keys())]
    return sum(deviations), sum(max(0, delta - tolerance) for delta in deviations)


def zonal_features(
    events: list[dict[str, Any]], *,
    observer_root_key: bytes, cu_root_key: bytes,
    max_count_delta: int = 0, min_peers: int = 3,
) -> dict[str, Any]:
    """Produce per-epoch peer statistics without attack metadata leakage."""
    if type(max_count_delta) is not int or not 0 <= max_count_delta <= 100:
        raise ValueError("max_count_delta must be a nonnegative integer <=100")
    if type(min_peers) is not int or not 3 <= min_peers <= len(MONITORED_NODES):
        raise ValueError("min_peers must be between 3 and monitored node count")
    by_epoch: dict[int, list[dict]] = defaultdict(list)
    for item in events:
        if (item.get("protocol") == "CU"
                and item.get("operation") == "CU.Reconciliation"
                and item.get("source") in MONITORED_NODES):
            by_epoch[item["time_ms"]].append(item)
    rows = []
    features = []
    excluded = Counter()
    for epoch, events_in_epoch in sorted(by_epoch.items()):
        nodes: dict[str, list[dict]] = defaultdict(list)
        for item in events_in_epoch:
            nodes[item["source"]].append(item)
        valid = []
        for node, entries in sorted(nodes.items()):
            if len(entries) != 1:
                excluded["duplicate_node"] += 1
                continue
            item = entries[0]
            detail = item.get("detail") or {}
            if detail.get("cu_delivered") is not True:
                excluded["cu_unavailable"] += 1
                continue
            report = detail.get("reported_counts")
            if not isinstance(report, dict) or not verify_cu_report(
                    cu_root_key, node, item["correlation_id"], report,
                    detail.get("report_signature")):
                excluded["invalid_cu_signature"] += 1
                continue
            decision = consensus_from_votes(
                detail.get("observer_votes", []), observer_root_key,
                node, item["correlation_id"], epoch,
                max_count_delta=max_count_delta)
            if not decision["quorum"]:
                excluded["observer_quorum_unavailable"] += 1
                continue
            expected = decision["consensus_counts"]
            mismatch, excess = _count_error(expected, report, max_count_delta)
            denom = max(1, sum(expected.values()))
            valid.append({
                "node": node, "generation": NODE_GENERATION[node],
                "observed_volume": sum(expected.values()),
                "reported_volume": sum(report.values()),
                "raw_discrepancy": mismatch,
                "excess_discrepancy": excess,
                "excess_ratio": excess / denom,
                "quorum_support": decision["support_count"],
            })
        values = [v["excess_ratio"] for v in valid]
        n = len(values)
        avg = mean(values) if values else None
        med = median(values) if values else None
        deviation = pstdev(values) if values else None
        absolute_median_deviation = (
            median([abs(v - med) for v in values]) if values else None)
        ranks = {v: ix + 1 for ix, v in enumerate(sorted(set(values), reverse=True))}
        for data in valid:
            value = data["excess_ratio"]
            peers = [other["excess_ratio"] for other in valid
                     if other["node"] != data["node"]]
            comparison = median(peers) if len(peers) >= min_peers - 1 else None
            features.append({
                **data, "time_ms": epoch,
                "zone_peer_count": n,
                "zone_median": med, "zone_mean": avg,
                "zone_population_sd": deviation,
                "zone_mad": absolute_median_deviation,
                "delta_from_zone_median": value - med,
                "peer_median_excluding_self": comparison,
                "delta_from_peer_median":
                    (value - comparison) if comparison is not None else None,
                "zone_zscore": ((value - avg) / deviation
                                if deviation > 0 else 0.0),
                "zone_robust_zscore": (
                    0.6745 * (value - med) / absolute_median_deviation
                    if absolute_median_deviation > 0 else
                    0.0 if value == med else None),
                "zone_rank_desc": ranks[value],
            })
        rows.append({
            "time_ms": epoch, "valid_nodes": n,
            "excluded_nodes": len(MONITORED_NODES) - n,
            "median_excess_ratio": med, "mean_excess_ratio": avg,
            "population_sd": deviation, "median_absolute_deviation":
                absolute_median_deviation,
            "generations_covered": sorted({v["generation"] for v in valid}),
            "peer_statistics_valid": n >= min_peers,
        })
    return {
        "method": "per-epoch descriptive normalized CU residuals, zone median/z/rank",
        "quorum_tolerance": max_count_delta,
        "min_peers": min_peers,
        "epochs": rows,
        "features": features,
        "exclusions": dict(sorted(excluded.items())),
        "summary": {
            "epochs": len(rows), "node_features": len(features),
            "epochs_with_sufficient_peers":
                sum(row["peer_statistics_valid"] for row in rows),
            "max_excess_ratio": max((v["excess_ratio"] for v in features),
                                    default=None),
        },
        "limitations": [
            "All virtual probes share the synthetic source stream",
            "Zone groups are mixed-protocol; only normalized residuals compared",
            "Zonal z-scores are descriptive, not trained detection claims",
            "Zero MAD with nonmedian values gives null robust z-score",
            "Incomplete quorum/invalid report signatures excluded, never imputed as normal",
        ],
    }
