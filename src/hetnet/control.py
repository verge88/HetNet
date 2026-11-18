"""Evidence-based, control-unit analysis independent from attack labels.

This module consumes only exported CU.Reconciliation events. It distinguishes
an authenticated counter mismatch from an on-path MAC failure and missing CU
telemetry. All findings are *research indicators*, not proof of intrusion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class _NodeState:
    delivered: int = 0
    missing: int = 0
    authenticated_matches: int = 0
    authenticated_mismatches: int = 0
    invalid_macs: int = 0
    longest_mismatch_streak: int = 0
    mismatch_streak: int = 0
    longest_missing_streak: int = 0
    missing_streak: int = 0
    last_ms: int = 0
    evidence_correlation_ids: list[str] = field(default_factory=list)


def inspect_cu_events(events: list[dict[str, Any]],
                      min_confirmations: int = 2) -> dict[str, Any]:
    """Classify nodes without consulting injection flags or security alerts.

    Repeated *authenticated* report-versus-observer disagreement supports
    report/observation divergence; it does not prove which side is wrong.
    MAC failures may be on-path modification and must not be attributed to
    node compromise. Missing reports may be ordinary transport loss.
    """
    if min_confirmations < 1:
        raise ValueError("min_confirmations must be positive")
    nodes: dict[str, _NodeState] = {}
    cu = sorted((item for item in events
                 if item.get("protocol") == "CU"
                 and item.get("operation") == "CU.Reconciliation"),
                key=lambda item: (item["time_ms"], item["source"]))
    for event in cu:
        node = event["source"]
        state = nodes.setdefault(node, _NodeState())
        detail = event.get("detail", {})
        state.last_ms = event["time_ms"]
        if detail.get("cu_delivered", True) is False:
            state.missing += 1
            state.missing_streak += 1
            state.longest_missing_streak = max(
                state.longest_missing_streak, state.missing_streak)
            state.mismatch_streak = 0
            continue
        state.delivered += 1
        state.missing_streak = 0
        if detail.get("mac_valid") is not True:
            state.invalid_macs += 1
            state.mismatch_streak = 0
            state.evidence_correlation_ids.append(event["correlation_id"])
            continue
        reported = detail.get("reported_total")
        observed = detail.get("observed_total")
        if (not isinstance(reported, int) or not isinstance(observed, int)
                or reported < 0 or observed < 0):
            # Unsupported/malformed telemetry must not become a security proof.
            state.mismatch_streak = 0
            continue
        vector_consistent = detail.get("observer_consistent")
        if vector_consistent is not None and not isinstance(vector_consistent, bool):
            state.mismatch_streak = 0
            continue
        mismatch = (not vector_consistent) if vector_consistent is not None else (
            reported != observed)
        if mismatch:
            state.authenticated_mismatches += 1
            state.mismatch_streak += 1
            state.longest_mismatch_streak = max(
                state.longest_mismatch_streak, state.mismatch_streak)
            state.evidence_correlation_ids.append(event["correlation_id"])
        else:
            state.authenticated_matches += 1
            state.mismatch_streak = 0

    result = []
    for node, state in sorted(nodes.items()):
        if state.longest_mismatch_streak >= min_confirmations:
            category = "persistent_report_divergence"
            reason = ("Signed reports repeatedly disagree with independent "
                      "transit counters; examine signer and observer integrity")
        elif state.invalid_macs:
            category = "report_integrity_failure"
            reason = ("Report MAC validation failed; source attribution "
                      "requires independent evidence")
        elif state.authenticated_mismatches:
            category = "unconfirmed_divergence"
            reason = ("Insufficient independent observations to confirm "
                      "a persistent report discrepancy")
        elif state.missing and state.authenticated_matches:
            category = "consistent_with_loss"
            reason = ("Available authenticated reports match independent "
                      "observations; some control-unit responses were lost")
        elif state.missing:
            category = "telemetry_degraded"
            reason = ("Control-unit replies are missing and trustworthy "
                      "comparison is unavailable; this is not proof of intrusion")
        elif state.authenticated_matches:
            category = "consistent"
            reason = "Received authenticated reports match transit observations"
        else:
            category = "insufficient_evidence"
            reason = "No trustworthy control-unit comparison available"
        total = state.delivered + state.missing
        result.append({
            "node": node,
            "classification": category,
            "reason": reason,
            "observations": total,
            "delivery_ratio": state.delivered / total if total else None,
            "delivered": state.delivered,
            "missing": state.missing,
            "authenticated_matches": state.authenticated_matches,
            "authenticated_mismatches": state.authenticated_mismatches,
            "invalid_macs": state.invalid_macs,
            "max_mismatch_streak": state.longest_mismatch_streak,
            "max_missing_streak": state.longest_missing_streak,
            "evidence_correlation_ids": state.evidence_correlation_ids[:100],
            "last_observed_ms": state.last_ms,
        })
    return {
        "method": "CU+independent-transit evidence, not attack labels",
        "min_confirmations": min_confirmations,
        "nodes": result,
        "categories": {
            "persistent_report_divergence":
                "possible reporting-node compromise or observer inconsistency",
            "report_integrity_failure":
                "possible transport modification; not equivalent to node compromise",
            "unconfirmed_divergence": "single signed discrepancy, not yet persistent",
            "telemetry_degraded": "missing CU with no trustworthy comparison",
            "consistent_with_loss": "received CU matches despite separate missing polls",
            "consistent": "no CU inconsistency in received reports",
            "insufficient_evidence": "cannot decide",
        },
    }
