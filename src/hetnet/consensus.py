"""Three independent simulated monitoring domains with 2-of-3 quorum.

This is an explicit fault-assumption experiment, NOT a consensus protocol for
production networks. Signed observer votes demonstrate integrity only, not
honesty. Two colluding observers can deceive the majority by construction.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import hmac
import json
from typing import Any

# Fixed, simulated administrative/trust domains; not physical geolocations.
OBSERVER_DOMAINS = {
    "tap-legacy": "legacy-probe-domain",
    "tap-epc": "epc-probe-domain",
    "tap-5gc": "5gc-probe-domain",
}


def _canonical_counts(counts: dict[str, int]) -> bytes:
    if (not isinstance(counts, dict) or len(counts) > 256
            or any(not isinstance(key, str) or not key or len(key) > 128
                   or type(value) is not int or value < 0 or value > 10**9
                   for key, value in counts.items())):
        raise ValueError("Invalid observer counter vector")
    return json.dumps(counts, sort_keys=True, separators=(",", ":")).encode()


def _vote_bytes(observer: str, node: str, nonce: str, at_ms: int,
                counts: dict[str, int]) -> bytes:
    return json.dumps({
        "observer": observer, "node": node, "nonce": nonce,
        "at_ms": at_ms, "counts": counts,
    }, sort_keys=True, separators=(",", ":")).encode()


def sign_vote(root_key: bytes, observer: str, node: str, nonce: str,
              at_ms: int, counts: dict[str, int]) -> str:
    """Create a deterministic *lab-only* observer HMAC for a particular epoch."""
    if observer not in OBSERVER_DOMAINS:
        raise ValueError("Unknown observer")
    _canonical_counts(counts)
    derived = hmac.new(root_key, ("observer/" + observer).encode(),
                       hashlib.sha256).digest()
    return hmac.new(derived, _vote_bytes(observer, node, nonce, at_ms, counts),
                    hashlib.sha256).hexdigest()


def consensus_from_votes(
    votes: list[dict[str, Any]], root_key: bytes, node: str, nonce: str,
    now_ms: int, quorum: int = 2, max_age_ms: int = 1000,
) -> dict[str, Any]:
    """Independently verify votes and choose only a multi-domain majority.

    Each observer contributes at most one vote, even if its report is replayed.
    A majority of compromised observers remains an unavoidable failure mode.
    The caller's attack labels are never read here.
    """
    if not isinstance(votes, list) or len(votes) > 20:
        raise ValueError("Invalid observer vote list")
    if quorum < 2 or quorum > len(OBSERVER_DOMAINS):
        raise ValueError("Require at least two independent monitoring domains")
    if max_age_ms < 0:
        raise ValueError("max_age_ms must be >= 0")
    accepted: dict[str, dict[str, int]] = {}
    invalid: list[str] = []
    missing: list[str] = []
    seen: set[str] = set()
    for vote in votes:
        if not isinstance(vote, dict):
            invalid.append("malformed")
            continue
        observer = vote.get("observer")
        if observer not in OBSERVER_DOMAINS or observer in seen:
            invalid.append(str(observer))
            continue
        seen.add(observer)
        if vote.get("delivered") is False:
            missing.append(observer)
            continue
        timestamp = vote.get("at_ms")
        counts = vote.get("counts")
        if (type(timestamp) is not int or timestamp > now_ms
                or now_ms - timestamp > max_age_ms
                or vote.get("domain") != OBSERVER_DOMAINS[observer]
                or vote.get("node") != node
                or vote.get("nonce") != nonce
                or not isinstance(vote.get("mac"), str)):
            invalid.append(observer)
            continue
        try:
            expected = sign_vote(root_key, observer, node, nonce,
                                 timestamp, counts)
        except (ValueError, TypeError):
            invalid.append(observer)
            continue
        if not hmac.compare_digest(expected, vote["mac"]):
            invalid.append(observer)
            continue
        accepted[observer] = counts
    missing.extend(sorted(set(OBSERVER_DOMAINS) - seen))
    groups: dict[bytes, list[str]] = {}
    for observer, counts in accepted.items():
        groups.setdefault(_canonical_counts(counts), []).append(observer)
    winner = max(groups.items(), key=lambda group: len(group[1])) if groups else None
    has_quorum = winner is not None and len(winner[1]) >= quorum
    if has_quorum:
        support = sorted(winner[1])
        consensus_counts = json.loads(winner[0].decode())
        digest = hashlib.sha256(winner[0]).hexdigest()
        status = "quorum"
    else:
        support, consensus_counts, digest = [], None, None
        status = "split" if len(accepted) >= quorum else "insufficient"
    return {
        "status": status, "quorum": bool(has_quorum),
        "supporters": support,
        "support_count": len(support),
        "consensus_counts": consensus_counts,
        "consensus_sha256": digest,
        "outlier_observers": sorted(set(accepted) - set(support))
        if has_quorum else [],
        "valid_observers": sorted(accepted),
        "invalid_observers": sorted(invalid),
        "missing_observers": sorted(set(missing)),
        "valid_votes": len(accepted),
        "quorum_size": quorum,
        "independent_domains": sorted(
            OBSERVER_DOMAINS[observer] for observer in support),
        "assumption": "Independent honest-majority, lab-only HMAC",
    }
