"""Research-only HMAC verification of control-unit node reports.

The root key lives inside the simulation. It is never exported as an event
field. This is not production PKI, secure key storage or a 3GPP protocol.
"""
from __future__ import annotations

import hashlib
import hmac
import json


def sign_cu_report(root_key: bytes, node: str, nonce: str,
                   counts: dict[str, int]) -> str:
    if (not isinstance(root_key, bytes) or not isinstance(node, str)
            or not isinstance(nonce, str) or not isinstance(counts, dict)
            or len(counts) > 256 or any(
                not isinstance(k, str) or type(v) is not int
                or not 0 <= v <= 10**9 for k, v in counts.items())):
        raise ValueError("Invalid laboratory CU report")
    data = json.dumps(
        {"node": node, "nonce": nonce, "counts": counts},
        sort_keys=True, separators=(",", ":")).encode()
    node_key = hmac.new(root_key, node.encode(), hashlib.sha256).digest()
    return hmac.new(node_key, data, hashlib.sha256).hexdigest()


def verify_cu_report(root_key: bytes, node: str, nonce: str,
                     counts: dict[str, int], signature: str) -> bool:
    if not isinstance(signature, str):
        return False
    try:
        expected = sign_cu_report(root_key, node, nonce, counts)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)
