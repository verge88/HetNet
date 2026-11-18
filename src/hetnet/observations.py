"""Research windows for cross-stack observations (thesis tables 3.2/4.1)."""
from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median


# 5G and GTP windows are extensions, not thesis-specified values.
WINDOW_SECONDS = {
    "SS7/MAP": 30, "Diameter": 15, "SIP/IMS": 20,
    "GTPv2-C": 15, "5G-SBI/HTTP2": 10,
}


def aggregate(events: list[dict]) -> list[dict]:
    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for event in events:
        stack = event["protocol"]
        if stack not in WINDOW_SECONDS:
            continue
        width_ms = WINDOW_SECONDS[stack] * 1000
        start = event["time_ms"] // width_ms * width_ms
        groups[(start, event["source"], stack)].append(event)
    records = []
    for (start, source, stack), group in sorted(groups.items()):
        outcomes = Counter(item["outcome"] for item in group)
        latencies = sorted(
            item["latency_ms"] for item in group
            if item["outcome"] == "DELIVERED")
        p95 = (latencies[min(len(latencies) - 1,
                             (95 * len(latencies) + 99) // 100 - 1)]
               if latencies else None)
        records.append({
            "start_ms": start,
            "end_ms": start + WINDOW_SECONDS[stack] * 1000,
            "source": source,
            "protocol": stack,
            "generation": group[0]["generation"],
            "total": len(group),
            "delivered": outcomes["DELIVERED"],
            "rejected": outcomes["REJECTED"],
            "lost": outcomes["LOST"],
            "congested": outcomes["CONGESTED"],
            "attack_labeled": sum(bool(g["attack"]) for g in group),
            "latency_median_ms": median(latencies) if latencies else None,
            "latency_p95_ms": p95,
            "operations": dict(sorted(Counter(g["operation"] for g in group).items())),
        })
    return records
