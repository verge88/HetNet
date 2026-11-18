"""Episode-based ground-truth evaluation, distinct from packet correlation scores."""
from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean, stdev
from typing import Any

from .experiment import rates
from .simulator import RULES, Scenario, Simulator, default_topology

_INTERNAL = {"CU", "INTERWORKING"}
_AUTOMATIC_SIP = {"SIP.ACK", "SIP.BYE"}


def episodes(events: list[dict], gap_ms: int = 1000) -> list[dict]:
    """Group attack-originated requests by protocol, source, subject and time.

    Only the evaluation layer reads attack labels. Automatically generated
    replies and SIP ACK/BYE are not counted as separate attack episodes.
    Benign samples remain individual independent correlation IDs.
    """
    if gap_ms < 0:
        raise ValueError("gap_ms must be nonnegative")
    messages = [e for e in events if e["protocol"] not in _INTERNAL
                and e["correlation_id"]]
    truth: dict[str, bool] = {}
    for e in messages:
        cid = e["correlation_id"]
        truth[cid] = truth.get(cid, False) or bool(e["attack"])
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for e in messages:
        if (e["attack"] and e["operation"] in RULES
                and e["operation"] not in _AUTOMATIC_SIP):
            groups[(e["protocol"], e["source"], e["subject"])].append(e)
    positives = []
    for (protocol, source, subject), batch in sorted(groups.items()):
        episode: dict | None = None
        for e in sorted(batch, key=lambda item: (item["time_ms"],
                                                  item["correlation_id"])):
            if episode is None or e["time_ms"] - episode["end_ms"] > gap_ms:
                episode = {
                    "ground_truth": True, "protocol": protocol,
                    "source": source, "subject": subject,
                    "start_ms": e["time_ms"], "end_ms": e["time_ms"],
                    "correlations": [], "messages": 0,
                }
                positives.append(episode)
            episode["end_ms"] = e["time_ms"]
            episode["messages"] += 1
            if e["correlation_id"] not in episode["correlations"]:
                episode["correlations"].append(e["correlation_id"])
    # Nonattack correlations in the generated trace provide negative controls.
    seen = set()
    negatives = []
    for e in messages:
        cid = e["correlation_id"]
        if truth[cid] or cid in seen:
            continue
        seen.add(cid)
        negatives.append({
            "ground_truth": False, "protocol": e["protocol"],
            "source": e["source"], "subject": e["subject"],
            "start_ms": e["time_ms"], "end_ms": e["time_ms"],
            "correlations": [cid], "messages": 1,
        })
    return positives + negatives


def evaluate_episodes(events: list[dict], alarms: list[dict],
                      gap_ms: int = 1000) -> dict[str, Any]:
    """Alarm matches an episode iff its correlation ID belongs to that episode."""
    alerts = {a["correlation_id"] for a in alarms
              if a.get("category") not in ("cu_integrity", "cu_discrepancy")}
    data = episodes(events, gap_ms)
    labels = [{"ground_truth": e["ground_truth"],
               "detected": bool(alerts.intersection(e["correlations"]))}
              for e in data]
    scores = rates(labels)
    scores["positive_episodes"] = sum(e["ground_truth"] for e in data)
    scores["negative_correlations"] = sum(not e["ground_truth"] for e in data)
    scores["message_attack_count"] = sum(e["messages"] for e in data
                                         if e["ground_truth"])
    return scores


class OfflineDetector:
    """Separate rule/rolling-count observer calibrated on normal traffic.

    Does not read ground-truth attack labels or simulator-generated alerts.
    Role permissions are evaluated from rules/topology, not packet outcomes.
    """

    def __init__(self, min_invite_count: int = 6):
        if min_invite_count < 1:
            raise ValueError("min_invite_count must be positive")
        self.min_invite_count = min_invite_count
        self.invite_threshold = min_invite_count
        self.net = default_topology()
        self.training_seeds: list[int] = []

    def fit(self, clean_runs: list[dict], training_seeds: list[int] | None = None) -> None:
        if not clean_runs:
            raise ValueError("At least one clean run is needed")
        maxima = []
        for result in clean_runs:
            windows: dict[str, deque[int]] = defaultdict(deque)
            top = 0
            for e in sorted(result["events"], key=lambda row: row["time_ms"]):
                if e["operation"] != "SIP.INVITE":
                    continue
                q = windows[e["source"]]
                q.append(e["time_ms"])
                while q and q[0] < e["time_ms"] - 1000:
                    q.popleft()
                top = max(top, len(q))
            maxima.append(top)
        maxima.sort()
        index = max(0, (99 * len(maxima) + 99) // 100 - 1)
        self.invite_threshold = max(self.min_invite_count, maxima[index])
        self.training_seeds = list(training_seeds or [])

    def detect(self, events: list[dict]) -> list[dict]:
        """Consume only permitted observable fields (labels/alerts never read)."""
        alarms: list[dict] = []
        windows: dict[tuple[str, str], deque[int]] = defaultdict(deque)
        already_high: dict[tuple[str, str], bool] = defaultdict(bool)
        for e in sorted(events, key=lambda item: item["time_ms"]):
            operation = e["operation"]
            if operation not in RULES:
                continue
            source, target = e["source"], e["target"]
            if source not in self.net.nodes or target not in self.net.nodes:
                continue
            rule = RULES[operation]
            source_role = self.net.nodes[source].role
            target_role = self.net.nodes[target].role
            if source_role not in rule.source_roles or target_role not in rule.target_roles:
                alarms.append({
                    "correlation_id": e["correlation_id"],
                    "category": "offline_role_policy", "source": source,
                    "time_ms": e["time_ms"],
                })
            if operation == "SIP.INVITE":
                key = (source, operation)
                q = windows[key]
                q.append(e["time_ms"])
                while q and q[0] < e["time_ms"] - 1000:
                    q.popleft()
                high = len(q) > self.invite_threshold
                if high and not already_high[key]:
                    alarms.append({
                        "correlation_id": e["correlation_id"],
                        "category": "offline_invite_rate", "source": source,
                        "time_ms": e["time_ms"],
                    })
                already_high[key] = high
        return alarms


def run_validation(train_seeds: tuple[int, ...] = (21, 22, 23, 24, 25),
                   test_seeds: tuple[int, ...] = tuple(range(42, 52)),
                   duration_s: int = 18, subscribers: int = 8,
                   traffic_scale: float = 1.0,
                   traffic_rates: dict[str, float] | None = None) -> dict[str, Any]:
    if not train_seeds or not test_seeds or set(train_seeds) & set(test_seeds):
        raise ValueError("Training and testing must have disjoint nonempty seeds")
    rate_overrides = traffic_rates or {}
    training = [Simulator(Scenario(
        duration_s=duration_s, subscribers=subscribers, seed=seed,
        inject_attacks=False, traffic_scale=traffic_scale,
        traffic_rates=rate_overrides,
    )).run() for seed in train_seeds]
    detector = OfflineDetector()
    detector.fit(training, list(train_seeds))
    rows = []
    controls = []
    for seed in test_seeds:
        scenario = Scenario(
            duration_s=duration_s, subscribers=subscribers, seed=seed,
            inject_attacks=True, traffic_scale=traffic_scale,
            traffic_rates=rate_overrides,
        )
        tested = Simulator(scenario).run()
        baseline = Simulator(Scenario(
            duration_s=duration_s, subscribers=subscribers, seed=seed,
            inject_attacks=False, traffic_scale=traffic_scale,
            traffic_rates=rate_overrides,
        )).run()
        for label, alarms in (
            ("built_in", tested["alerts"]),
            ("offline", detector.detect(tested["events"])),
        ):
            rows.append({
                "seed": seed, "detector": label,
                **evaluate_episodes(tested["events"], alarms),
            })
        for label, alarms in (
            ("built_in", baseline["alerts"]),
            ("offline", detector.detect(baseline["events"])),
        ):
            controls.append({
                "seed": seed, "detector": label,
                **evaluate_episodes(baseline["events"], alarms),
            })
    summary = {}
    for name in ("built_in", "offline"):
        subset = [row for row in rows if row["detector"] == name]
        clean = [row for row in controls if row["detector"] == name]
        summary[name] = {
            metric: {
                "mean": mean(float(row[metric]) for row in subset),
                "sample_std": stdev([float(row[metric]) for row in subset])
                if len(subset) > 1 else 0.0,
            } for metric in ("precision", "recall", "f1", "fpr")
        }
        summary[name]["clean_controls"] = {
            "false_alarms": sum(row["fp"] for row in clean),
            "negative_samples": sum(row["negative_correlations"] for row in clean),
        }
    return {
        "method": "episode-level positive vs per-correlation benign negatives",
        "train_seeds": list(train_seeds), "test_seeds": list(test_seeds),
        "offline_invite_threshold": detector.invite_threshold,
        "rows": rows, "clean_control_rows": controls, "summary": summary,
        "limitations": [
            "Synthetic attack schedules and benchmark-specific episodes",
            "Offline detector is a rule/quantile baseline, not ML or a certified security function",
            "One alert matches all messages in an episode; this differs from packet-level recall",
            "CU and NFProfile compromises need separate node-level evaluation",
            "No independent operator traffic, temporal domain shift or external reference traces",
        ],
    }
