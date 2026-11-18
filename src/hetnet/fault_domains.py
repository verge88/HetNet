"""Common-cause monitoring domain faults shared across *all* CU targets.

The fault schedule is sampled once per CU epoch. Every monitored node sees
the same domain outage/forgery at that time, unlike independent packet loss.
This models correlated administrative failures, not physical transport.
"""
from __future__ import annotations

from dataclasses import dataclass
import random

MONITORED_NODES = ("msc2", "sgsn3", "mme4", "dra", "pcscf", "amf5")

FAULT_CASES = (
    "none", "epc_outage", "epc_5gc_outage", "epc_corrupt",
    "epc_5gc_collude", "all_outage",
)

_OUTAGE = {
    "none": frozenset(),
    "epc_outage": frozenset(("tap-epc",)),
    "epc_5gc_outage": frozenset(("tap-epc", "tap-5gc")),
    "epc_corrupt": frozenset(),
    "epc_5gc_collude": frozenset(),
    "all_outage": frozenset(("tap-legacy", "tap-epc", "tap-5gc")),
}
_FORGERY = {
    "none": frozenset(),
    "epc_outage": frozenset(),
    "epc_5gc_outage": frozenset(),
    "epc_corrupt": frozenset(("tap-epc",)),
    "epc_5gc_collude": frozenset(("tap-epc", "tap-5gc")),
    "all_outage": frozenset(),
}


@dataclass(frozen=True)
class CommonFault:
    offline: frozenset[str] = frozenset()
    fabricated: frozenset[str] = frozenset()
    active: bool = False


class CommonFaultSchedule:
    """Cache one shared fault draw per timestamp, independent of node order."""

    def __init__(self, *, seed: int, kind: str = "none",
                 probability: float = 1.0, onset_ms: int = 0) -> None:
        if kind not in FAULT_CASES:
            raise ValueError("Unknown common monitoring fault case")
        if not 0 <= probability <= 1:
            raise ValueError("Fault probability must be in [0,1]")
        if onset_ms < 0:
            raise ValueError("onset_ms must not be negative")
        self.kind = kind
        self.probability = probability
        self.onset_ms = onset_ms
        self.rng = random.Random(seed ^ 0x39A63E)
        self._cache: dict[int, CommonFault] = {}

    def at(self, epoch_ms: int) -> CommonFault:
        if epoch_ms < 0:
            raise ValueError("Epoch must be nonnegative")
        if epoch_ms not in self._cache:
            active = (
                self.kind != "none" and epoch_ms >= self.onset_ms
                and self.rng.random() < self.probability
            )
            self._cache[epoch_ms] = CommonFault(
                _OUTAGE[self.kind] if active else frozenset(),
                _FORGERY[self.kind] if active else frozenset(),
                active,
            )
        return self._cache[epoch_ms]
