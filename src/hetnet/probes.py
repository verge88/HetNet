"""Optional independent *sampling errors* on each virtual monitoring probe.

All probes still observe the SAME underlying synthetic event counter: their
errors are independent, not their physical ground truth. This must never be
presented as independence of real sensing infrastructure.
"""
from __future__ import annotations

import hashlib
import math
import random

from .consensus import OBSERVER_DOMAINS


class ProbeSampler:
    """Bernoulli missed events per operation, deterministically per probe+epoch."""

    def __init__(self, seed: int, miss_probability: float = 0.0) -> None:
        if (type(miss_probability) not in (int, float)
                or not math.isfinite(miss_probability)
                or not 0 <= miss_probability <= 0.5):
            raise ValueError("miss_probability must be a finite number in [0,0.5]")
        self.seed = seed
        self.miss_probability = float(miss_probability)

    def observe(self, node: str, observer: str, time_ms: int,
                ground_truth: dict[str, int]) -> dict[str, int]:
        if observer not in OBSERVER_DOMAINS:
            raise ValueError("Unsupported observer identity")
        if type(time_ms) is not int or time_ms < 0:
            raise ValueError("Invalid sampling timestamp")
        p = self.miss_probability
        if p == 0:
            return dict(ground_truth)
        out = {}
        for operation, count in sorted(ground_truth.items()):
            if type(count) is not int or not 0 <= count <= 1_000_000:
                raise ValueError("Synthetic counter must be nonnegative and bounded")
            material = "{}|{}|{}|{}|{}".format(
                self.seed, node, observer, time_ms, operation)
            digest = hashlib.sha256(material.encode()).digest()
            rng = random.Random(int.from_bytes(digest[:8], "big"))
            if count <= 400:
                missed = sum(rng.random() < p for _ in range(count))
            else:
                # Normal approximation only in large-count regime.
                mu = count * p
                sigma = math.sqrt(count * p * (1 - p))
                missed = max(0, min(count, int(round(rng.gauss(mu, sigma)))))
            out[operation] = count - missed
        return out
