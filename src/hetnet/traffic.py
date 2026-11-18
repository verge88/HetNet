"""Seeded statistical load with 24-hour seasonality and AR(1) perturbations.

The load model follows the *form* of thesis §3.2: a daily cycle, normal
innovation and a first-order autoregression. Rates are demonstration
calibration values, not measurements from an operator's network.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Iterator


@dataclass(frozen=True)
class TrafficProfile:
    domain: str
    generation: str
    operation: str
    source: str
    target: str
    baseline_per_second: float


PROFILES: tuple[TrafficProfile, ...] = (
    TrafficProfile("map_2g", "2G", "MAP.SendAuthenticationInfo", "msc2", "hlr", 0.18),
    TrafficProfile("map_3g", "3G", "MAP.SendAuthenticationInfo", "sgsn3", "hlr", 0.16),
    TrafficProfile("diameter_4g", "4G", "Diameter.AIR", "mme4", "hss4", 0.21),
    TrafficProfile("sip_ims", "4G", "SIP.REGISTER", "pcscf", "scscf", 0.14),
    TrafficProfile("sbi_5g", "5G", "Nnrf_NFDiscovery.Search", "amf5", "nrf5", 0.18),
)


def daily_factor(second: float, peak_hour: float = 18.0,
                 amplitude: float = 0.35) -> float:
    """Exactly 1+amplitude at peak_hour and 1-amplitude 12h apart."""
    return 1.0 + amplitude * math.cos(
        2.0 * math.pi * (second / 3600.0 - peak_hour) / 24.0
    )


def poisson(rng: random.Random, expectation: float) -> int:
    """Small-rate exact Poisson sampler with no numpy dependency."""
    if expectation < 0.0 or not math.isfinite(expectation):
        raise ValueError("Poisson expectation must be finite and nonnegative")
    if expectation == 0.0:
        return 0
    # Decomposition keeps Knuth's algorithm stable for larger expectations.
    draws = 0
    while expectation > 0.0:
        lam = min(expectation, 12.0)
        expectation -= lam
        threshold = math.exp(-lam)
        value = 1.0
        n = 0
        while value > threshold:
            n += 1
            value *= rng.random()
        draws += n - 1
    return draws


class TrafficGenerator:
    def __init__(self, seed: int, scale: float = 1.0,
                 amplitude: float = 0.35, phi: float = 0.7,
                 innovation_sigma: float = 0.12, peak_hour: float = 18.0) -> None:
        if not (0 <= scale <= 50 and 0 <= amplitude < 1 and
                0 <= phi < 1 and innovation_sigma >= 0 and
                0 <= peak_hour < 24):
            raise ValueError("Invalid traffic parameters")
        self.rng = random.Random(seed ^ 0x71AAB57)
        self.scale = scale
        self.amplitude = amplitude
        self.phi = phi
        self.innovation_sigma = innovation_sigma
        self.peak_hour = peak_hour
        self._ar = {p.domain: 0.0 for p in PROFILES}
        self.generated: dict[str, int] = {p.domain: 0 for p in PROFILES}

    def stream(self, duration_s: int, subscribers: int) -> Iterator[
        tuple[int, TrafficProfile, str, str]
    ]:
        """Yield (time_ms, profile, pseudo-subscriber, correlation_id)."""
        if subscribers <= 0 or duration_s < 0:
            raise ValueError("invalid simulation length or subscriber count")
        for second in range(duration_s):
            for profile in PROFILES:
                ar = self.phi * self._ar[profile.domain] + (
                    self.innovation_sigma * self.rng.gauss(0, 1))
                self._ar[profile.domain] = ar
                factor = daily_factor(second, self.peak_hour, self.amplitude)
                expected = (profile.baseline_per_second * self.scale
                            * max(0.05, factor + ar))
                for i in range(poisson(self.rng, expected)):
                    self.generated[profile.domain] += 1
                    subject = "ue-" + str(self.rng.randrange(1, subscribers + 1)).zfill(4)
                    when_ms = second * 1000 + self.rng.randint(0, 999)
                    correlation = "background-{}-{}-{}".format(
                        profile.domain, second, i
                    )
                    yield when_ms, profile, subject, correlation
