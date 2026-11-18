"""Explicit load calibration from aggregate, non-PII request counts."""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import math

from .traffic import PROFILES

DOMAINS = {profile.domain for profile in PROFILES}
LIMIT = 1_048_576


def _read_json(path: Path) -> dict:
    if path.stat().st_size > LIMIT:
        raise ValueError("Calibration file exceeds 1 MiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data


def calibrate(data: dict) -> dict:
    """Compute request rates from independent source counts per domain.

    Schema: {"measurements":[{"domain":str, "duration_seconds":number,
             "request_count":int},...],"source":str}.
    The aggregate file must not contain subscriber IDs or raw signaling.
    """
    if not isinstance(data, dict):
        raise ValueError("Calibration input must be an object")
    rows = data.get("measurements")
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError("measurements must be a nonempty list (max 10000)")
    if not isinstance(data.get("source", "unspecified"), str):
        raise ValueError("source must be a string")
    counts: dict[str, int] = defaultdict(int)
    seconds: dict[str, float] = defaultdict(float)
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "domain", "duration_seconds", "request_count"
        }:
            raise ValueError("Each row requires exactly domain, duration_seconds, request_count")
        domain = row["domain"]
        duration = row["duration_seconds"]
        count = row["request_count"]
        if domain not in DOMAINS:
            raise ValueError("Unknown domain: " + str(domain))
        if (type(duration) not in (int, float) or not math.isfinite(duration)
                or duration <= 0 or duration > 86_400 * 365):
            raise ValueError("Invalid measurement duration")
        if type(count) is not int or count < 0 or count > 10**9:
            raise ValueError("request_count must be a nonnegative integer")
        counts[domain] += count
        seconds[domain] += duration
    rates = {domain: counts[domain] / seconds[domain] for domain in sorted(counts)}
    return {
        "schema_version": 1, "source": data.get("source", "unspecified"),
        "rates": rates, "counts": dict(sorted(counts.items())),
        "seconds": dict(sorted(seconds.items())),
        "method": "request_count / aggregate observation seconds",
        "provenance": "user-supplied aggregates; missing domains use simulator defaults",
    }


def load_rates(path: Path) -> dict[str, float]:
    data = _read_json(path)
    if data.get("schema_version") != 1 or not isinstance(data.get("rates"), dict):
        raise ValueError("Expected calibration schema_version=1 and rates object")
    rates = data["rates"]
    if not rates:
        raise ValueError("Empty calibration rates")
    result = {}
    for domain, rate in rates.items():
        if (domain not in DOMAINS or type(rate) not in (int, float)
                or not math.isfinite(rate) or not 0 <= rate <= 1000):
            raise ValueError("Invalid calibrated rate for " + str(domain))
        result[domain] = float(rate)
    return result


def calibrate_file(source: Path, destination: Path) -> dict:
    result = calibrate(_read_json(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    return result
