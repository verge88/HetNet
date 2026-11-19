"""Safe, fixed-fixture, aggregate-only research studies for the local GUI.

No arbitrary file paths, private trust material, operator records, signed
envelopes or durable replay DBs can be selected through the browser.
All studies here consume ONLY the explicitly committed synthetic fixtures.
"""
from __future__ import annotations

from pathlib import Path

from .zonal_detection import heldout_comparison


STUDIES = {
    "zonal": {
        "title": "Зональные детекторы",
        "description": "Три правила на раздельных синтетических источниках и seed.",
        "primary": "recall_with_abstentions_as_misses",
        "primary_label": "Полнота с учётом отказов",
    },
    "labeled": {
        "title": "Размеченные агрегаты",
        "description": "Чистое обучение и проверка узловых меток без утечки.",
        "primary": "recall_with_abstentions_as_misses",
        "primary_label": "Полнота с учётом отказов",
    },
    "episodes": {
        "title": "Временные эпизоды",
        "description": "Неизвестное начало атаки, задержка и неподтверждённые тревоги.",
        "primary": "episode_recall",
        "primary_label": "Полнота обнаружения эпизодов",
    },
    "clock": {
        "title": "Чувствительность к сдвигу часов",
        "description": "Фиксированные относительные сдвиги на 0, ±1 и ±2 интервала.",
        "primary": "episode_recall",
        "primary_label": "Полнота обнаружения эпизодов",
    },
}


def _fixtures() -> tuple[list[Path], list[Path], list[Path]]:
    examples = Path(__file__).resolve().parents[2] / "examples"
    train = [examples / "labeled" / ("lab_clean_" + name + ".json")
             for name in ("alpha", "beta")]
    labeled = [examples / "labeled" / ("lab_holdout_" + name + ".json")
               for name in ("gamma", "delta")]
    episodic = [examples / "episodic" /
                ("episodic_holdout_" + name + ".json")
                for name in ("alpha", "beta", "gamma")]
    return train, labeled, episodic


def list_studies() -> dict:
    return {
        "studies": [{"id": name, **details}
                    for name, details in STUDIES.items()],
        "security": (
            "Только встроенные синтетические файлы. Веб-интерфейс не принимает "
            "операторские выгрузки, ключи HMAC или путь к приватной SQLite."
        ),
    }


def _row(label: str, data: dict, *, primary: str) -> dict:
    def field(key: str):
        value = data.get(key)
        return value if type(value) in (int, float) else None

    return {
        "label": label,
        "primary": field(primary),
        "detected": field("tp") if "tp" in data else field("detected_episodes"),
        "false": field("fp") if "fp" in data else field("unmatched_alerts"),
        "coverage": field("coverage") if "coverage" in data else field("pair_coverage"),
        "delay_intervals": field("mean_delay_intervals"),
    }


def run_study(name: str) -> dict:
    """Return just aggregate comparison scores, never original/raw data."""
    if name not in STUDIES:
        raise ValueError("Unknown synthetic research study")
    train, labeled, episodic = _fixtures()
    details = STUDIES[name]
    if name == "zonal":
        # GUI intentionally uses a bounded preview, not a heavy 48-run benchmark.
        report = heldout_comparison(
            train_seeds=(21,), test_seeds=(42,),
            cohort_names=("none", "legacy_5g"),
        )
        rows = [_row(x["detector"], x, primary=details["primary"])
                for x in report["overall"]]
        scope = "8 синтетических симуляций, 1 train seed, 1 test seed, 2 когорты"
    elif name == "labeled":
        from .labeled_aggregates import run_labeled_eval
        report = run_labeled_eval(train, labeled)
        rows = [_row(x["detector"], x, primary=details["primary"])
                for x in report["overall"]]
        scope = "2 чистых train и 2 синтетических holdout-источника"
    elif name == "episodes":
        from .temporal_episodes import run_temporal_eval
        report = run_temporal_eval(train, episodic)
        rows = [_row(x["detector"], x, primary=details["primary"])
                for x in report["overall"]]
        scope = "3 синтетических источника, 6 размеченных эпизодов"
    else:
        from .clock_sensitivity import run_clock_study
        report = run_clock_study(train, episodic)
        rows = []
        for case in report["cases"]:
            peer = next(item for item in case["overall"]
                        if item["detector"] == "zone_peer")
            rows.append(_row(case["case"], peer, primary=details["primary"]))
        scope = "4 парных синтетических сдвига по 3 источникам"
    return {
        "id": name, "title": details["title"],
        "description": details["description"], "primary_label": details["primary_label"],
        "scope": scope, "rows": rows,
        "limitations": [
            "Все входы — только открытые синтетические фикстуры HetNet.",
            "Ни один веб-результат не удостоверяет независимые операторские данные.",
            "Заявленные флаги CU и quorum не являются проверенными HMAC в этих исследованиях.",
            "Числа демонстрируют методику, а не 3GPP conformance или эксплуатационную точность.",
        ],
    }
