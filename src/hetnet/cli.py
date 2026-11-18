"""Command-line interface and deterministic experiment exports."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .simulator import RULES, Scenario, Simulator
from .experiment import export_experiment, run_multiseed
from .calibration import calibrate_file, load_rates
from .episode import run_validation
from .stress import benign_stress
from .wire import DecodeError, MAX_INPUT, PARSERS, inspect_wire


def export_run(result: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("result.json", result),
        ("summary.json", result["summary"]),
        ("alerts.json", result["alerts"]),
        ("topology.json", {"nodes": result["nodes"], "links": result["links"]}),
    ):
        (output / name).write_text(
            json.dumps(content, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if result["observations"]:
        with (output / "observations.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=result["observations"][0].keys())
            writer.writeheader()
            for window in result["observations"]:
                writer.writerow({
                    key: json.dumps(value, ensure_ascii=False)
                    if isinstance(value, (dict, list)) else value
                    for key, value in window.items()
                })
    if result["events"]:
        with (output / "events.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=result["events"][0].keys())
            writer.writeheader()
            for event in result["events"]:
                writer.writerow({
                    key: json.dumps(value, ensure_ascii=False)
                    if isinstance(value, (dict, list)) else value
                    for key, value in event.items()
                })


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="hetnet", description="Unified synthetic 2G–5G control-plane simulator"
    )
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("run", help="Generate a synthetic signaling experiment")
    run.add_argument("--duration", type=int, default=18, help="seconds (5..86400)")
    run.add_argument("--subscribers", type=int, default=8, help="4..10000")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--loss-rate", type=float, default=0.0)
    run.add_argument("--cu-interval", type=int, default=1500, help="milliseconds")
    run.add_argument("--no-attacks", action="store_true")
    run.add_argument("--output", type=Path, default=Path("results"))
    run.add_argument("--traffic-scale", type=float, default=1.0)
    run.add_argument("--traffic-amplitude", type=float, default=0.35)
    run.add_argument("--peak-hour", type=float, default=18.0)
    run.add_argument("--traffic-profile", type=Path, help="Calibrated aggregate JSON")
    exp = commands.add_parser("experiment", help="Repeatable multi-seed evaluation")
    exp.add_argument("--duration", type=int, default=18)
    exp.add_argument("--subscribers", type=int, default=8)
    exp.add_argument("--start-seed", type=int, default=42)
    exp.add_argument("--runs", type=int, default=10)
    exp.add_argument("--traffic-scale", type=float, default=1.0)
    exp.add_argument("--traffic-profile", type=Path, help="Calibrated aggregate JSON")
    exp.add_argument("--output", type=Path, default=Path("results/experiment"))
    validation = commands.add_parser(
        "validate", help="Train on clean seeds and evaluate attack episodes")
    validation.add_argument("--duration", type=int, default=18)
    validation.add_argument("--subscribers", type=int, default=8)
    validation.add_argument("--traffic-scale", type=float, default=1.0)
    validation.add_argument("--traffic-profile", type=Path)
    validation.add_argument("--train-start-seed", type=int, default=21)
    validation.add_argument("--train-runs", type=int, default=5)
    validation.add_argument("--test-start-seed", type=int, default=42)
    validation.add_argument("--test-runs", type=int, default=10)
    validation.add_argument("--output", type=Path, default=Path("results/validation"))
    stress = commands.add_parser(
        "stress", help="Benign load/loss domain-shift false-positive experiment")
    stress.add_argument("--duration", type=int, default=18)
    stress.add_argument("--subscribers", type=int, default=8)
    stress.add_argument("--traffic-profile", type=Path)
    stress.add_argument("--scales", default="1,8,20")
    stress.add_argument("--loss-rates", default="0,0.03,0.1")
    stress.add_argument("--test-runs", type=int, default=3)
    stress.add_argument("--output", type=Path, default=Path("results/stress"))
    calibration = commands.add_parser(
        "calibrate", help="Calculate rates from aggregate non-PII counts")
    calibration.add_argument("--input", type=Path, required=True)
    calibration.add_argument("--output", type=Path, required=True)
    wire = commands.add_parser("wirecheck", help="Read-only offline wire envelope validator")
    wire.add_argument("--protocol", choices=sorted(PARSERS), required=True)
    source = wire.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", help="Packet bytes as hex string")
    source.add_argument("--input", type=Path, help="Local binary file")
    serve = commands.add_parser("serve", help="Open local simulation dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    commands.add_parser("standards", help="List modeled operations and specifications")
    args = parser.parse_args(argv)

    if args.command == "serve":
        from .web import serve_dashboard
        serve_dashboard(args.host, args.port)
    elif args.command == "wirecheck":
        try:
            if args.input is not None:
                if args.input.stat().st_size > MAX_INPUT:
                    raise ValueError("Input file too large")
                data = args.input.read_bytes()
            else:
                data = bytes.fromhex(args.hex)
            result = inspect_wire(args.protocol, data)
        except (OSError, ValueError, DecodeError) as error:
            parser.error(str(error))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "stress":
        if not 1 <= args.test_runs <= 20:
            parser.error("--test-runs must be 1..20")
        try:
            scales = tuple(float(v) for v in args.scales.split(","))
            losses = tuple(float(v) for v in args.loss_rates.split(","))
            rates = load_rates(args.traffic_profile) if args.traffic_profile else {}
            result = benign_stress(
                duration_s=args.duration, subscribers=args.subscribers,
                traffic_scales=scales, loss_rates=losses,
                test_seeds=tuple(range(42, 42 + args.test_runs)),
                traffic_rates=rates,
            )
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "stress.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(result["conditions"], ensure_ascii=False, indent=2))
        print("Exported benign stress to", args.output.resolve())
    elif args.command == "calibrate":
        try:
            result = calibrate_file(args.input, args.output)
        except (OSError, ValueError, KeyError) as error:
            parser.error(str(error))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "validate":
        if not 1 <= args.train_runs <= 50 or not 1 <= args.test_runs <= 100:
            parser.error("train-runs must be 1..50 and test-runs 1..100")
        rates = load_rates(args.traffic_profile) if args.traffic_profile else {}
        result = run_validation(
            train_seeds=tuple(range(args.train_start_seed,
                                   args.train_start_seed + args.train_runs)),
            test_seeds=tuple(range(args.test_start_seed,
                                  args.test_start_seed + args.test_runs)),
            duration_s=args.duration, subscribers=args.subscribers,
            traffic_scale=args.traffic_scale, traffic_rates=rates,
        )
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "validation.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
        print("Exported validation to", args.output.resolve())
    elif args.command == "experiment":
        if not 1 <= args.runs <= 100:
            parser.error("--runs must be between 1 and 100")
        result = run_multiseed(
            duration_s=args.duration, subscribers=args.subscribers,
            seeds=tuple(range(args.start_seed, args.start_seed + args.runs)),
            traffic_scale=args.traffic_scale,
            traffic_rates=load_rates(args.traffic_profile)
            if args.traffic_profile else {},
        )
        export_experiment(result, args.output)
        print(json.dumps(result["summary"], indent=2, ensure_ascii=False))
        print("Exported reproducible evaluation to", args.output.resolve())
    elif args.command == "standards":
        print(json.dumps({
            key: {"protocol": rule.protocol, "reference": rule.reference}
            for key, rule in RULES.items()
        }, indent=2, ensure_ascii=False))
    elif args.command in ("run", None):
        if args.command is None:
            parser.print_help()
            return
        scenario = Scenario(
            duration_s=args.duration, subscribers=args.subscribers,
            seed=args.seed, loss_rate=args.loss_rate,
            cu_interval_ms=args.cu_interval,
            inject_attacks=not args.no_attacks,
            traffic_scale=args.traffic_scale,
            traffic_amplitude=args.traffic_amplitude,
            traffic_peak_hour=args.peak_hour,
            traffic_rates=load_rates(args.traffic_profile)
            if args.traffic_profile else {},
        )
        result = Simulator(scenario).run()
        export_run(result, args.output)
        print(json.dumps(result["summary"], indent=2, ensure_ascii=False))
        print("Exported experiment to", args.output.resolve())


if __name__ == "__main__":
    main()
