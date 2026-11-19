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
from .node_validation import node_study
from .zone_validation import zone_study, OBSERVER_CASES
from .cohort_validation import multi_node_study, COHORTS
from .probe_validation import probe_study
from .external_aggregates import (run_external_eval, load_dataset,
                                  source_summary)
from .zonal_detection import heldout_comparison
from .labeled_aggregates import run_labeled_eval, load_labeled, audit_labeled
from .temporal_episodes import run_temporal_eval, load_episodic, audit_episodic
from .aggregate_attestation import run_attested_eval, create_envelope, TrustedIdentity, evaluate_attested_episodes
from .clock_sensitivity import run_clock_study
from .durable_attestation import DurableReplayStore, run_durable_eval, synthetic_durable_demo
from .fault_domains import FAULT_CASES, MONITORED_NODES
from .wire import DecodeError, MAX_INPUT, PARSERS, inspect_wire


def export_run(result: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("result.json", result),
        ("summary.json", result["summary"]),
        ("alerts.json", result["alerts"]),
        ("node_evidence.json", result["node_evidence"]),
        ("domain_evidence.json", result["domain_evidence"]),
        ("zonal_evidence.json", result["zonal_evidence"]),
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
    run.add_argument("--node-case", choices=["auto", "none", "report", "tamper", "both"],
                     default="auto", help="Isolated node compromise/tamper scenario")
    run.add_argument("--observer-case", choices=OBSERVER_CASES, default="none",
                     help="Independent monitoring domain fault scenario")
    run.add_argument("--observer-loss-rate", type=float, default=0.0,
                     help="Independent observer vote loss probability")
    run.add_argument("--report-fault-nodes", default="",
                     help="Comma-separated monitored nodes compromised after 72%%")
    run.add_argument("--shared-zone-case", choices=FAULT_CASES, default="none")
    run.add_argument("--shared-zone-probability", type=float, default=1.0)
    run.add_argument("--observer-capture-miss", type=float, default=0.0,
                     help="Independent virtual probe miss probability, 0..0.5")
    run.add_argument("--quorum-max-count-delta", type=int, default=0,
                     help="Absolute tolerated per-operation count difference")
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
    probe = commands.add_parser(
        "probe-study", help="Synthetic sensor sampling vs tolerant-quorum sensitivity")
    probe.add_argument("--duration", type=int, default=18)
    probe.add_argument("--subscribers", type=int, default=8)
    probe.add_argument("--start-seed", type=int, default=42)
    probe.add_argument("--runs", type=int, default=6)
    probe.add_argument("--capture-miss-rates", default="0,0.05,0.15")
    probe.add_argument("--tolerances", default="0,1,2")
    probe.add_argument("--cohorts", default="none,legacy_5g")
    probe.add_argument("--output", type=Path, default=Path("results/probe-study"))
    cohort = commands.add_parser(
        "cohort-study", help="Multi-generation CU nodes vs common observer-domain faults")
    cohort.add_argument("--duration", type=int, default=18)
    cohort.add_argument("--subscribers", type=int, default=8)
    cohort.add_argument("--start-seed", type=int, default=42)
    cohort.add_argument("--runs", type=int, default=6)
    cohort.add_argument("--fault-cases", default=",".join(
        ("none", "epc_outage", "epc_5gc_outage",
         "epc_corrupt", "epc_5gc_collude")))
    cohort.add_argument("--cohorts", default="none,legacy_5g,epc_ims")
    cohort.add_argument("--shared-zone-probability", type=float, default=1.0)
    cohort.add_argument("--output", type=Path, default=Path("results/cohort-study"))
    zones = commands.add_parser(
        "zone-study", help="2-of-3 monitoring quorum vs observer failures/collusion")
    zones.add_argument("--duration", type=int, default=18)
    zones.add_argument("--subscribers", type=int, default=8)
    zones.add_argument("--start-seed", type=int, default=42)
    zones.add_argument("--runs", type=int, default=6)
    zones.add_argument("--observer-loss-rates", default="0,0.2,0.45")
    zones.add_argument("--observer-cases", default=",".join(OBSERVER_CASES))
    zones.add_argument("--output", type=Path, default=Path("results/zone-study"))
    node = commands.add_parser(
        "node-study", help="CU report compromise vs benign packet-loss matrix")
    node.add_argument("--duration", type=int, default=18)
    node.add_argument("--subscribers", type=int, default=8)
    node.add_argument("--start-seed", type=int, default=42)
    node.add_argument("--runs", type=int, default=4)
    node.add_argument("--loss-rates", default="0,0.1,0.35")
    node.add_argument("--traffic-scale", type=float, default=1.0)
    node.add_argument("--output", type=Path, default=Path("results/node-study"))
    stress = commands.add_parser(
        "stress", help="Benign load/loss domain-shift false-positive experiment")
    stress.add_argument("--duration", type=int, default=18)
    stress.add_argument("--subscribers", type=int, default=8)
    stress.add_argument("--traffic-profile", type=Path)
    stress.add_argument("--scales", default="1,8,20")
    stress.add_argument("--loss-rates", default="0,0.03,0.1")
    stress.add_argument("--test-runs", type=int, default=3)
    stress.add_argument("--output", type=Path, default=Path("results/stress"))
    durable_demo = commands.add_parser(
        "durable-replay-demo",
        help="Ephemeral synthetic signer + private temporary SQLite; no secrets exported")
    durable_demo.add_argument("--output", type=Path,
                              default=Path("results/durable-replay-demo"))
    durable = commands.add_parser(
        "durable-attested-eval",
        help="Verify signed aggregates with durable SQLite replay protection")
    durable.add_argument("--train", type=Path, nargs="+", required=True)
    durable.add_argument("--holdout", type=Path, nargs="+", required=True)
    durable.add_argument("--trust-config", type=Path, required=True)
    durable.add_argument("--state-db", type=Path, required=True,
                         help="Persistent private SQLite database in a 0700 directory")
    durable.add_argument("--output", type=Path,
                         default=Path("results/durable-attested-episodes"))
    revoke = commands.add_parser(
        "attestation-revoke", help="Permanently revoke an admitted key ID in a local state DB")
    revoke.add_argument("--state-db", type=Path, required=True)
    revoke.add_argument("--key-id", required=True)
    status = commands.add_parser(
        "attestation-state", help="Display nonsecret accepted-key and revocation state")
    status.add_argument("--state-db", type=Path, required=True)
    attested = commands.add_parser(
        "attested-episode-eval",
        help="Verify source-bound HMAC aggregate envelopes before episode evaluation")
    attested.add_argument("--train", type=Path, nargs="+", required=True,
                          help="Signed version-1 clean-source envelope files")
    attested.add_argument("--holdout", type=Path, nargs="+", required=True,
                          help="Signed version-2 episodic-source envelope files")
    attested.add_argument("--trust-config", type=Path, required=True,
                          help="Private 0600 local HMAC trust-policy file; never commit")
    attested.add_argument("--output", type=Path,
                          default=Path("results/attested-episodes"))
    demo_attest = commands.add_parser(
        "attestation-demo",
        help="Self-sign synthetic fixtures IN MEMORY using ephemeral keys; not provenance proof")
    demo_attest.add_argument("--output", type=Path,
                             default=Path("results/attestation-demo"))
    clock = commands.add_parser(
        "clock-study",
        help="Synthetic relative-clock-bin offset study on onset-blind episode rules")
    clock.add_argument("--train", type=Path, nargs="+", required=True)
    clock.add_argument("--holdout", type=Path, nargs="+", required=True)
    clock.add_argument("--output", type=Path,
                       default=Path("results/clock-study"))
    episode_audit = commands.add_parser(
        "episode-audit", help="Validate a privacy-restricted temporal annotated source")
    episode_audit.add_argument("--input", type=Path, required=True)
    episode_eval = commands.add_parser(
        "episode-eval", help="Causal unknown-onset CU episode evaluation on heldout lineages")
    episode_eval.add_argument("--train", type=Path, nargs="+", required=True)
    episode_eval.add_argument("--holdout", type=Path, nargs="+", required=True)
    episode_eval.add_argument("--output", type=Path,
                              default=Path("results/episode-eval"))
    labeled_audit = commands.add_parser(
        "labeled-audit", help="Check privacy-minimized labeled CU aggregate schema")
    labeled_audit.add_argument("--input", type=Path, required=True)
    labeled_eval = commands.add_parser(
        "labeled-eval",
        help="Train clean-only and compare CU/zonal rules on separate annotated sources")
    labeled_eval.add_argument("--train", type=Path, nargs="+", required=True)
    labeled_eval.add_argument("--holdout", type=Path, nargs="+", required=True)
    labeled_eval.add_argument("--output", type=Path,
                              default=Path("results/labeled-eval"))
    zonal = commands.add_parser(
        "zonal-compare",
        help="Compare signed CU and zonal detectors with disjoint synthetic sources")
    zonal.add_argument("--duration", type=int, default=18)
    zonal.add_argument("--subscribers", type=int, default=8)
    zonal.add_argument("--train-start-seed", type=int, default=21)
    zonal.add_argument("--train-runs", type=int, default=4)
    zonal.add_argument("--test-start-seed", type=int, default=42)
    zonal.add_argument("--test-runs", type=int, default=4)
    zonal.add_argument("--output", type=Path, default=Path("results/zonal-compare"))
    audit = commands.add_parser(
        "aggregate-audit", help="Validate aggregate-only JSON and print privacy-safe summary")
    audit.add_argument("--input", type=Path, required=True)
    ext = commands.add_parser(
        "external-eval", help="Source-disjoint aggregate observer calibration (no attack labels)")
    ext.add_argument("--train", type=Path, nargs="+", required=True,
                     help="One or more independent SOURCE IDs for training; not proof of independence")
    ext.add_argument("--holdout", type=Path, required=True,
                     help="Source ID different from every training dataset")
    ext.add_argument("--output", type=Path, default=Path("results/external-eval"))
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
    elif args.command == "probe-study":
        if not 1 <= args.runs <= 100:
            parser.error("--runs must be between 1 and 100")
        try:
            report = probe_study(
                seeds=tuple(range(args.start_seed, args.start_seed + args.runs)),
                capture_miss_rates=tuple(float(x) for x in args.capture_miss_rates.split(",")),
                tolerances=tuple(int(x) for x in args.tolerances.split(",")),
                cohorts=tuple(x.strip() for x in args.cohorts.split(",")),
                duration_s=args.duration, subscribers=args.subscribers,
            )
        except ValueError as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "probe_study.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["groups"], ensure_ascii=False, indent=2))
        print("Exported probe study to", args.output.resolve())
    elif args.command == "cohort-study":
        if not 1 <= args.runs <= 100:
            parser.error("--runs must be between 1 and 100")
        try:
            result = multi_node_study(
                seeds=tuple(range(args.start_seed, args.start_seed + args.runs)),
                fault_cases=tuple(c.strip() for c in args.fault_cases.split(",")),
                cohort_names=tuple(c.strip() for c in args.cohorts.split(",")),
                fault_probability=args.shared_zone_probability,
                duration_s=args.duration, subscribers=args.subscribers,
            )
        except ValueError as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "cohort_study.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(result["groups"], ensure_ascii=False, indent=2))
        print("Exported cohort study to", args.output.resolve())
    elif args.command == "zone-study":
        if not 1 <= args.runs <= 100:
            parser.error("--runs must be between 1 and 100")
        try:
            losses = tuple(float(v) for v in args.observer_loss_rates.split(","))
            cases = tuple(v.strip() for v in args.observer_cases.split(","))
            result = zone_study(
                seeds=tuple(range(args.start_seed, args.start_seed + args.runs)),
                observer_loss_rates=losses, observer_cases=cases,
                duration_s=args.duration, subscribers=args.subscribers,
            )
        except ValueError as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "zone_study.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(result["groups"], ensure_ascii=False, indent=2))
        print("Exported zone study to", args.output.resolve())
    elif args.command == "node-study":
        if not 1 <= args.runs <= 100:
            parser.error("--runs must be between 1 and 100")
        try:
            losses = tuple(float(x) for x in args.loss_rates.split(","))
            study = node_study(
                seeds=tuple(range(args.start_seed, args.start_seed + args.runs)),
                loss_rates=losses,
                duration_s=args.duration, subscribers=args.subscribers,
                traffic_scale=args.traffic_scale,
            )
        except ValueError as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "node_study.json").write_text(
            json.dumps(study, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(study["conditions"], ensure_ascii=False, indent=2))
        print("Exported node study to", args.output.resolve())
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
    elif args.command == "durable-replay-demo":
        report = synthetic_durable_demo()
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "durable_replay_demo.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps({
            key: report[key] for key in
            ("self_signed_synthetic_demo", "durable_reopen_replay_rejected",
             "revoked_key_rejected", "new_key_id_rotation_succeeded")
        }, ensure_ascii=False, indent=2))
        print("Exported synthetic durable demonstration to",
              args.output.resolve())
    elif args.command == "durable-attested-eval":
        try:
            report = run_durable_eval(args.train, args.holdout,
                                      args.trust_config, args.state_db)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "durable_attested_comparison.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["overall"], ensure_ascii=False, indent=2))
        print("Committed durable replay state; export to", args.output.resolve())
    elif args.command == "attestation-revoke":
        try:
            report = DurableReplayStore(args.state_db).revoke(args.key_id)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.command == "attestation-state":
        try:
            report = DurableReplayStore(args.state_db).summary()
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.command == "attested-episode-eval":
        try:
            report = run_attested_eval(args.train, args.holdout,
                                       args.trust_config)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "attested_episode_comparison.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["overall"], ensure_ascii=False, indent=2))
        print("Exported verified-envelope comparison to", args.output.resolve())
    elif args.command == "attestation-demo":
        # Intentionally self-attests generated synthetic examples in memory.
        # This shows HMAC envelope mechanics, NOT external provenance.
        import secrets
        examples = Path(__file__).resolve().parents[2] / "examples"
        train_paths = [examples / "labeled" / f"lab_clean_{name}.json"
                       for name in ("alpha", "beta")]
        holdout_paths = [
            examples / "episodic" / f"episodic_holdout_{name}.json"
            for name in ("alpha", "beta", "gamma")]
        trusted = {}
        train_env, holdout_env = [], []
        for idx, source in enumerate(
            [*[load_labeled(p) for p in train_paths],
             *[load_episodic(p) for p in holdout_paths]]
        ):
            kid = f"demo_key_{idx}"
            secret = secrets.token_bytes(32)
            trusted[kid] = TrustedIdentity(
                source["source_id"], source["lineage_id"], secret)
            envelope = create_envelope(
                source, key_id=kid, sequence=1, secret=secret)
            (train_env if idx < len(train_paths) else holdout_env).append(envelope)
        report = evaluate_attested_episodes(train_env, holdout_env, trusted)
        report["attestation"]["self_signed_synthetic_demo"] = True
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "attestation_demo.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["overall"], ensure_ascii=False, indent=2))
        print("Exported self-attested SYNTHETIC demo to", args.output.resolve())
    elif args.command == "clock-study":
        try:
            report = run_clock_study(args.train, args.holdout)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "clock_study.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(
            [{"case": case["case"], "overall": case["overall"]}
             for case in report["cases"]], ensure_ascii=False, indent=2))
        print("Exported clock-bin sensitivity to", args.output.resolve())
    elif args.command == "episode-audit":
        try:
            summary = audit_episodic(load_episodic(args.input))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.command == "episode-eval":
        try:
            report = run_temporal_eval(args.train, args.holdout)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "episode_comparison.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["overall"], ensure_ascii=False, indent=2))
        print("Exported onset-agnostic episode comparison to", args.output.resolve())
    elif args.command == "labeled-audit":
        try:
            summary = audit_labeled(load_labeled(args.input))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.command == "labeled-eval":
        try:
            report = run_labeled_eval(args.train, args.holdout)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "labeled_comparison.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(report["overall"], ensure_ascii=False, indent=2))
        print("Exported labeled comparison to", args.output.resolve())
    elif args.command == "zonal-compare":
        if not 1 <= args.train_runs <= 100 or not 1 <= args.test_runs <= 100:
            parser.error("Training and test runs must be between 1 and 100")
        try:
            result = heldout_comparison(
                train_seeds=tuple(range(args.train_start_seed,
                                        args.train_start_seed + args.train_runs)),
                test_seeds=tuple(range(args.test_start_seed,
                                       args.test_start_seed + args.test_runs)),
                duration_s=args.duration, subscribers=args.subscribers,
            )
        except ValueError as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "zonal_comparison.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        for key in ("training", "overall", "per_source"):
            print(json.dumps({key: result[key]}, ensure_ascii=False, indent=2))
        print("Exported source-heldout zonal comparison to", args.output.resolve())
    elif args.command == "aggregate-audit":
        try:
            summary = source_summary(load_dataset(args.input))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.command == "external-eval":
        try:
            result = run_external_eval(args.train, args.holdout)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "external_eval.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(json.dumps(result["holdout"], ensure_ascii=False, indent=2))
        print("Exported source-disjoint evaluation to", args.output.resolve())
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
            node_case=args.node_case,
            observer_case=args.observer_case,
            observer_loss_rate=args.observer_loss_rate,
            report_fault_nodes=tuple(filter(None, (
                n.strip() for n in args.report_fault_nodes.split(",")))),
            shared_zone_case=args.shared_zone_case,
            shared_zone_probability=args.shared_zone_probability,
            observer_capture_miss=args.observer_capture_miss,
            quorum_max_count_delta=args.quorum_max_count_delta,
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
