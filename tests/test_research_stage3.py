"""Stage 3 tests: offline wire headers, non-PII calibration, episode evaluation."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from hetnet import Scenario, Simulator
from hetnet.calibration import calibrate, calibrate_file, load_rates
from hetnet.cli import main
from hetnet.episode import OfflineDetector, episodes, evaluate_episodes, run_validation
from hetnet.traffic import TrafficGenerator
from hetnet.wire import (DecodeError, inspect_wire, parse_diameter,
                         parse_gtpv2, parse_http2_frame, parse_sip)


def diameter_avp(vendor=False):
    header = (264).to_bytes(4, "big")
    if vendor:
        return (header + b"\x80" + (15).to_bytes(3, "big")
                + (10415).to_bytes(4, "big") + b"abc" + b"\x00")
    return header + b"\x40" + (11).to_bytes(3, "big") + b"abc" + b"\x00"


def diameter_packet(avp=b""):
    total = 20 + len(avp)
    return (b"\x01" + total.to_bytes(3, "big")
            + b"\x80" + (318).to_bytes(3, "big")
            + (16777251).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + (2).to_bytes(4, "big") + avp)


def gtp_packet(ie=b""):
    # T flag, CreateSessionRequest, TEID 0, sequence 1, spare 0.
    return (b"\x48\x20" + (8 + len(ie)).to_bytes(2, "big")
            + b"\x00\x00\x00\x00\x00\x00\x01\x00" + ie)


def sip_packet():
    return (b"INVITE sip:bob@example.org SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP caller.example.org;branch=z9hG4bK01\r\n"
            b"To: <sip:bob@example.org>\r\n"
            b"From: <sip:alice@example.org>;tag=x\r\n"
            b"Call-ID: test-call-01\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n")


class WireChecks(unittest.TestCase):
    def test_diameter_header_and_padded_avps(self):
        one = parse_diameter(diameter_packet(diameter_avp()))
        self.assertEqual((one["command_code"], one["application_id"]), (318, 16777251))
        self.assertEqual(one["avps"][0]["data_length"], 3)
        with_vendor = parse_diameter(diameter_packet(diameter_avp(True)))
        self.assertEqual(with_vendor["avps"][0]["vendor_id"], 10415)
        self.assertTrue(with_vendor["request"])

    def test_diameter_rejects_bad_lengths_and_padding(self):
        packet = bytearray(diameter_packet(diameter_avp()))
        packet[-1] = 1
        with self.assertRaises(DecodeError):
            parse_diameter(bytes(packet))
        packet = bytearray(diameter_packet(diameter_avp()))
        packet[25:28] = b"\x00\x00\x03"
        with self.assertRaises(DecodeError):
            parse_diameter(bytes(packet))
        with self.assertRaises(DecodeError):
            parse_diameter(diameter_packet() + b"extra")
        with self.assertRaises(DecodeError):
            parse_diameter(b"\x01" * 19)

    def test_gtpv2_teid_sequence_ie(self):
        ie = b"\x57\x00\x01\x00\x02"
        result = parse_gtpv2(gtp_packet(ie))
        self.assertEqual(result["sequence"], 1)
        self.assertTrue(result["teid_present"])
        self.assertEqual(result["ies"][0]["type"], 87)
        no_teid_echo = b"\x40\x01\x00\x04\x00\x00\x01\x00"
        self.assertFalse(parse_gtpv2(no_teid_echo)["teid_present"])

    def test_gtpv2_rejects_truncation_and_piggyback(self):
        with self.assertRaises(DecodeError):
            parse_gtpv2(gtp_packet(b"\x57\x00\x05\x00\x01"))
        with self.assertRaises(DecodeError):
            parse_gtpv2(bytes([0x58]) + gtp_packet()[1:])
        with self.assertRaises(DecodeError):
            parse_gtpv2(gtp_packet()[:-1])

    def test_sip_request_response_and_content_length(self):
        msg = sip_packet()
        info = parse_sip(msg)
        self.assertEqual(info["method"], "INVITE")
        self.assertEqual(info["call_id"], "test-call-01")
        self.assertEqual(info["body_length"], 0)
        response = msg.replace(
            b"INVITE sip:bob@example.org SIP/2.0", b"SIP/2.0 200 OK"
        )
        self.assertEqual(parse_sip(response)["status"], 200)

    def test_sip_rejects_mismatch_duplicates_lf(self):
        with self.assertRaises(DecodeError):
            parse_sip(sip_packet().replace(b"CSeq: 1 INVITE", b"CSeq: 1 BYE"))
        with self.assertRaises(DecodeError):
            parse_sip(sip_packet().replace(b"Content-Length: 0", b"Content-Length: 2"))
        with self.assertRaises(DecodeError):
            parse_sip(sip_packet().replace(b"\r\n", b"\n"))
        with self.assertRaises(DecodeError):
            parse_sip(sip_packet().replace(
                b"Call-ID: test-call-01", b"Call-ID: a\r\nCall-ID: b"))

    def test_http2_settings_ping_and_bad_frame(self):
        settings = b"\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x64"
        parsed = parse_http2_frame(settings)
        self.assertEqual((parsed["frame_type"], parsed["stream_id"]), (4, 0))
        ping = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"abcdefgh"
        self.assertEqual(parse_http2_frame(ping)["length"], 8)
        with self.assertRaises(DecodeError):
            parse_http2_frame(settings[:9] + b"ab")
        with self.assertRaises(DecodeError):
            parse_http2_frame(settings[:5] + b"\x00\x00\x00\x01" + settings[9:])
        with self.assertRaises(DecodeError):
            inspect_wire("bogus", b"123456789")
        with self.assertRaises(DecodeError):
            inspect_wire("http2", b"\x00" * (1_048_576 + 1))

    def test_offline_cli_hex(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            main(["wirecheck", "--protocol", "diameter",
                  "--hex", diameter_packet(diameter_avp()).hex()])
        self.assertEqual(json.loads(stream.getvalue())["command_code"], 318)


class CalibrationTests(unittest.TestCase):
    def test_weighted_rates_from_aggregates(self):
        source = {"source": "synthetic demo; not operator telemetry", "measurements": [
            {"domain": "map_2g", "duration_seconds": 10, "request_count": 4},
            {"domain": "map_2g", "duration_seconds": 30, "request_count": 4},
            {"domain": "sip_ims", "duration_seconds": 10, "request_count": 0},
        ]}
        result = calibrate(source)
        self.assertAlmostEqual(result["rates"]["map_2g"], 0.2)
        self.assertEqual(result["rates"]["sip_ims"], 0.0)
        with tempfile.TemporaryDirectory() as tmp:
            raw, ready = Path(tmp) / "counts.json", Path(tmp) / "rates.json"
            raw.write_text(json.dumps(source), encoding="utf-8")
            calibrate_file(raw, ready)
            rates = load_rates(ready)
        self.assertEqual(rates, {"map_2g": 0.2, "sip_ims": 0.0})

    def test_rejects_invalid_or_personalized_inputs(self):
        for row in (
            {"domain": "map_2g", "duration_seconds": 0, "request_count": 3},
            {"domain": "unknown", "duration_seconds": 10, "request_count": 3},
            {"domain": "sip_ims", "duration_seconds": 10, "request_count": True},
            {"domain": "sip_ims", "duration_seconds": 10,
             "request_count": 1, "imsi": "forbidden"},
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                calibrate({"measurements": [row]})

    def test_rate_overrides_affect_generator(self):
        a = list(TrafficGenerator(5, scale=1, rates={"map_2g": 0}).stream(40, 8))
        self.assertTrue(all(p.domain != "map_2g" for _, p, _, _ in a))
        baseline = list(TrafficGenerator(5, scale=1).stream(40, 8))
        self.assertTrue(any(p.domain == "map_2g" for _, p, _, _ in baseline))


class EpisodeTests(unittest.TestCase):
    def test_sip_flood_episode_matches_one_alarm(self):
        result = Simulator(Scenario(
            duration_s=15, subscribers=8, seed=42, inject_attacks=True)).run()
        samples = episodes(result["events"])
        flood = [ep for ep in samples if ep["ground_truth"]
                 and ep["protocol"] == "SIP/IMS"]
        self.assertEqual(len(flood), 1)
        self.assertEqual(flood[0]["messages"], 14)
        built_in = evaluate_episodes(result["events"], result["alerts"])
        self.assertEqual(built_in["positive_episodes"], 4)
        self.assertEqual(built_in["tp"], 4)
        self.assertEqual(built_in["fn"], 0)

    def test_offline_observer_ignores_attack_truth_column(self):
        sim = Simulator(Scenario(
            duration_s=15, subscribers=8, seed=42, inject_attacks=True))
        result = sim.run()
        detector = OfflineDetector()
        detector.fit([Simulator(Scenario(
            duration_s=15, subscribers=8, seed=22,
            inject_attacks=False)).run()])
        original = detector.detect(result["events"])
        copied = [{**event, "attack": not event["attack"]}
                  for event in result["events"]]
        self.assertEqual(original, detector.detect(copied))
        evaluation = evaluate_episodes(result["events"], original)
        self.assertEqual(evaluation["tp"], 4)

    def test_disjoint_seed_validation_with_clean_controls(self):
        report = run_validation(
            train_seeds=(21, 22), test_seeds=(42, 43),
            duration_s=15, subscribers=8)
        self.assertEqual(len(report["rows"]), 4)
        self.assertEqual(len(report["clean_control_rows"]), 4)
        self.assertEqual(report["train_seeds"], [21, 22])
        self.assertIn("clean_controls", report["summary"]["offline"])
        with self.assertRaises(ValueError):
            run_validation(train_seeds=(42,), test_seeds=(42,))


if __name__ == "__main__":
    unittest.main()
