"""Stage 14 local GUI: responsive UI, validated APIs, and privacy boundaries."""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from hetnet.dashboard_research import STUDIES, list_studies, run_study
from hetnet.web import (
    HTML, make_dashboard_server, scenario_from_query,
)


@contextmanager
def running_server():
    server = make_dashboard_server("127.0.0.1", 0)
    runner = threading.Thread(target=server.serve_forever, daemon=True)
    runner.start()
    try:
        yield "http://127.0.0.1:{}".format(server.server_port)
    finally:
        server.shutdown()
        runner.join(timeout=5)
        server.server_close()


def get_json(base, endpoint, *, headers=None):
    request = Request(base + endpoint, headers=headers or {})
    try:
        with urlopen(request, timeout=20) as resp:
            return resp.status, dict(resp.headers), json.load(resp)
    except HTTPError as err:
        return err.code, dict(err.headers), json.loads(err.read())


UI_HEADER = {"X-HetNet-UI": "1"}


class ScenarioValidationTests(unittest.TestCase):
    def test_safe_defaults_and_all_visible_scenario_controls(self):
        scenario = scenario_from_query("")
        self.assertEqual(scenario.seed, 42)
        self.assertEqual(scenario.duration_s, 18)
        self.assertEqual(scenario.observer_capture_miss, 0)
        changed = scenario_from_query(urlencode({
            "duration": "12", "subscribers": "9", "seed": "12",
            "traffic": "1.5", "nodecase": "report",
            "observercase": "one_faulty", "observerloss": "0.2",
            "reportnodes": "msc2,amf5", "sharedzone": "epc_outage",
            "sharedprob": "0.5", "capturemiss": "0.1",
            "countdelta": "2", "attacks": "0",
        }))
        self.assertEqual(changed.report_fault_nodes, ("msc2", "amf5"))
        self.assertEqual(changed.shared_zone_case, "epc_outage")
        self.assertEqual(changed.observer_loss_rate, .2)
        self.assertEqual(changed.quorum_max_count_delta, 2)
        self.assertFalse(changed.inject_attacks)

    def test_malformed_queries_are_bounded_and_fail_closed(self):
        for query in (
            "duration=91", "duration=-1", "duration=notanumber",
            "subscribers=41", "seed=-1", "seed=1000000000",
            "traffic=NaN", "traffic=Infinity", "traffic=-1",
            "traffic=10.01", "observerloss=NaN",
            "observerloss=1.1", "capturemiss=-0.1",
            "capturemiss=0.51", "sharedprob=-0.1",
            "countdelta=101", "countdelta=True",
            "nodecase=inject_code", "observercase=untrusted",
            "sharedzone=unrecognized", "reportnodes=unknown",
            "reportnodes=msc2,msc2", "attacks=yes",
            "seed=1&seed=2", "any_file=private.json",
            "duration=" + "3" * 900,
        ):
            with self.subTest(query=query[:95]), self.assertRaises(
                    (ValueError, TypeError)):
                scenario_from_query(query)


class ResearchStudyTests(unittest.TestCase):
    def test_studies_are_whitelisted_and_safe(self):
        available = list_studies()
        self.assertEqual({x["id"] for x in available["studies"]},
                         set(STUDIES))
        self.assertIn("синтетические", available["security"])
        for name in ("../private", "/etc/passwd", "attested", "sqlite"):
            with self.assertRaises(ValueError):
                run_study(name)

    def test_all_four_studies_return_aggregate_only_summaries(self):
        for name in STUDIES:
            with self.subTest(study=name):
                report = run_study(name)
                self.assertEqual(report["id"], name)
                self.assertTrue(report["rows"])
                self.assertTrue(all(row["label"] for row in report["rows"]))
                self.assertEqual(json.loads(json.dumps(report)), report)
                serialized = json.dumps(report)
                for forbidden in (
                    '"measurements"', '"episodes"', '"attack_label"',
                    '"secret_b64"', '"mac_sha256"',
                    '"reference_count"', '"reported_count"',
                    '"source_id"', '"lineage_id"',
                ):
                    self.assertNotIn(forbidden, serialized)
                self.assertTrue(any("синтетичес" in x.lower()
                                    for x in report["limitations"]))

    def test_clock_study_contains_all_four_fixed_clock_cases(self):
        report = run_study("clock")
        self.assertEqual(len(report["rows"]), 4)
        self.assertEqual(report["rows"][0]["label"], "aligned")
        self.assertTrue(all(0 <= row["primary"] <= 1
                            for row in report["rows"]))


class BrowserMarkupTests(unittest.TestCase):
    def test_ui_has_three_views_and_downloads_and_is_responsive(self):
        for expected in (
            'id="overview"', 'id="research"', 'id="security"',
            'id="controls"', 'id="study-form"',
            'id="topology"', 'id="node-table"',
            'id="zone-table"', 'id="event-table"',
            'id="histogram"', 'id="export-simulation"',
            'id="export-study"', '@media(max-width:780px)',
            'data-preset="normal"', 'data-preset="outage"',
            'aria-live="polite"', "X-HetNet-UI",
        ):
            self.assertIn(expected, HTML)

    def test_privacy_controls_are_command_line_only(self):
        self.assertNotIn('type="file"', HTML)
        self.assertNotIn('api/upload', HTML)
        self.assertNotIn('api/attestation', HTML)
        self.assertNotIn('input id="secret"', HTML)
        self.assertNotIn("innerHTML", HTML)
        self.assertNotIn('https://cdn', HTML)


class BrowserApiTests(unittest.TestCase):
    def test_loopback_only_binding(self):
        for host in ("0.0.0.0", "192.0.2.2", "example.com", ""):
            with self.subTest(host=host), self.assertRaises(ValueError):
                make_dashboard_server(host, 0)
        with self.assertRaises(ValueError):
            make_dashboard_server("127.0.0.1", 65536)

    def test_html_is_delivered_without_third_party_assets(self):
        with running_server() as base:
            with urlopen(base + "/", timeout=10) as response:
                self.assertEqual(response.status, 200)
                html = response.read().decode("utf-8")
                self.assertIn("HetNet Studio", html)
                self.assertIn('id="research"', html)
                self.assertIn("default-src 'none'",
                              response.headers["Content-Security-Policy"])
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_run_returns_valid_synthetic_node_and_topology_fields(self):
        with running_server() as base:
            code, headers, report = get_json(
                base, "/api/run?duration=5&subscribers=4&seed=21",
                headers=UI_HEADER)
            self.assertEqual(code, 200, report)
            self.assertIn("events", report)
            self.assertIn("nodes", report)
            self.assertIn("alerts", report)
            self.assertIn("zonal_evidence", report)
            self.assertIn("node_evidence", report)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_without_ui_header_denied_including_on_localhost(self):
        with running_server() as base:
            for path in (
                "/api/run?duration=5&subscribers=4",
                "/api/study?name=episodes",
            ):
                with self.subTest(path=path):
                    code, _, data = get_json(base, path)
                    self.assertEqual(code, 403, data)

    def test_host_header_and_cross_origin_requests_denied(self):
        with running_server() as base:
            for headers in (
                {"X-HetNet-UI": "1", "Host": "private.attacker.net"},
                {"X-HetNet-UI": "1", "Origin": "https://example.com"},
                {"X-HetNet-UI": "1", "Sec-Fetch-Site": "cross-site"},
            ):
                with self.subTest(headers=headers):
                    code, _, _ = get_json(
                        base, "/api/study?name=episodes", headers=headers)
                    self.assertEqual(code, 403)

    def test_bad_scenarios_do_not_start_simulations(self):
        with running_server() as base:
            for q in ("traffic=Infinity", "duration=180",
                      "reportnodes=invalid", "seed=2&seed=3",
                      "file=/etc/passwd"):
                with self.subTest(query=q):
                    code, _, data = get_json(
                        base, "/api/run?" + q, headers=UI_HEADER)
                    self.assertEqual(code, 400, data)
                    self.assertIn("error", data)

    def test_research_http_returns_only_safe_synthetic_summary(self):
        with running_server() as base:
            code, _, report = get_json(
                base, "/api/study?name=episodes", headers=UI_HEADER)
            self.assertEqual(code, 200, report)
            self.assertEqual(report["id"], "episodes")
            self.assertEqual(len(report["rows"]), 3)
            self.assertNotIn('"measurements"', json.dumps(report))
            for query in ("name=../../private", "name=zonal&name=clock",
                          "output=/tmp/foo"):
                status, _, _ = get_json(
                    base, "/api/study?" + query, headers=UI_HEADER)
                self.assertEqual(status, 400)

    def test_unknown_routes_are_not_local_file_reads(self):
        with running_server() as base:
            for path in ("/private/trust.json", "/api/sqlite",
                         "/api/attestation", "/favicon.ico"):
                code, _, _ = get_json(base, path, headers=UI_HEADER)
                self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
