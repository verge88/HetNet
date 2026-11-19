"""Local-only HetNet Studio HTTP server.

No arbitrary file access, custom scenario code, private HMAC keys, operator
inputs, or persistent SQLite endpoints are exposed here. API calls require
a custom same-origin header and a loopback Host to limit browser CSRF and
DNS rebinding. Server binds loopback only; it is not an authenticated service.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
from urllib.parse import parse_qs, urlsplit

from .dashboard_research import run_study
from .fault_domains import MONITORED_NODES
from .simulator import Scenario, Simulator
from .web_ui import HTML

LOOPBACK_NAMES = frozenset(("127.0.0.1", "::1", "localhost"))
RUN_FIELDS = frozenset((
    "duration", "subscribers", "seed", "traffic", "nodecase", "observercase",
    "observerloss", "reportnodes", "sharedzone", "sharedprob",
    "capturemiss", "countdelta", "attacks",
))
NODE_CASES = frozenset(("auto", "none", "report", "tamper", "both"))
OBSERVER_CASES = frozenset((
    "none", "one_faulty", "two_colluding", "outage",
    "mixed", "bad_mac", "stale",
))
SHARED_CASES = frozenset((
    "none", "epc_outage", "epc_5gc_outage", "epc_corrupt",
    "epc_5gc_collude", "all_outage",
))
CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; connect-src 'self'; "
    "img-src 'self' data: blob:; font-src 'self'; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
)


def _parse(query: str, *, known: frozenset[str]) -> dict[str, str]:
    if len(query) > 700:
        raise ValueError("Too many URL query bytes")
    raw = parse_qs(query, keep_blank_values=True, max_num_fields=20)
    if set(raw) - known or any(len(items) != 1 for items in raw.values()):
        raise ValueError("Unknown or duplicate dashboard parameter")
    return {key: values[0] for key, values in raw.items()}


def _integer(params: dict[str, str], key: str, default: str,
             low: int, high: int) -> int:
    literal = params.get(key, default)
    if len(literal) > 14 or not literal.isdecimal():
        raise ValueError(key + " must be an integer")
    result = int(literal)
    if not low <= result <= high:
        raise ValueError(key + " outside allowed range")
    return result


def _number(params: dict[str, str], key: str, default: str,
            low: float, high: float) -> float:
    literal = params.get(key, default)
    if len(literal) > 22:
        raise ValueError(key + " too long")
    try:
        result = float(literal)
    except ValueError as error:
        raise ValueError(key + " must be numeric") from error
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError(key + " must be finite and within range")
    return result


def scenario_from_query(query: str) -> Scenario:
    params = _parse(query, known=RUN_FIELDS)
    node_case = params.get("nodecase", "auto")
    observer_case = params.get("observercase", "none")
    shared_zone = params.get("sharedzone", "none")
    if (node_case not in NODE_CASES or observer_case not in OBSERVER_CASES
            or shared_zone not in SHARED_CASES):
        raise ValueError("Unknown attack or observer configuration")
    names = params.get("reportnodes", "")
    report_nodes = [name.strip() for name in names.split(",") if name.strip()]
    if (len(set(report_nodes)) != len(report_nodes)
            or any(name not in MONITORED_NODES for name in report_nodes)):
        raise ValueError("Unknown or duplicate monitored report node")
    attacks = params.get("attacks", "1")
    if attacks not in ("0", "1"):
        raise ValueError("attacks must be 0 or 1")
    return Scenario(
        duration_s=_integer(params, "duration", "18", 5, 90),
        subscribers=_integer(params, "subscribers", "8", 4, 40),
        seed=_integer(params, "seed", "42", 0, 999999999),
        traffic_scale=_number(params, "traffic", "1", 0, 10),
        node_case=node_case,
        observer_case=observer_case,
        observer_loss_rate=_number(params, "observerloss", "0", 0, 1),
        report_fault_nodes=tuple(report_nodes),
        shared_zone_case=shared_zone,
        shared_zone_probability=_number(params, "sharedprob", "1", 0, 1),
        observer_capture_miss=_number(params, "capturemiss", "0", 0, .5),
        quorum_max_count_delta=_integer(params, "countdelta", "0", 0, 100),
        inject_attacks=attacks == "1",
    )


def _is_loopback_host(value: str) -> bool:
    if not value or len(value) > 110:
        return False
    try:
        parsed = urlsplit("http://" + value)
        return (parsed.hostname in LOOPBACK_NAMES and parsed.username is None
                and parsed.password is None and parsed.path == ""
                and parsed.query == "" and parsed.fragment == "")
    except ValueError:
        return False


def make_dashboard_server(host: str = "127.0.0.1",
                          port: int = 8080) -> ThreadingHTTPServer:
    if host not in LOOPBACK_NAMES:
        raise ValueError("Dashboard is local-only: use 127.0.0.1, ::1 or localhost")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Invalid dashboard port")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            # Require a loopback Host, avoiding private-browser DNS rebinding.
            if not _is_loopback_host(self.headers.get("Host", "")):
                self._json(403, {"error": "Loopback Host required"})
                return
            path = urlsplit(self.path)
            if path.path == "/":
                if path.query:
                    self._json(400, {"error": "No query parameters on document"})
                else:
                    self._send(200, "text/html; charset=utf-8",
                               HTML.encode("utf-8"))
                return
            if path.path not in ("/api/run", "/api/study"):
                self._json(404, {"error": "Unknown route"})
                return
            # Browsers from other sites cannot attach this custom header
            # without CORS preflight (which our server never enables).
            if self.headers.get("X-HetNet-UI") != "1":
                self._json(403, {"error": "Same-origin UI header required"})
                return
            site = self.headers.get("Sec-Fetch-Site")
            if site not in (None, "same-origin", "none"):
                self._json(403, {"error": "Cross-site requests are disabled"})
                return
            origin = self.headers.get("Origin")
            if origin:
                try:
                    parsed = urlsplit(origin)
                    valid = (parsed.scheme == "http"
                             and parsed.hostname in LOOPBACK_NAMES
                             and parsed.port == self.server.server_port
                             and not parsed.path and not parsed.query
                             and not parsed.fragment)
                except ValueError:
                    valid = False
                if not valid:
                    self._json(403, {"error": "Cross-origin requests are disabled"})
                    return
            try:
                if path.path == "/api/run":
                    result = Simulator(scenario_from_query(path.query)).run()
                else:
                    params = _parse(path.query, known=frozenset(("name",)))
                    result = run_study(params.get("name", "episodes"))
                self._json(200, result)
            except (TypeError, ValueError, OverflowError) as error:
                self._json(400, {"error": str(error)})
            except OSError:
                self._json(503, {"error": "Required synthetic fixtures unavailable"})

        def _json(self, status: int, value: dict) -> None:
            self._send(
                status, "application/json; charset=utf-8",
                json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
            )

        def _send(self, status: int, mime: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = make_dashboard_server(host, port)
    print("HetNet Studio: http://{}:{}/".format(host, server.server_port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
