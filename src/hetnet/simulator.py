"""Deterministic control-plane simulation of coexisting 2G–5G networks.

This is a protocol-aware *abstract* simulator, not an SS7, Diameter, SIP,
GTP or HTTP/2 wire implementation. No external network packets are sent.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
import hashlib
import heapq
import hmac
import json
import random
from typing import Any

from .procedures import ProcedureLedger
from .traffic import TrafficGenerator
from .observations import aggregate
from .control import inspect_cu_events
from .consensus import OBSERVER_DOMAINS, sign_vote, consensus_from_votes, count_distance
from .probes import ProbeSampler
from .attestation import sign_cu_report
from .zonal import zonal_features
from .fault_domains import (MONITORED_NODES, FAULT_CASES,
                            CommonFaultSchedule, CommonFault)
from .domain_analysis import analyze_domain_correlations


@dataclass(frozen=True)
class Node:
    id: str
    generation: str
    role: str
    zone: str


@dataclass(frozen=True)
class Link:
    source: str
    target: str
    latency_ms: int = 8
    capacity_bps: int = 100_000_000
    buffer_bytes: int = 16_384


@dataclass(frozen=True)
class Rule:
    protocol: str
    source_roles: tuple[str, ...]
    target_roles: tuple[str, ...]
    reference: str
    response: str | None


# A subset of *logical* procedures, not exhaustive protocol implementations.
RULES: dict[str, Rule] = {
    "MAP.SendAuthenticationInfo": Rule("SS7/MAP", ("MSC", "SGSN"), ("HLR",), "3GPP TS 29.002", "MAP.ReturnResult"),
    "MAP.UpdateLocation": Rule("SS7/MAP", ("MSC",), ("HLR",), "3GPP TS 29.002", "MAP.ReturnResult"),
    "MAP.UpdateGprsLocation": Rule("SS7/MAP", ("SGSN",), ("HLR",), "3GPP TS 29.002", "MAP.ReturnResult"),
    "Diameter.AIR": Rule("Diameter", ("MME",), ("HSS",), "3GPP TS 29.272; RFC 6733", "Diameter.AIA"),
    "Diameter.ULR": Rule("Diameter", ("MME",), ("HSS",), "3GPP TS 29.272; RFC 6733", "Diameter.ULA"),
    "GTPv2-C.CreateSessionRequest": Rule("GTPv2-C", ("MME",), ("SGW",), "3GPP TS 29.274", "GTPv2-C.CreateSessionResponse"),
    "SIP.REGISTER": Rule("SIP/IMS", ("P-CSCF",), ("S-CSCF",), "RFC 3261; 3GPP TS 24.229", "SIP.200_REGISTER"),
    "SIP.INVITE": Rule("SIP/IMS", ("P-CSCF",), ("S-CSCF",), "RFC 3261; 3GPP TS 24.229", "SIP.200_INVITE"),
    "SIP.ACK": Rule("SIP/IMS", ("P-CSCF",), ("S-CSCF",), "RFC 3261", None),
    "SIP.BYE": Rule("SIP/IMS", ("P-CSCF",), ("S-CSCF",), "RFC 3261", "SIP.200_BYE"),
    "Nnrf_NFDiscovery.Search": Rule("5G-SBI/HTTP2", ("AMF", "SMF"), ("NRF",), "3GPP TS 29.510; TS 29.500", "HTTP.200"),
    "Nausf_UEAuthentication.Authenticate": Rule("5G-SBI/HTTP2", ("AMF",), ("AUSF",), "3GPP TS 29.509; TS 33.501", "HTTP.200"),
    "Nudm_UECM.Registration": Rule("5G-SBI/HTTP2", ("AMF",), ("UDM",), "3GPP TS 29.503", "HTTP.201"),
    "Nsmf_PDUSession.CreateSMContext": Rule("5G-SBI/HTTP2", ("AMF",), ("SMF",), "3GPP TS 29.502", "HTTP.201"),
    "Nnrf_NFManagement.NFRegister": Rule("5G-SBI/HTTP2", ("AMF", "SMF"), ("NRF",), "3GPP TS 29.510; TS 33.501", "HTTP.201"),
}
REGISTRATIONS = {
    "MAP.UpdateLocation": "2G",
    "MAP.UpdateGprsLocation": "3G",
    "Diameter.ULR": "4G",
    "Nudm_UECM.Registration": "5G",
}


class Topology:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.links: list[Link] = []
        self._adj: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self._edges: dict[tuple[str, str], Link] = {}

    def edge(self, a: str, b: str) -> Link:
        return self._edges[tuple(sorted((a, b)))]

    def add(self, name: str, generation: str, role: str, zone: str) -> None:
        if name in self.nodes:
            raise ValueError("Duplicate node: " + name)
        self.nodes[name] = Node(name, generation, role, zone)

    def connect(self, a: str, b: str, latency_ms: int = 8,
                capacity_bps: int | None = None,
                buffer_bytes: int = 16_384) -> None:
        if (a not in self.nodes or b not in self.nodes or a == b
                or latency_ms <= 0 or buffer_bytes <= 0):
            raise ValueError("Invalid topology edge")
        key = tuple(sorted((a, b)))
        if key in self._edges:
            raise ValueError("Duplicate topology link")
        if capacity_bps is None:
            # Demonstration profile from thesis §3.2: SS7 links 64–128 kbps.
            capacity_bps = 128_000 if {a, b} == {"stp", "hlr"} else (
                64_000 if "stp" in key else 100_000_000)
        if capacity_bps <= 0:
            raise ValueError("Capacity must be positive")
        link = Link(a, b, latency_ms, capacity_bps, buffer_bytes)
        self.links.append(link)
        self._edges[key] = link
        self._adj[a].append((b, latency_ms))
        self._adj[b].append((a, latency_ms))

    def path(self, source: str, target: str) -> tuple[str, ...]:
        if source not in self.nodes or target not in self.nodes:
            return ()
        queue = [(0, (source,), source)]
        best: dict[str, int] = {}
        while queue:
            cost, route, vertex = heapq.heappop(queue)
            if vertex in best:
                continue
            best[vertex] = cost
            if vertex == target:
                return route
            for neighbor, weight in sorted(self._adj[vertex]):
                if neighbor not in best:
                    heapq.heappush(queue, (cost + weight, route + (neighbor,), neighbor))
        return ()

    def latency(self, path: tuple[str, ...]) -> int:
        return sum(next(weight for neighbor, weight in self._adj[a] if neighbor == b)
                   for a, b in zip(path, path[1:]))


def default_topology() -> Topology:
    """Logical control-plane connectivity. Radio physical layers are out of scope."""
    net = Topology()
    for args in (
        ("bsc2", "2G", "BSC", "access"), ("msc2", "2G", "MSC", "legacy"),
        ("stp", "2G/3G", "STP", "legacy"), ("hlr", "2G/3G", "HLR", "legacy"),
        ("rnc3", "3G", "RNC", "access"), ("sgsn3", "3G", "SGSN", "legacy"),
        ("enb4", "4G", "eNB", "access"), ("mme4", "4G", "MME", "epc"),
        ("dra", "4G", "DRA", "epc"), ("hss4", "4G", "HSS", "epc"),
        ("sgw4", "4G", "SGW", "epc"), ("pgw4", "4G", "PGW", "epc"),
        ("pcrf4", "4G", "PCRF", "epc"),
        ("pcscf", "IMS", "P-CSCF", "ims"), ("scscf", "IMS", "S-CSCF", "ims"),
        ("gnb5", "5G", "gNB", "access"), ("amf5", "5G", "AMF", "5gc"),
        ("ausf5", "5G", "AUSF", "5gc"), ("udm5", "5G", "UDM", "5gc"),
        ("smf5", "5G", "SMF", "5gc"), ("upf5", "5G", "UPF", "5gc"),
        ("nrf5", "5G", "NRF", "5gc"), ("sepp5", "5G", "SEPP", "border"),
        ("iwf", "shared", "IWF", "interworking"),
        ("external", "external", "EXTERNAL", "untrusted"),
    ):
        net.add(*args)
    for a, b, latency in (
        ("bsc2", "msc2", 6), ("msc2", "stp", 9), ("stp", "hlr", 8),
        ("rnc3", "sgsn3", 6), ("sgsn3", "stp", 9),
        ("enb4", "mme4", 5), ("mme4", "dra", 7), ("dra", "hss4", 8),
        ("mme4", "sgw4", 6), ("sgw4", "pgw4", 7), ("pgw4", "pcrf4", 6),
        ("pgw4", "pcscf", 9), ("pcscf", "scscf", 8),
        ("gnb5", "amf5", 5), ("amf5", "ausf5", 7),
        ("amf5", "udm5", 8), ("amf5", "smf5", 6),
        ("smf5", "upf5", 6), ("amf5", "nrf5", 7),
        ("nrf5", "sepp5", 9), ("stp", "iwf", 12),
        ("iwf", "dra", 11), ("iwf", "amf5", 12),
        ("external", "stp", 15),
    ):
        net.connect(a, b, latency)
    return net


@dataclass
class Scenario:
    duration_s: int = 18
    subscribers: int = 8
    seed: int = 42
    inject_attacks: bool = True
    loss_rate: float = 0.0
    cu_interval_ms: int = 1500
    traffic_scale: float = 1.0
    traffic_amplitude: float = 0.35
    traffic_peak_hour: float = 18.0
    traffic_ar1_phi: float = 0.7
    transaction_timeout_ms: int = 2000
    traffic_rates: dict[str, float] = field(default_factory=dict)
    node_case: str = "auto"  # auto, none, report, tamper, both
    observer_case: str = "none"
    observer_loss_rate: float = 0.0
    report_fault_nodes: tuple[str, ...] = ()
    shared_zone_case: str = "none"
    shared_zone_probability: float = 1.0
    observer_capture_miss: float = 0.0
    quorum_max_count_delta: int = 0

    def __post_init__(self) -> None:
        if not 5 <= self.duration_s <= 86400:
            raise ValueError("duration_s must be between 5 and 86400")
        if not 4 <= self.subscribers <= 10000:
            raise ValueError("subscribers must be between 4 and 10000")
        if not 0 <= self.loss_rate <= 1:
            raise ValueError("loss_rate must be in [0, 1]")
        if self.cu_interval_ms < 100:
            raise ValueError("cu_interval_ms must be >= 100")
        if not 0 <= self.traffic_scale <= 50:
            raise ValueError("traffic_scale must be between 0 and 50")
        if not 0 <= self.traffic_amplitude < 1:
            raise ValueError("traffic_amplitude must be in [0,1)")
        if not 0 <= self.traffic_peak_hour < 24:
            raise ValueError("traffic_peak_hour must be in [0,24)")
        if not 0 <= self.traffic_ar1_phi < 1:
            raise ValueError("traffic_ar1_phi must be in [0,1)")
        if self.transaction_timeout_ms < 200:
            raise ValueError("transaction_timeout_ms must be >= 200")
        if self.node_case not in ("auto", "none", "report", "tamper", "both"):
            raise ValueError("node_case must be auto, none, report, tamper or both")
        if self.observer_case not in ("none", "one_faulty", "two_colluding",
                                      "outage", "mixed", "bad_mac", "stale"):
            raise ValueError("Invalid observer fault case")
        if not 0 <= self.observer_loss_rate <= 1:
            raise ValueError("observer_loss_rate must be in [0, 1]")
        if (not isinstance(self.report_fault_nodes, tuple)
                or len(set(self.report_fault_nodes)) != len(self.report_fault_nodes)
                or any(node not in MONITORED_NODES
                       for node in self.report_fault_nodes)):
            raise ValueError("report_fault_nodes must be unique monitored node IDs")
        if self.shared_zone_case not in FAULT_CASES:
            raise ValueError("Invalid shared_zone_case")
        if not 0 <= self.shared_zone_probability <= 1:
            raise ValueError("shared_zone_probability must be in [0,1]")
        if (type(self.observer_capture_miss) not in (int, float)
                or not 0 <= self.observer_capture_miss <= 0.5):
            raise ValueError("observer_capture_miss must be in [0,0.5]")
        if (type(self.quorum_max_count_delta) is not int
                or not 0 <= self.quorum_max_count_delta <= 100):
            raise ValueError("quorum_max_count_delta must be an integer in [0,100]")


@dataclass
class Event:
    time_ms: int
    generation: str
    protocol: str
    operation: str
    source: str
    target: str
    subject: str
    correlation_id: str
    outcome: str
    latency_ms: int
    route: list[str]
    standard: str
    attack: bool = False
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    time_ms: int
    category: str
    source: str
    reason: str
    correlation_id: str


@dataclass
class Packet:
    source: str
    target: str
    operation: str
    protocol: str
    standard: str
    generation: str
    subject: str
    correlation_id: str
    sent_ms: int
    route: tuple[str, ...]
    lost: bool
    attack: bool
    payload: dict[str, Any]
    response: bool = False


class Simulator:
    """One clock, topology, event queue, normalization and security monitor."""

    def __init__(self, scenario: Scenario | None = None) -> None:
        self.scenario = scenario or Scenario()
        self.net = default_topology()
        self.rng = random.Random(self.scenario.seed)
        self._queue: list[tuple[int, int, str, Any]] = []
        self._seq = 0
        self.events: list[Event] = []
        self.alerts: list[Alert] = []
        self._alert_keys: set[tuple[str, str]] = set()
        self.registered: dict[str, str] = {}
        self._node_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._independent_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._rate: dict[tuple[str, str], deque[int]] = defaultdict(deque)
        self._procedures = ProcedureLedger(self.scenario.transaction_timeout_ms)
        self._traffic = TrafficGenerator(
            self.scenario.seed, scale=self.scenario.traffic_scale,
            amplitude=self.scenario.traffic_amplitude,
            peak_hour=self.scenario.traffic_peak_hour,
            phi=self.scenario.traffic_ar1_phi,
            rates=self.scenario.traffic_rates,
        )
        self._link_available_ms: dict[tuple[str, str], int] = defaultdict(int)
        self._queue_drops = 0
        self._max_queue_delay_ms = 0
        self._completed_invites: set[str] = set()
        self._acked_invites: set[str] = set()
        self._nf_profiles: dict[str, tuple[str, str]] = {}
        self._compromised: set[str] = set()
        self._wire_tampered: set[str] = set()
        self._cu_rng = random.Random(self.scenario.seed ^ 0xC0FFEE)
        self._observer_rng = random.Random(self.scenario.seed ^ 0x0B5E77)
        self._probes = ProbeSampler(
            self.scenario.seed, self.scenario.observer_capture_miss)
        self._common_faults = CommonFaultSchedule(
            seed=self.scenario.seed, kind=self.scenario.shared_zone_case,
            probability=self.scenario.shared_zone_probability,
            onset_ms=int(self.scenario.duration_s * 720),
        )
        self._observer_key = hashlib.sha256(
            ("hetnet-observer-lab:" + str(self.scenario.seed)).encode()).digest()
        self._cu_loss_streak: dict[str, int] = defaultdict(int)
        self._cu_last_success: dict[str, int] = {}
        self._cu_key = hashlib.sha256(("hetnet-cu-test:" + str(self.scenario.seed)).encode()).digest()
        self._executed = False

    def _push(self, time_ms: int, kind: str, item: Any) -> None:
        self._seq += 1
        heapq.heappush(self._queue, (time_ms, self._seq, kind, item))

    def _alert(self, time_ms: int, category: str, source: str,
               reason: str, correlation_id: str, dedupe: bool = False) -> None:
        key = (category, source)
        if dedupe and key in self._alert_keys:
            return
        if dedupe:
            self._alert_keys.add(key)
        self.alerts.append(Alert(time_ms, category, source, reason, correlation_id))

    def request(self, time_ms: int, operation: str, source: str, target: str,
                subject: str, correlation_id: str, generation: str,
                attack: bool = False, payload: dict[str, Any] | None = None) -> None:
        if operation not in RULES:
            raise ValueError("Unknown logical operation: " + operation)
        rule = RULES[operation]
        self._schedule_packet(time_ms, source, target, operation, rule.protocol,
                              rule.reference, generation, subject, correlation_id,
                              attack, payload or {}, False)

    def _schedule_packet(self, time_ms: int, source: str, target: str, operation: str,
                         protocol: str, standard: str, generation: str,
                         subject: str, correlation_id: str, attack: bool,
                         payload: dict[str, Any], response: bool) -> None:
        route = self.net.path(source, target)
        packet = Packet(source, target, operation, protocol, standard,
                        generation, subject, correlation_id, time_ms, route,
                        False, attack, payload, response)
        # Each hop runs at its actual simulation timestamp, so queues are
        # updated in causal event order rather than reserving future links.
        self._push(time_ms, "hop", (packet, 0))

    def _on_hop(self, now: int, packet: Packet, index: int) -> None:
        if not packet.route or index == len(packet.route) - 1:
            self._on_packet(now, packet)
            return
        left, right = packet.route[index:index + 2]
        link = self.net.edge(left, right)
        # Approximate synthetic signaling PDU sizes, not protocol wire encoding.
        estimated_bytes = {
            "SS7/MAP": 140, "Diameter": 320, "GTPv2-C": 180,
            "SIP/IMS": 520, "5G-SBI/HTTP2": 600,
        }.get(packet.protocol, 200)
        if self.rng.random() < self.scenario.loss_rate:
            packet.lost = True
            self._on_packet(now, packet)
            return
        direction = (left, right)
        available = self._link_available_ms[direction]
        backlog_bytes = max(0, available - now) * link.capacity_bps / 8000.0
        if backlog_bytes + estimated_bytes > link.buffer_bytes:
            self._queue_drops += 1
            self._record(now, packet, "CONGESTED")
            return
        departure = max(now, available)
        self._max_queue_delay_ms = max(
            self._max_queue_delay_ms, departure - now)
        serialization_ms = max(
            1, (estimated_bytes * 8 * 1000 + link.capacity_bps - 1)
            // link.capacity_bps,
        )
        self._link_available_ms[direction] = departure + serialization_ms
        self._push(departure + serialization_ms + link.latency_ms,
                   "hop", (packet, index + 1))

    def _reply(self, now: int, packet: Packet, operation: str, offset: int = 3) -> None:
        self._schedule_packet(now + offset, packet.target, packet.source, operation,
                              packet.protocol, packet.standard, packet.generation,
                              packet.subject, packet.correlation_id, packet.attack,
                              {}, True)

    def _record(self, now: int, packet: Packet, outcome: str) -> None:
        self.events.append(Event(
            now, packet.generation, packet.protocol, packet.operation,
            packet.source, packet.target, packet.subject, packet.correlation_id,
            outcome, now - packet.sent_ms, list(packet.route), packet.standard,
            packet.attack,
        ))

    def _verify_nf_profile(self, packet: Packet, now: int) -> bool:
        profile = packet.payload
        instance = profile.get("nfInstanceId")
        nf_type = profile.get("nfType")
        status = profile.get("nfStatus")
        previous = self._nf_profiles.get(packet.source)
        valid = (
            instance == packet.source + "-instance"
            and nf_type == self.net.nodes[packet.source].role
            and status in ("REGISTERED", "SUSPENDED")
            and (previous is None and status == "REGISTERED"
                 or previous is not None and previous[0] == instance
                 and (previous[1], status) in (
                     ("REGISTERED", "REGISTERED"),
                     ("REGISTERED", "SUSPENDED"),
                     ("SUSPENDED", "REGISTERED"),
                     ("SUSPENDED", "SUSPENDED")))
        )
        if valid:
            self._nf_profiles[packet.source] = (instance, status)
        else:
            self._alert(now, "nfprofile_invariant", packet.source,
                        "NFProfile identity/type or lifecycle transition invalid",
                        packet.correlation_id)
        return bool(valid)

    def _on_packet(self, now: int, packet: Packet) -> None:
        if not packet.route:
            self._record(now, packet, "NO_ROUTE")
            self._alert(now, "no_route", packet.source, "Topology has no path",
                        packet.correlation_id)
            return
        if packet.lost:
            self._record(now, packet, "LOST")
            return
        if not packet.response:
            rule = RULES[packet.operation]
            source_role = self.net.nodes[packet.source].role
            target_role = self.net.nodes[packet.target].role
            if (source_role not in rule.source_roles or
                    target_role not in rule.target_roles):
                self._record(now, packet, "REJECTED")
                self._alert(now, "unauthorized_operation", packet.source,
                            packet.operation + ": role/endpoint policy denied",
                            packet.correlation_id)
                return
            if packet.operation == "Nnrf_NFManagement.NFRegister":
                if not self._verify_nf_profile(packet, now):
                    self._record(now, packet, "REJECTED")
                    return
        if packet.response:
            decision = self._procedures.inspect_response(
                now, packet.operation, packet.source, packet.target,
                packet.subject, packet.correlation_id)
        else:
            decision = self._procedures.inspect_request(
                now, packet.operation, RULES[packet.operation].response,
                packet.source, packet.target, packet.subject, packet.correlation_id)
        if not decision.accepted:
            self._record(now, packet, "REJECTED")
            self._alert(now, decision.category, packet.source,
                        decision.reason, packet.correlation_id)
            return
        self._record(now, packet, "DELIVERED")
        self._node_counts[packet.source][packet.operation] += 1
        # Independent observer is outside the reporting node (abstract transit tap).
        self._independent_counts[packet.source][packet.operation] += 1

        if packet.operation == "SIP.INVITE":
            window = self._rate[(packet.source, packet.operation)]
            window.append(now)
            while window and window[0] < now - 1000:
                window.popleft()
            if len(window) > 6:
                self._alert(now, "signaling_rate_spike", packet.source,
                            "More than six INVITE events in a rolling second",
                            packet.correlation_id, dedupe=True)

        if packet.response:
            if decision.completed in REGISTRATIONS:
                # Registration is committed only on a matched successful reply.
                self.registered[packet.subject] = REGISTRATIONS[decision.completed]
            if packet.operation == "SIP.200_INVITE":
                self._completed_invites.add(packet.correlation_id)
                if packet.correlation_id not in self._acked_invites:
                    self.request(now + 4, "SIP.ACK", "pcscf", "scscf",
                                 packet.subject, packet.correlation_id,
                                 packet.generation, packet.attack)
            return

        if packet.operation == "SIP.ACK":
            if packet.correlation_id not in self._completed_invites:
                self._alert(now, "sip_unexpected_ack", packet.source,
                            "ACK not correlated with a received 2xx INVITE",
                            packet.correlation_id)
            else:
                self._acked_invites.add(packet.correlation_id)
                self.request(now + 10, "SIP.BYE", "pcscf", "scscf",
                             packet.subject, packet.correlation_id,
                             packet.generation, packet.attack)
        if packet.operation == "SIP.INVITE":
            self._reply(now, packet, "SIP.100_TRYING", 2)
            self._reply(now, packet, "SIP.180_RINGING", 15)
            self._reply(now, packet, "SIP.200_INVITE", 35)
        else:
            response = RULES[packet.operation].response
            if response:
                self._reply(now, packet, response)

    def _attach(self, at: int, subject: str, gen: str, corr: str) -> None:
        if gen == "2G":
            plan = [
                (0, "MAP.SendAuthenticationInfo", "msc2", "hlr", {}),
                (130, "MAP.UpdateLocation", "msc2", "hlr", {}),
            ]
        elif gen == "3G":
            plan = [
                (0, "MAP.SendAuthenticationInfo", "sgsn3", "hlr", {}),
                (130, "MAP.UpdateGprsLocation", "sgsn3", "hlr", {}),
            ]
        elif gen == "4G":
            plan = [
                (0, "Diameter.AIR", "mme4", "hss4", {}),
                (130, "Diameter.ULR", "mme4", "hss4", {}),
                (260, "GTPv2-C.CreateSessionRequest", "mme4", "sgw4", {}),
            ]
        elif gen == "5G":
            plan = [
                (0, "Nnrf_NFDiscovery.Search", "amf5", "nrf5", {}),
                (130, "Nausf_UEAuthentication.Authenticate", "amf5", "ausf5", {}),
                (260, "Nudm_UECM.Registration", "amf5", "udm5", {}),
                (390, "Nsmf_PDUSession.CreateSMContext", "amf5", "smf5", {}),
            ]
        else:
            raise ValueError("Unknown generation: " + gen)
        for offset, operation, source, target, payload in plan:
            self.request(at + offset, operation, source, target, subject,
                         corr, gen, payload=payload)

    def _move(self, now: int, subject: str, new_gen: str) -> None:
        old_gen = self.registered.get(subject, "unknown")
        corr = "mobility-" + subject + "-" + str(now)
        # Semantic cross-RAT correlation only, NOT a fictitious MAP->SBI packet.
        self.events.append(Event(
            now, new_gen, "INTERWORKING", "InterRAT.ContextTransition",
            "iwf", "iwf", subject, corr, "OBSERVED", 0, ["iwf"],
            "3GPP TS 23.401 / TS 23.501 (procedure abstraction)", False,
            {"from": old_gen, "to": new_gen, "wire_message": False},
        ))
        self._attach(now + 30, subject, new_gen, corr)

    def _ims(self, now: int, subject: str, gen: str) -> None:
        corr = "ims-" + subject + "-" + str(now)
        self.request(now, "SIP.REGISTER", "pcscf", "scscf",
                     subject, corr + "-reg", gen)
        self.request(now + 150, "SIP.INVITE", "pcscf", "scscf",
                     subject, corr + "-call", gen)

    def _inject(self, now: int) -> None:
        self.request(now, "MAP.UpdateLocation", "external", "hlr",
                     "ue-0001", "attack-ss7", "2G", attack=True)
        self.request(now + 25, "Diameter.ULR", "external", "hss4",
                     "ue-0002", "attack-diameter", "4G", attack=True)
        self.request(now + 50, "Nnrf_NFManagement.NFRegister",
                     "external", "nrf5", "ue-0004", "attack-sbi", "5G",
                     attack=True, payload={
                         "nfInstanceId": "forged", "nfType": "AMF",
                         "nfStatus": "REGISTERED",
                     })
        for n in range(14):
            self.request(now + 100 + n * 12, "SIP.INVITE", "pcscf",
                         "scscf", "ue-0004", "attack-sip-" + str(n),
                         "5G", attack=True)

    def _sign(self, node: str, nonce: str, counts: dict[str, int]) -> str:
        # Simulation-only node-specific signature, not production PKI.
        return sign_cu_report(self._cu_key, node, nonce, counts)

    def _observer_votes(self, now: int, node: str, nonce: str,
                        expected: dict[str, int],
                        common: CommonFault | None = None,
                        ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Sample three monitoring domains with independent transport/faults.

        Only DRA is subject to explicitly configured malicious observer cases.
        Every other node has three normally independent laboratory witnesses.
        """
        votes: list[dict[str, Any]] = []
        common = common or CommonFault()
        # Align malicious observer behavior with the CU report compromise
        # window, allowing clean pre-attack evidence and a meaningful
        # collusion/concealment test.
        case = (self.scenario.observer_case
                if node == "dra" and now >= int(self.scenario.duration_s * 720)
                else "none")
        for observer, domain in OBSERVER_DOMAINS.items():
            delivered = self._observer_rng.random() >= self.scenario.observer_loss_rate
            if observer in common.offline:
                delivered = False
            if case in ("outage", "mixed") and observer == "tap-5gc":
                delivered = False
            if case == "outage" and observer == "tap-epc":
                delivered = False
            if not delivered:
                votes.append({
                    "observer": observer, "domain": domain,
                    "delivered": False,
                })
                continue
            # Each virtual sensor independently samples the same synthetic
            # transit event count; independent noise != independent hardware.
            counts = self._probes.observe(node, observer, now, expected)
            forged = ((case == "one_faulty" and observer == "tap-epc")
                      or (case == "two_colluding" and observer in
                          ("tap-epc", "tap-5gc"))
                      or (case == "mixed" and observer == "tap-epc")
                      or (case == "bad_mac" and observer == "tap-epc"))
            if forged or observer in common.fabricated:
                counts["fabricated"] = counts.get("fabricated", 0) + 5
            timestamp = now - 2000 if case == "stale" and observer == "tap-epc" else now
            # Intentional on-path corruption must NOT be re-signed.
            signed_counts = dict(expected) if case == "bad_mac" and observer == "tap-epc" else counts
            mac = sign_vote(self._observer_key, observer, node, nonce,
                            timestamp, signed_counts)
            votes.append({
                "observer": observer, "domain": domain, "node": node,
                "nonce": nonce, "at_ms": timestamp, "counts": counts,
                "mac": mac, "delivered": True,
            })
        decision = consensus_from_votes(
            votes, self._observer_key, node, nonce, now,
            max_count_delta=self.scenario.quorum_max_count_delta)
        return votes, decision

    def _poll(self, now: int) -> None:
        """Measure control-channel, signed CU and separately verified witnesses."""
        # Correlated fault is evaluated once for this epoch, then shared
        # across all target nodes regardless of iteration order.
        common = self._common_faults.at(now)
        for node in MONITORED_NODES:
            nonce = "cu-" + str(now)
            generation = self.net.nodes[node].generation
            actual = dict(self._node_counts[node])
            expected = dict(self._independent_counts[node])
            votes, quorum = self._observer_votes(now, node, nonce, expected,
                                                  common)
            # Request and response independently lost; never label missing
            # control telemetry as compromise merely from the timeout.
            delivered = all(
                self._cu_rng.random() >= self.scenario.loss_rate for _ in range(2))
            if not delivered:
                self._cu_loss_streak[node] += 1
                self.events.append(Event(
                    now, generation, "CU", "CU.Reconciliation",
                    node, "observer", "", nonce, "MISSING", 0, [node],
                    "Research control-unit method (not 3GPP wire protocol)",
                    False, {
                        "cu_delivered": False, "mac_valid": None,
                        "reported_total": None, "observed_total": None,
                        "observer_consistent": None,
                        "observer_votes": votes, "observer_quorum": quorum,
                        "transport_loss_observed": True,
                        "cu_consecutive_losses": self._cu_loss_streak[node],
                        "cu_staleness_ms": now - self._cu_last_success.get(node, 0),
                    },
                ))
                continue
            self._cu_loss_streak[node] = 0
            self._cu_last_success[node] = now
            reported = dict(actual)
            signature = self._sign(node, nonce, reported)
            if node in self._compromised:
                # Compromised CU signer can attest invented counters.
                reported["fabricated"] = reported.get("fabricated", 0) + 5
                signature = self._sign(node, nonce, reported)
            elif node in self._wire_tampered:
                # On-path alteration cannot produce a valid reporter MAC.
                reported["fabricated"] = reported.get("fabricated", 0) + 1
            valid_mac = hmac.compare_digest(
                signature, self._sign(node, nonce, reported))
            majority_counts = quorum["consensus_counts"] if quorum["quorum"] else None
            comparable = majority_counts is not None
            consistent = (count_distance(reported, majority_counts)
                          <= self.scenario.quorum_max_count_delta
                          if comparable else None)
            outcome = ("UNVERIFIED" if not comparable and valid_mac
                       else "MATCH" if valid_mac and consistent
                       else "MISMATCH")
            if valid_mac and consistent is False:
                self._alert(now, "cu_discrepancy", node,
                            "Authenticated report diverges from observer majority",
                            nonce, dedupe=True)
            if not valid_mac:
                self._alert(now, "cu_integrity", node,
                            "Control-unit MAC verification failed; no node attribution",
                            nonce, dedupe=True)
            self.events.append(Event(
                now, generation, "CU", "CU.Reconciliation",
                node, "observer", "", nonce, outcome, 0, [node],
                "Research control-unit method (not 3GPP wire protocol)",
                False, {
                    "cu_delivered": True, "reported_counts": reported,
                    "reported_total": sum(reported.values()),
                    "observed_total": sum(majority_counts.values())
                    if comparable else None,
                    "observer_consistent": consistent,
                    "counter_disagreement": sum(
                        abs(reported.get(op, 0) - majority_counts.get(op, 0))
                        for op in set(reported) | set(majority_counts))
                    if comparable else None,
                    "observer_votes": votes, "observer_quorum": quorum,
                    "mac_valid": valid_mac,
                    "report_signature": signature,
                    "transport_loss_observed": False,
                    "cu_consecutive_losses": 0, "cu_staleness_ms": 0,
                    "cu_processing_delay_ms": 5 if node in ("msc2", "sgsn3") else 2,
                },
            ))

    def _plan(self) -> None:
        generations = ("2G", "3G", "4G", "5G")
        for n in range(self.scenario.subscribers):
            subject = "ue-" + str(n + 1).zfill(4)
            gen = generations[n % 4]
            self._push(50 + n * 25, "attach",
                       (subject, gen, "initial-" + subject))
            destination = {"2G": "3G", "3G": "4G", "4G": "5G", "5G": "4G"}[gen]
            self._push(int(self.scenario.duration_s * 450) + n * 5,
                       "move", (subject, destination))
            if gen in ("4G", "5G"):
                self._push(int(self.scenario.duration_s * 280) + n * 9,
                           "ims", (subject, gen))
        # A real NRF API registration is represented as a logical message.
        self.request(80, "Nnrf_NFManagement.NFRegister", "amf5", "nrf5",
                     "nf-amf", "nf-register-amf", "5G", payload={
                         "nfInstanceId": "amf5-instance",
                         "nfType": "AMF", "nfStatus": "REGISTERED",
                     })
        for time_ms, profile, subject, corr in self._traffic.stream(
                self.scenario.duration_s, self.scenario.subscribers):
            self._push(time_ms, "background", (
                profile.operation, profile.source, profile.target,
                subject, corr, profile.generation))
        for time_ms in range(self.scenario.cu_interval_ms,
                             self.scenario.duration_s * 1000,
                             self.scenario.cu_interval_ms):
            self._push(time_ms, "poll", None)
        if self.scenario.inject_attacks:
            self._push(int(self.scenario.duration_s * 650), "inject", None)
        node_case = self.scenario.node_case
        if node_case == "auto":
            node_case = "both" if self.scenario.inject_attacks else "none"
        if node_case in ("report", "both"):
            self._push(int(self.scenario.duration_s * 720), "compromise", "dra")
        if node_case in ("tamper", "both"):
            self._push(int(self.scenario.duration_s * 740), "wire_tamper", "msc2")
        for node in self.scenario.report_fault_nodes:
            self._push(int(self.scenario.duration_s * 720), "compromise", node)

    def run(self) -> dict[str, Any]:
        if self._executed:
            raise RuntimeError("Each simulator instance can only be run once")
        self._executed = True
        self._plan()
        horizon = self.scenario.duration_s * 1000
        while self._queue:
            now, _, kind, item = heapq.heappop(self._queue)
            if now > horizon:
                break
            if kind == "hop":
                self._on_hop(now, *item)
            elif kind == "background":
                operation, source, target, subject, corr, generation = item
                self.request(now, operation, source, target,
                             subject, corr, generation)
            elif kind == "attach":
                self._attach(now, *item)
            elif kind == "move":
                self._move(now, *item)
            elif kind == "ims":
                self._ims(now, *item)
            elif kind == "poll":
                self._poll(now)
                for tx in self._procedures.expire(now):
                    self._alert(now, "transaction_timeout", tx.source,
                                tx.operation + ": no matching reply before timeout",
                                tx.correlation_id)
            elif kind == "inject":
                self._inject(now)
            elif kind == "compromise":
                self._compromised.add(item)
            elif kind == "wire_tamper":
                self._wire_tampered.add(item)

        for corr in sorted(self._completed_invites - self._acked_invites):
            self._alert(horizon, "sip_ack_deficit", "pcscf",
                        "2xx INVITE observed, matching ACK not delivered", corr)
        counts = Counter(
            e.outcome for e in self.events
            if e.protocol not in ("CU", "INTERWORKING")
        )
        by_protocol = Counter(
            e.protocol for e in self.events
            if e.protocol not in ("CU", "INTERWORKING")
        )
        by_generation = Counter(
            e.generation for e in self.events
            if e.protocol not in ("CU", "INTERWORKING")
        )
        node_evidence = inspect_cu_events(
            [asdict(e) for e in self.events],
            observer_root_key=self._observer_key,
            cu_root_key=self._cu_key,
            max_count_delta=self.scenario.quorum_max_count_delta,
        )
        domain_evidence = analyze_domain_correlations(
            [asdict(e) for e in self.events], self._observer_key,
            max_count_delta=self.scenario.quorum_max_count_delta)
        zonal_evidence = zonal_features(
            [asdict(e) for e in self.events],
            observer_root_key=self._observer_key, cu_root_key=self._cu_key,
            max_count_delta=self.scenario.quorum_max_count_delta)
        cu_total = sum(e.protocol == "CU" for e in self.events)
        cu_delivered = sum(e.protocol == "CU" and
                           e.detail.get("cu_delivered", True)
                           for e in self.events)
        scenario_snapshot = asdict(self.scenario)
        # Public result JSON must survive an exact dumps/loads roundtrip.
        # dataclasses.asdict preserves tuples, whereas JSON represents arrays.
        scenario_snapshot["report_fault_nodes"] = list(self.scenario.report_fault_nodes)
        return {
            "scenario": scenario_snapshot,
            "summary": {
                "total_messages": sum(counts.values()),
                "delivered": counts["DELIVERED"],
                "lost": counts["LOST"],
                "congested": counts["CONGESTED"],
                "rejected": counts["REJECTED"],
                "no_route": counts["NO_ROUTE"],
                "alerts": len(self.alerts),
                "registrations": len(self.registered),
                "inter_rat_transitions": sum(
                    e.operation == "InterRAT.ContextTransition"
                    for e in self.events
                ),
                "by_protocol": dict(sorted(by_protocol.items())),
                "by_generation": dict(sorted(by_generation.items())),
                "traffic_generated": dict(sorted(self._traffic.generated.items())),
                "max_queue_delay_ms": self._max_queue_delay_ms,
                "queue_drops": self._queue_drops,
                "transactions": self._procedures.snapshot(),
                "cu_observations": cu_total,
                "cu_delivered": cu_delivered,
                "cu_delivery_ratio": cu_delivered / cu_total if cu_total else None,
                "domain_correlation": domain_evidence["summary"],
                "zonal_feature_coverage": zonal_evidence["summary"],
                "node_evidence_classes": dict(sorted(Counter(
                    row["classification"] for row in node_evidence["nodes"]
                ).items())),
            },
            "registered": dict(sorted(self.registered.items())),
            "nodes": [asdict(n) for n in self.net.nodes.values()],
            "links": [asdict(link) for link in self.net.links],
            "events": [asdict(e) for e in self.events],
            "observations": aggregate([asdict(e) for e in self.events]),
            "alerts": [asdict(a) for a in self.alerts],
            "node_evidence": node_evidence,
            "domain_evidence": domain_evidence,
            "zonal_evidence": zonal_evidence,
            "standards": {
                op: {"protocol": rule.protocol, "reference": rule.reference}
                for op, rule in RULES.items()
            },
        }
