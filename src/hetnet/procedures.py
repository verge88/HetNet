"""Logical transaction and subscriber-state invariants.

These guards model an intentionally small *subset* of 3GPP/IETF procedure
semantics. They do not replace full MAP, SIP, Diameter or SBI protocol FSMs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple


# Successful prerequisite requests, within the same attach/mobility correlation.
PREREQUISITES: dict[str, str] = {
    "MAP.UpdateLocation": "MAP.SendAuthenticationInfo",
    "MAP.UpdateGprsLocation": "MAP.SendAuthenticationInfo",
    "Diameter.ULR": "Diameter.AIR",
    "GTPv2-C.CreateSessionRequest": "Diameter.ULR",
    "Nudm_UECM.Registration": "Nausf_UEAuthentication.Authenticate",
    "Nsmf_PDUSession.CreateSMContext": "Nudm_UECM.Registration",
}
PROVISIONAL = frozenset({"SIP.100_TRYING", "SIP.180_RINGING"})


@dataclass
class Transaction:
    operation: str
    response: str
    source: str
    target: str
    subject: str
    correlation_id: str
    started_ms: int
    expires_ms: int


class Decision(NamedTuple):
    accepted: bool
    category: str = ""
    reason: str = ""
    completed: str | None = None


class ProcedureLedger:
    """Check operation order, matched responses, retransmissions and SIP dialogs.

    The ledger sees only *delivered* messages. State changes occur on matched
    successful replies, not on outgoing requests. Routing and loss are external.
    """

    def __init__(self, timeout_ms: int = 2000) -> None:
        self.timeout_ms = timeout_ms
        self.pending: list[Transaction] = []
        self.completed: dict[tuple[str, str], set[str]] = {}
        self.ims_registered: set[str] = set()
        self.sip_acked: set[str] = set()
        self.failed_timeouts: list[Transaction] = []
        self.accepted_responses = 0
        self.rejected_invariants = 0

    def inspect_request(self, now: int, operation: str, response: str | None,
                        source: str, target: str, subject: str,
                        correlation_id: str) -> Decision:
        steps = self.completed.get((correlation_id, subject), set())
        prerequisite = PREREQUISITES.get(operation)
        if prerequisite and prerequisite not in steps:
            self.rejected_invariants += 1
            return Decision(False, "procedure_order",
                            operation + " requires completed " + prerequisite)
        if operation == "SIP.INVITE" and subject not in self.ims_registered:
            self.rejected_invariants += 1
            return Decision(False, "sip_registration",
                            "INVITE requires successful preceding IMS REGISTER")
        if operation == "SIP.BYE" and correlation_id not in self.sip_acked:
            self.rejected_invariants += 1
            return Decision(False, "sip_dialog_state", "BYE requires accepted ACK")
        if operation == "SIP.ACK":
            # An ACK for a successful INVITE must be correlated with that
            # very dialog; a fabricated ACK must not authorize a later BYE.
            if "SIP.INVITE" not in steps or correlation_id in self.sip_acked:
                self.rejected_invariants += 1
                return Decision(False, "sip_dialog_state",
                                "ACK requires matched 2xx INVITE and must be unique")
            self.sip_acked.add(correlation_id)
        if response:
            if any(tx.correlation_id == correlation_id
                   and tx.operation == operation for tx in self.pending):
                self.rejected_invariants += 1
                return Decision(False, "duplicate_transaction",
                                "Request with same operation/correlation still open")
            self.pending.append(Transaction(
                operation, response, source, target, subject,
                correlation_id, now, now + self.timeout_ms,
            ))
        return Decision(True)

    def inspect_response(self, now: int, operation: str, source: str, target: str,
                         subject: str, correlation_id: str) -> Decision:
        for i, tx in enumerate(self.pending):
            if (tx.correlation_id == correlation_id and tx.subject == subject
                    and tx.source == target and tx.target == source
                    and (tx.response == operation
                         or operation in PROVISIONAL
                         and tx.operation == "SIP.INVITE")):
                if now > tx.expires_ms:
                    self.pending.pop(i)
                    self.rejected_invariants += 1
                    return Decision(False, "late_response", "Response after transaction deadline")
                if operation in PROVISIONAL:
                    return Decision(True)
                self.pending.pop(i)
                self.completed.setdefault((correlation_id, subject), set()).add(tx.operation)
                if tx.operation == "SIP.REGISTER":
                    self.ims_registered.add(subject)
                self.accepted_responses += 1
                return Decision(True, completed=tx.operation)
        self.rejected_invariants += 1
        return Decision(False, "unmatched_response",
                        "Response without matching delivered request")

    def expire(self, now: int) -> list[Transaction]:
        expired = [tx for tx in self.pending if now > tx.expires_ms]
        if expired:
            self.pending = [tx for tx in self.pending if now <= tx.expires_ms]
            self.failed_timeouts.extend(expired)
        return expired

    def snapshot(self) -> dict[str, int]:
        return {
            "pending": len(self.pending),
            "completed_responses": self.accepted_responses,
            "rejected_invariants": self.rejected_invariants,
            "timeouts": len(self.failed_timeouts),
            "ims_registered_subjects": len(self.ims_registered),
        }
