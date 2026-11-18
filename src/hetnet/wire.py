"""Bounded offline validators for signaling envelopes, not production codecs."""
from __future__ import annotations
import re
import hashlib
from typing import Any

MAX_INPUT = 1_048_576
MAX_FIELDS = 4096
_SIP_NAME = re.compile(rb"^[A-Za-z0-9.!%*_+'~-]+$")
_SIP_METHOD = re.compile(rb"^[A-Z][A-Z0-9_.-]*$")


class DecodeError(ValueError):
    """Malformed data or unsupported strict subset."""


def _bounded(data: bytes, minimum: int) -> None:
    if not isinstance(data, bytes):
        raise DecodeError("Input must be bytes")
    if len(data) > MAX_INPUT:
        raise DecodeError("Input exceeds 1 MiB")
    if len(data) < minimum:
        raise DecodeError("Truncated message")


def _u24(data: bytes) -> int:
    return int.from_bytes(data, "big")


def parse_diameter(data: bytes) -> dict[str, Any]:
    """RFC 6733 §§3,4.1: header, flat AVP boundaries, no AVP values."""
    _bounded(data, 20)
    if data[0] != 1:
        raise DecodeError("Diameter version must be 1")
    length = _u24(data[1:4])
    if length != len(data) or length % 4 or length < 20:
        raise DecodeError("Diameter length mismatch or non-4-byte alignment")
    flags = data[4]
    avps = []
    pos = 20
    while pos < length:
        if len(avps) >= MAX_FIELDS:
            raise DecodeError("Too many AVPs")
        if pos + 8 > length:
            raise DecodeError("Truncated AVP header")
        code = int.from_bytes(data[pos:pos + 4], "big")
        avp_flags = data[pos + 4]
        avp_length = _u24(data[pos + 5:pos + 8])
        vendor = bool(avp_flags & 0x80)
        header_size = 12 if vendor else 8
        if avp_length < header_size:
            raise DecodeError("Invalid AVP length")
        padded = (avp_length + 3) & ~3
        if pos + padded > length:
            raise DecodeError("AVP overruns Diameter message")
        vendor_id = (int.from_bytes(data[pos + 8:pos + 12], "big")
                     if vendor else None)
        if any(data[pos + avp_length:pos + padded]):
            raise DecodeError("Nonzero AVP padding")
        avps.append({
            "code": code, "flags": avp_flags, "vendor_id": vendor_id,
            "data_length": avp_length - header_size,
        })
        pos += padded
    return {
        "protocol": "diameter", "version": 1, "length": length,
        "command_flags": flags, "request": bool(flags & 0x80),
        "command_code": _u24(data[5:8]),
        "application_id": int.from_bytes(data[8:12], "big"),
        "hop_by_hop": int.from_bytes(data[12:16], "big"),
        "end_to_end": int.from_bytes(data[16:20], "big"),
        "avps": avps, "reference": "RFC 6733 §§3,4.1",
    }


def parse_gtpv2(data: bytes) -> dict[str, Any]:
    """3GPP TS 29.274 §5: one GTPv2-C message and flat IEs, no piggyback."""
    _bounded(data, 8)
    flags = data[0]
    version = (flags >> 5) & 7
    if version != 2:
        raise DecodeError("GTPv2-C version must be 2")
    if flags & 0x10:
        raise DecodeError("GTPv2-C piggyback not supported")
    has_teid = bool(flags & 0x08)
    header_size = 12 if has_teid else 8
    length = int.from_bytes(data[2:4], "big")
    if len(data) != length + 4 or len(data) < header_size:
        raise DecodeError("Invalid GTPv2-C length")
    teid = int.from_bytes(data[4:8], "big") if has_teid else None
    start = 8 if has_teid else 4
    sequence = _u24(data[start:start + 3])
    ies = []
    pos = header_size
    while pos < len(data):
        if len(ies) >= MAX_FIELDS:
            raise DecodeError("Too many IEs")
        if pos + 4 > len(data):
            raise DecodeError("Truncated IE header")
        ie_length = int.from_bytes(data[pos + 1:pos + 3], "big")
        end = pos + 4 + ie_length
        if end > len(data):
            raise DecodeError("IE overruns GTPv2-C message")
        ies.append({
            "type": data[pos], "length": ie_length,
            "instance": data[pos + 3] & 0x0f,
        })
        pos = end
    return {
        "protocol": "gtpv2c", "version": 2, "type": data[1],
        "length": len(data), "teid_present": has_teid, "teid": teid,
        "sequence": sequence, "ies": ies, "reference": "3GPP TS 29.274 §5",
    }


def parse_sip(data: bytes) -> dict[str, Any]:
    """RFC 3261 SIP subset: CRLF lines, CSeq and body length, no obs-fold."""
    _bounded(data, 12)
    if b"\r\n\r\n" not in data:
        raise DecodeError("SIP CRLF header terminator missing")
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if len(lines) > 512:
        raise DecodeError("Too many SIP headers")
    try:
        start = lines[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise DecodeError("Invalid SIP start line") from error
    response = start.startswith("SIP/2.0 ")
    if response:
        parts = start.split(" ", 2)
        if (len(parts) < 3 or not parts[1].isdigit()
                or not 100 <= int(parts[1]) <= 699):
            raise DecodeError("Invalid SIP status")
        method = None
        status = int(parts[1])
    else:
        parts = start.split(" ")
        if (len(parts) != 3 or parts[2] != "SIP/2.0"
                or not _SIP_METHOD.fullmatch(parts[0].encode("ascii"))
                or not parts[1].startswith(("sip:", "sips:"))):
            raise DecodeError("Invalid SIP request line")
        method, status = parts[0], None
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise DecodeError("Invalid or folded SIP header")
        name, value = line.split(b":", 1)
        if not _SIP_NAME.fullmatch(name):
            raise DecodeError("Invalid SIP header name")
        headers.setdefault(name.decode("ascii").lower(), []).append(
            value.strip().decode("latin-1"))
    for key in ("via", "to", "from", "call-id", "cseq", "content-length"):
        if not headers.get(key):
            raise DecodeError("Missing SIP header " + key)
        if key != "via" and len(headers[key]) != 1:
            raise DecodeError("Duplicate SIP singleton " + key)
    cseq = headers["cseq"][0].split()
    if (len(cseq) != 2 or not cseq[0].isdigit()
            or not cseq[1].isupper()):
        raise DecodeError("Invalid SIP CSeq")
    if method and cseq[1] != method:
        raise DecodeError("SIP request CSeq mismatch")
    claimed = headers["content-length"][0]
    if not claimed.isascii() or not claimed.isdecimal():
        raise DecodeError("Invalid SIP Content-Length")
    if int(claimed) != len(body):
        raise DecodeError("SIP body length mismatch")
    return {
        "protocol": "sip", "method": method, "status": status,
        "call_id_sha256": hashlib.sha256(
            headers["call-id"][0].encode("latin-1")).hexdigest(),
        "cseq": int(cseq[0]),
        "cseq_method": cseq[1], "via_count": len(headers["via"]),
        "body_length": len(body), "reference": "RFC 3261 §§7,8,20",
    }


def parse_http2_frame(data: bytes) -> dict[str, Any]:
    """RFC 9113 §4.1: frame envelope only, without HPACK or connection state."""
    _bounded(data, 9)
    length = _u24(data[:3])
    if length > 16_384:
        raise DecodeError("HTTP/2 payload exceeds default MAX_FRAME_SIZE")
    if len(data) != 9 + length:
        raise DecodeError("HTTP/2 frame length mismatch")
    frame_type, flags = data[3], data[4]
    stream_id = int.from_bytes(data[5:9], "big") & 0x7fffffff
    if frame_type in (0, 1, 2, 3, 9) and stream_id == 0:
        raise DecodeError("HTTP/2 stream-specific frame on stream 0")
    if frame_type in (4, 6, 7) and stream_id != 0:
        raise DecodeError("HTTP/2 connection frame on nonzero stream")
    if frame_type == 4 and (
        (flags & 1 and length != 0)
        or (not flags & 1 and length % 6)
    ):
        raise DecodeError("Invalid HTTP/2 SETTINGS size")
    if frame_type == 6 and length != 8:
        raise DecodeError("HTTP/2 PING requires eight bytes")
    if frame_type == 8 and length != 4:
        raise DecodeError("HTTP/2 WINDOW_UPDATE requires four bytes")
    return {
        "protocol": "http2-frame", "length": length, "frame_type": frame_type,
        "flags": flags, "stream_id": stream_id, "reference": "RFC 9113 §4.1",
    }


PARSERS = {
    "sip": parse_sip, "diameter": parse_diameter,
    "gtpv2c": parse_gtpv2, "http2": parse_http2_frame,
}


def inspect_wire(protocol: str, data: bytes) -> dict[str, Any]:
    try:
        return PARSERS[protocol](data)
    except KeyError as e:
        raise DecodeError("Unsupported protocol") from e
