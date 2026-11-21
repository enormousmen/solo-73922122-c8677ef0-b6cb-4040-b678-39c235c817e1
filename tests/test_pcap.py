"""Tests for the offline PCAP DNS fragment check (POST /pcap/dns-response-check).

Packet crafting is done by hand (no third-party libs): classic PCAP global
header + Ethernet/IPv4/UDP frames, with a tiny DNS message builder.
"""

from __future__ import annotations

import itertools
import pathlib
import struct

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pcap import MAX_PCAP_BYTES, DnsParseError, parse_dns, parse_pcap

client = TestClient(app)

SAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "pcap"

CLIENT_IP = "192.0.2.10"
CLIENT_PORT = 53210
SERVER_IP = "198.51.100.53"
SERVER_PORT = 53
QNAME = "www.example.com"


# --------------------------------------------------------------------------- #
# Crafting helpers
# --------------------------------------------------------------------------- #


def ip_b(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


def ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def ip_packet(
    src: str,
    dst: str,
    ident: int,
    mf: bool,
    offset_units: int,
    payload: bytes,
    proto: int = 17,
) -> bytes:
    flags_frag = (0x2000 if mf else 0) | offset_units
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        flags_frag,
        64,
        proto,
        0,
        ip_b(src),
        ip_b(dst),
    )
    header = header[:10] + struct.pack("!H", ip_checksum(header)) + header[12:]
    return header + payload


def eth(payload: bytes, eth_type: int = 0x0800, vlan: bool = False) -> bytes:
    macs = b"\x02\x00\x00\x00\x00\x35" + b"\x02\x00\x00\x00\x00\x0a"
    if vlan:
        return macs + b"\x81\x00\x00\x64" + struct.pack("!H", eth_type) + payload
    return macs + struct.pack("!H", eth_type) + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def enc_name(name: str) -> bytes:
    return b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")
    ) + b"\x00"


def dns_query(txid: int, name: str = QNAME, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + enc_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str = QNAME, rcode: int = 0, answers: tuple[str, ...] = ()) -> bytes:
    records = b"".join(
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_b(a) for a in answers
    )
    return (
        struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
        + enc_name(name)
        + struct.pack("!HH", 1, 1)
        + records
    )


def query_pkt(txid: int, name: str = QNAME, qtype: int = 1, **kw) -> bytes:
    return eth(ip_packet(CLIENT_IP, SERVER_IP, 0x1000, False, 0, udp(CLIENT_PORT, SERVER_PORT, dns_query(txid, name, qtype))), **kw)


def response_datagram(txid: int, name: str = QNAME, rcode: int = 0, answers: tuple[str, ...] = ()) -> bytes:
    return udp(SERVER_PORT, CLIENT_PORT, dns_response(txid, name, rcode, answers))


def fragment_frames(datagram: bytes, ident: int, size: int) -> list[bytes]:
    frames = []
    offset = 0
    while offset < len(datagram):
        chunk = datagram[offset : offset + size]
        mf = offset + len(chunk) < len(datagram)
        frames.append(eth(ip_packet(SERVER_IP, CLIENT_IP, ident, mf, offset // 8, chunk)))
        offset += len(chunk)
    return frames


def pcap(frames: list[bytes], endian: str = "<", linktype: int = 1, orig_lens: list[int] | None = None) -> bytes:
    magic = 0xA1B2C3D4
    out = [struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)]
    for i, frame in enumerate(frames):
        orig = orig_lens[i] if orig_lens else len(frame)
        out.append(struct.pack(endian + "IIII", 1_700_000_000 + i, i, len(frame), orig))
        out.append(frame)
    return b"".join(out)


def check(blob: bytes, query_frame: int = 1, cutoff_frame: int | None = None) -> dict:
    """POST the capture to the API and return the parsed 200 response."""
    if cutoff_frame is None:
        cutoff_frame = len(parse_pcap(blob))
    resp = client.post(
        "/pcap/dns-response-check",
        files={"file": ("capture.pcap", blob)},
        data={"query_frame": str(query_frame), "cutoff_frame": str(cutoff_frame)},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def check_raw(blob: bytes, query_frame: int, cutoff_frame: int):
    """POST and return the raw response (for error-status assertions)."""
    return client.post(
        "/pcap/dns-response-check",
        files={"file": ("capture.pcap", blob)},
        data={"query_frame": str(query_frame), "cutoff_frame": str(cutoff_frame)},
    )


# --------------------------------------------------------------------------- #
# File-level parsing / validation
# --------------------------------------------------------------------------- #


def test_bad_magic_rejected() -> None:
    resp = check_raw(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, 1, 2)
    assert resp.status_code == 422
    assert "经典 PCAP" in resp.json()["detail"]


def test_too_small_file_rejected() -> None:
    assert check_raw(b"\xd4\xc3\xb2\xa1", 1, 2).status_code == 422


def test_non_ethernet_linktype_rejected() -> None:
    blob = pcap([], linktype=101)
    resp = check_raw(blob, 1, 2)
    assert resp.status_code == 422
    assert "LINKTYPE=101" in resp.json()["detail"]


def test_truncated_record_header_rejected() -> None:
    blob = pcap([query_pkt(0x1111)]) + b"\x00\x01"  # dangling partial record header
    assert check_raw(blob, 1, 2).status_code == 422


def test_truncated_packet_data_rejected() -> None:
    good = pcap([query_pkt(0x1111)])
    blob = good[:-10]  # cut inside the packet data
    assert check_raw(blob, 1, 2).status_code == 422


def test_empty_capture_rejected() -> None:
    resp = check_raw(pcap([]), 1, 1)
    assert resp.status_code == 422
    assert "不含任何帧" in resp.json()["detail"]


def test_big_endian_pcap_accepted() -> None:
    blob = pcap([query_pkt(0x1111), eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(0x1111, answers=("203.0.113.5",))))], endian=">")
    out = check(blob)
    assert out["verdict"] == "answered"
    assert out["response"]["rcode_name"] == "NOERROR"


def test_oversize_upload_rejected() -> None:
    blob = b"\x00" * (MAX_PCAP_BYTES + 1)
    resp = check_raw(blob, 1, 2)
    assert resp.status_code == 413
    assert "5 MiB" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# Frame-number window and query-frame validation
# --------------------------------------------------------------------------- #


def _simple_capture(txid: int = 0x1111) -> bytes:
    return pcap(
        [
            query_pkt(txid),
            eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(txid))),
        ]
    )


def test_query_frame_out_of_range() -> None:
    resp = check_raw(_simple_capture(), 3, 3)
    assert resp.status_code == 422
    assert "超出范围" in resp.json()["detail"]


def test_cutoff_frame_out_of_range() -> None:
    resp = check_raw(_simple_capture(), 1, 99)
    assert resp.status_code == 422
    assert "超出范围" in resp.json()["detail"]


def test_cutoff_must_follow_query() -> None:
    assert check_raw(_simple_capture(), 2, 2).status_code == 422
    assert check_raw(_simple_capture(), 2, 1).status_code == 422


def test_frame_numbers_must_be_positive() -> None:
    assert check_raw(_simple_capture(), 0, 2).status_code == 422
    assert check_raw(_simple_capture(), 1, 0).status_code == 422


def test_query_frame_must_be_a_query() -> None:
    blob = pcap(
        [
            eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(0x1111))),
            query_pkt(0x1111),
        ]
    )
    resp = check_raw(blob, 1, 2)
    assert resp.status_code == 422
    assert "QR=1" in resp.json()["detail"]


def test_query_frame_must_be_dns() -> None:
    blob = pcap(
        [
            eth(ip_packet(CLIENT_IP, SERVER_IP, 0x1000, False, 0, udp(CLIENT_PORT, SERVER_PORT, b"\x00" * 40))),
            query_pkt(0x1111),
        ]
    )
    assert check_raw(blob, 1, 2).status_code == 422


def test_query_frame_must_be_a_type_query() -> None:
    blob = pcap([query_pkt(0x1111, qtype=28), query_pkt(0x1111)])  # AAAA then A
    resp = check_raw(blob, 1, 2)
    assert resp.status_code == 422
    assert "AAAA" in resp.json()["detail"]


def test_query_frame_must_not_be_fragmented() -> None:
    payload = udp(CLIENT_PORT, SERVER_PORT, dns_query(0x1111))
    blob = pcap(
        [
            eth(ip_packet(CLIENT_IP, SERVER_IP, 0x1000, True, 0, payload[:32])),
            query_pkt(0x1111),
        ]
    )
    resp = check_raw(blob, 1, 2)
    assert resp.status_code == 422
    assert "分片" in resp.json()["detail"]


def test_query_frame_must_be_udp() -> None:
    blob = pcap(
        [
            eth(ip_packet(CLIENT_IP, SERVER_IP, 0x1000, False, 0, b"\x00" * 20, proto=6)),
            query_pkt(0x1111),
        ]
    )
    assert check_raw(blob, 1, 2).status_code == 422


def test_query_frame_must_be_ipv4() -> None:
    blob = pcap([eth(b"\x00" * 46, eth_type=0x0806), query_pkt(0x1111)])  # ARP
    assert check_raw(blob, 1, 2).status_code == 422


def test_window_excludes_frames_outside() -> None:
    txid = 0x1111
    response = eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(txid)))
    # response sits after the cutoff frame -> not scanned
    blob = pcap([query_pkt(txid), query_pkt(0x2222), response])
    out = check(blob, 1, 2)
    assert out["verdict"] == "no_response"
    # cutoff includes the response -> answered
    out = check(blob, 1, 3)
    assert out["verdict"] == "answered"


def test_vlan_tagged_frames_work() -> None:
    txid = 0x1111
    blob = pcap(
        [
            query_pkt(txid, vlan=True),
            eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(txid)), vlan=True),
        ]
    )
    assert check(blob)["verdict"] == "answered"


# --------------------------------------------------------------------------- #
# Bundled samples: one per verdict
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,verdict",
    [
        ("01-complete-unfragmented.pcap", "answered"),
        ("02-complete-fragments-out-of-order.pcap", "answered"),
        ("03-missing-fragment.pcap", "missing_fragments"),
        ("04-only-non-first-fragments.pcap", "unattributable"),
        ("05-conflicting-first-fragments.pcap", "unattributable"),
        ("06-no-response.pcap", "no_response"),
        ("07-question-mismatch.pcap", "question_mismatch"),
        ("08-nxdomain.pcap", "answered"),
    ],
)
def test_sample_verdicts(name: str, verdict: str) -> None:
    blob = (SAMPLES / name).read_bytes()
    out = check(blob, 1, len(parse_pcap(blob)))
    assert out["verdict"] == verdict
    assert out["query"]["frame"] == 1


def test_sample_answered_details() -> None:
    blob = (SAMPLES / "01-complete-unfragmented.pcap").read_bytes()
    out = check(blob, 1, 2)
    resp = out["response"]
    assert resp["frames"] == [2]
    assert resp["rcode"] == 0
    assert resp["rcode_name"] == "NOERROR"
    assert resp["question_match"] is True
    assert resp["answers_a"] == ["203.0.113.10", "203.0.113.11"]
    assert out["query"]["txid_hex"] == "0x1a2b"


def test_sample_missing_details() -> None:
    blob = (SAMPLES / "03-missing-fragment.pcap").read_bytes()
    out = check(blob, 1, 3)
    (group,) = out["missing"]
    assert group["frames"] == [2, 3]
    assert group["missing_ranges"] == [{"offset": 48, "length": 48}]
    assert group["received_ranges"] == [
        {"offset": 0, "length": 48},
        {"offset": 96, "length": 9},
    ]
    assert group["udp_length"] == 105
    assert group["last_fragment_seen"] is True
    assert out.get("response") is None  # no complete response in this verdict


def test_sample_unattributable_details() -> None:
    blob = (SAMPLES / "05-conflicting-first-fragments.pcap").read_bytes()
    out = check(blob, 1, 5)
    (group,) = out["unattributable"]
    assert group["reason"] == "conflicting_first_fragments"
    assert group["conflicting_first_frames"] == [2, 3]
    assert group["frames"] == [2, 3, 4, 5]


def test_sample_nxdomain_rcode() -> None:
    blob = (SAMPLES / "08-nxdomain.pcap").read_bytes()
    out = check(blob, 1, 2)
    assert out["response"]["rcode"] == 3
    assert out["response"]["rcode_name"] == "NXDOMAIN"
    assert out["response"]["answers_a"] == []


# --------------------------------------------------------------------------- #
# Reassembly semantics
# --------------------------------------------------------------------------- #

FRAG_TXID = 0xBEEF
FRAG_IDENT = 0x3000
FRAG_ANSWERS = ("203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13")


def _frag_parts() -> list[bytes]:
    return fragment_frames(response_datagram(FRAG_TXID, answers=FRAG_ANSWERS), FRAG_IDENT, 48)


def test_fragment_order_and_duplicates_do_not_change_verdict() -> None:
    parts = _frag_parts()
    assert len(parts) == 3
    baseline = check(pcap([query_pkt(FRAG_TXID)] + parts))
    assert baseline["verdict"] == "answered"
    for perm in itertools.permutations(parts):
        blob = pcap([query_pkt(FRAG_TXID), *perm])
        out = check(blob)
        assert out["verdict"] == "answered", perm
        assert out["response"]["rcode"] == baseline["response"]["rcode"]
        assert out["response"]["answers_a"] == baseline["response"]["answers_a"]
    # duplicates anywhere must not change anything either
    blob = pcap([query_pkt(FRAG_TXID), parts[1], parts[1], parts[0], parts[2], parts[0]])
    out = check(blob)
    assert out["verdict"] == "answered"
    assert out["response"]["answers_a"] == baseline["response"]["answers_a"]


def test_fragment_order_does_not_change_missing_ranges() -> None:
    parts = _frag_parts()
    subset = [parts[0], parts[2]]  # middle fragment absent
    expected = [{"offset": 48, "length": 48}]
    for perm in itertools.permutations(subset):
        out = check(pcap([query_pkt(FRAG_TXID), *perm]))
        assert out["verdict"] == "missing_fragments"
        assert out["missing"][0]["missing_ranges"] == expected
    # and with a duplicate of a received fragment
    out = check(pcap([query_pkt(FRAG_TXID), parts[2], parts[0], parts[2]]))
    assert out["missing"][0]["missing_ranges"] == expected


def test_missing_tail_and_multiple_gaps() -> None:
    datagram = response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)
    udp_len = len(datagram)
    parts = fragment_frames(datagram, FRAG_IDENT, 32)
    assert len(parts) >= 4
    # keep first and third fragments only: gap in the middle AND tail missing
    blob = pcap([query_pkt(FRAG_TXID), parts[0], parts[2]])
    out = check(blob)
    (group,) = out["missing"]
    assert group["missing_ranges"] == [
        {"offset": 32, "length": 32},
        {"offset": 96, "length": udp_len - 96},
    ]
    assert group["last_fragment_seen"] is False
    assert group["udp_length"] == udp_len


def test_ip_identification_separates_groups() -> None:
    datagram = response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)
    parts_a = fragment_frames(datagram, 0x1111, 48)
    stray = fragment_frames(datagram, 0x2222, 48)[1]  # non-first frag, other ident
    blob = pcap([query_pkt(FRAG_TXID), parts_a[0], stray, parts_a[1], parts_a[2]])
    out = check(blob)
    assert out["verdict"] == "answered"
    assert out["response"]["identification"] == 0x1111
    # the stray fragment forms its own unattributable group
    (other,) = out["unattributable"]
    assert other["identification"] == 0x2222
    assert other["reason"] == "only_non_first_fragments"


def test_retransmitted_response_two_groups() -> None:
    datagram = response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)
    parts_a = fragment_frames(datagram, 0x1111, 48)
    parts_b = fragment_frames(datagram, 0x2222, 48)
    # group A completes, group B only has its first fragment
    blob = pcap([query_pkt(FRAG_TXID), parts_a[0], parts_b[0], parts_a[1], parts_a[2]])
    out = check(blob)
    assert out["verdict"] == "answered"
    assert out["response"]["identification"] == 0x1111
    (incomplete,) = out["missing"]
    assert incomplete["identification"] == 0x2222
    assert incomplete["missing_ranges"] == [
        {"offset": 48, "length": incomplete["udp_length"] - 48}
    ]


def test_conflicting_first_fragments_unattributable() -> None:
    good = fragment_frames(response_datagram(FRAG_TXID, answers=FRAG_ANSWERS), FRAG_IDENT, 48)
    other = fragment_frames(response_datagram(0x9999, answers=FRAG_ANSWERS), FRAG_IDENT, 48)
    blob = pcap([query_pkt(FRAG_TXID), good[0], other[0], good[1], good[2]])
    out = check(blob)
    assert out["verdict"] == "unattributable"
    (group,) = out["unattributable"]
    assert group["reason"] == "conflicting_first_fragments"
    assert group["conflicting_first_frames"] == [2, 3]


def test_identical_first_fragment_retransmit_is_not_a_conflict() -> None:
    parts = _frag_parts()
    blob = pcap([query_pkt(FRAG_TXID), parts[0], parts[0], parts[1], parts[2]])
    assert check(blob)["verdict"] == "answered"


def test_only_non_first_fragments_unattributable() -> None:
    parts = _frag_parts()
    blob = pcap([query_pkt(FRAG_TXID), parts[1], parts[2]])
    out = check(blob)
    assert out["verdict"] == "unattributable"
    (group,) = out["unattributable"]
    assert group["reason"] == "only_non_first_fragments"
    assert group["frames"] == [2, 3]


def test_first_fragment_without_txid_unverifiable() -> None:
    datagram = response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)
    # pathological: first fragment carries only the UDP header (8 bytes)
    first = eth(ip_packet(SERVER_IP, CLIENT_IP, FRAG_IDENT, True, 0, datagram[:8]))
    rest = eth(ip_packet(SERVER_IP, CLIENT_IP, FRAG_IDENT, False, 1, datagram[8:]))
    blob = pcap([query_pkt(FRAG_TXID), first, rest])
    out = check(blob)
    assert out["verdict"] == "unattributable"
    assert out["unattributable"][0]["reason"] == "first_fragment_unverifiable"


def test_other_transaction_and_ports_ignored() -> None:
    # same hosts, matching ports, but a different transaction id
    wrong_txid = eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(0x9999)))
    # same hosts, but a different port pair
    wrong_ports = eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2001, False, 0, udp(53, 12345, dns_response(FRAG_TXID))))
    blob = pcap([query_pkt(FRAG_TXID), wrong_txid, wrong_ports])
    out = check(blob)
    assert out["verdict"] == "no_response"
    assert out["unattributable"] == []


def test_same_direction_traffic_ignored() -> None:
    blob = pcap([query_pkt(FRAG_TXID), query_pkt(0x2222)])  # a second *query*
    assert check(blob)["verdict"] == "no_response"


def test_question_mismatch_withhelds_rcode() -> None:
    blob = pcap(
        [
            query_pkt(FRAG_TXID),
            eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(FRAG_TXID, name="other.example.com", rcode=3))),
        ]
    )
    out = check(blob)
    assert out["verdict"] == "question_mismatch"
    assert "rcode" not in out["response"]  # excluded: question did not match
    assert out["response"]["question_match"] is False
    assert out["response"]["response_questions"][0]["name"] == "other.example.com"


def test_assembled_qr0_is_a_mismatch() -> None:
    # a reflected *query* (QR=0) with matching txid/ports is not an answer
    reflected = udp(SERVER_PORT, CLIENT_PORT, dns_query(FRAG_TXID))
    blob = pcap([query_pkt(FRAG_TXID), eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, reflected))])
    out = check(blob)
    assert out["verdict"] == "question_mismatch"
    assert "QR" in out["response"]["mismatch_detail"]


def test_snaplen_truncation_counts_as_missing_and_is_noted() -> None:
    query = query_pkt(FRAG_TXID)
    frame = eth(ip_packet(SERVER_IP, CLIENT_IP, 0x2000, False, 0, response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)))
    cut = frame[:-10]  # snaplen cut the tail
    blob = pcap([query, cut], orig_lens=[len(query), len(frame)])
    out = check(blob)
    assert out["verdict"] == "missing_fragments"
    udp_len = len(response_datagram(FRAG_TXID, answers=FRAG_ANSWERS))
    assert out["missing"][0]["missing_ranges"] == [
        {"offset": udp_len - 10, "length": 10}
    ]
    assert any("snaplen" in note for note in out["notes"])


def test_udp_length_extends_beyond_last_fragment() -> None:
    # sender claims a longer datagram than what the MF=0 fragment closes
    datagram = response_datagram(FRAG_TXID, answers=FRAG_ANSWERS)
    first = eth(ip_packet(SERVER_IP, CLIENT_IP, FRAG_IDENT, False, 0, datagram[:48]))
    blob = pcap([query_pkt(FRAG_TXID), first])
    out = check(blob)
    (group,) = out["missing"]
    assert group["last_fragment_seen"] is True
    assert group["missing_ranges"] == [{"offset": 48, "length": len(datagram) - 48}]


def test_dns_pointer_loop_does_not_hang() -> None:
    # question name is a pointer to itself
    payload = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    with pytest.raises(DnsParseError):
        parse_dns(payload)


def test_healthz_still_ok() -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
