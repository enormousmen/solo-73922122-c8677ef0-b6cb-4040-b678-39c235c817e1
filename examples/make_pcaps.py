"""Generate the bundled sample captures under examples/pcap/.

The samples are hand-crafted classic PCAP files (Ethernet / IPv4 / UDP) that
exercise every verdict of POST /pcap/dns-response-check.  They are committed
to the repository; run this script to regenerate them:

    python examples/make_pcaps.py

No third-party dependencies are needed.
"""

from __future__ import annotations

import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "pcap"

CLIENT_IP = "192.0.2.10"
CLIENT_PORT = 53210
SERVER_IP = "198.51.100.53"
SERVER_PORT = 53
CLIENT_MAC = "02:00:00:00:00:0a"
SERVER_MAC = "02:00:00:00:00:35"
QNAME = "www.example.com"


# --------------------------------------------------------------------------- #
# Packet crafting helpers
# --------------------------------------------------------------------------- #


def ip_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def mac_bytes(addr: str) -> bytes:
    return bytes(int(part, 16) for part in addr.split(":"))


def ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def ip_packet(src: str, dst: str, ident: int, mf: bool, offset_units: int, payload: bytes) -> bytes:
    """One IPv4/UDP packet or fragment (UDP protocol hard-coded)."""
    ihl = 20
    flags_frag = (0x2000 if mf else 0) | offset_units
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ihl + len(payload),
        ident,
        flags_frag,
        64,
        17,
        0,
        ip_bytes(src),
        ip_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", ip_checksum(header)) + header[12:]
    return header + payload


def eth_frame(ip_pkt: bytes, src_mac: str, dst_mac: str) -> bytes:
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00" + ip_pkt


def udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    # UDP checksum 0 means "not computed", which is legal for IPv4.
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def encode_name(name: str) -> bytes:
    return b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    ) + b"\x00"


def dns_query(txid: int, name: str = QNAME, qtype: int = 1) -> bytes:
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question


def dns_response(
    txid: int,
    name: str = QNAME,
    rcode: int = 0,
    answers: tuple[str, ...] = (),
    qtype: int = 1,
) -> bytes:
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    records = b""
    for addr in answers:
        records += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes(addr)
    return (
        struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
        + question
        + records
    )


def query_frame(txid: int, name: str = QNAME, qtype: int = 1) -> bytes:
    return eth_frame(
        ip_packet(CLIENT_IP, SERVER_IP, 0x1000, False, 0, udp_datagram(CLIENT_PORT, SERVER_PORT, dns_query(txid, name, qtype))),
        CLIENT_MAC,
        SERVER_MAC,
    )


def response_frames(
    txid: int,
    ident: int,
    name: str = QNAME,
    rcode: int = 0,
    answers: tuple[str, ...] = (),
    fragment_size: int | None = None,
) -> list[bytes]:
    """Response as one frame, or as in-order fragments of ``fragment_size``."""
    datagram = udp_datagram(SERVER_PORT, CLIENT_PORT, dns_response(txid, name, rcode, answers))
    if fragment_size is None:
        return [eth_frame(ip_packet(SERVER_IP, CLIENT_IP, ident, False, 0, datagram), SERVER_MAC, CLIENT_MAC)]
    frames = []
    offset = 0
    while offset < len(datagram):
        chunk = datagram[offset : offset + fragment_size]
        mf = offset + len(chunk) < len(datagram)
        frames.append(
            eth_frame(ip_packet(SERVER_IP, CLIENT_IP, ident, mf, offset // 8, chunk), SERVER_MAC, CLIENT_MAC)
        )
        offset += len(chunk)
    return frames


def write_pcap(name: str, frames: list[bytes]) -> None:
    blob = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for idx, frame in enumerate(frames):
        blob.append(struct.pack("<IIII", 1_700_000_000 + idx, idx * 1000, len(frame), len(frame)))
        blob.append(frame)
    path = OUT / name
    path.write_bytes(b"".join(blob))
    print(f"{path.name}: {len(frames)} 帧, {path.stat().st_size} 字节")


# --------------------------------------------------------------------------- #
# Scenarios (query is always frame 1; cutoff is always the last frame)
# --------------------------------------------------------------------------- #

ANSWERS = ("203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13")


def main() -> None:
    OUT.mkdir(exist_ok=True)

    # 1) Unfragmented response -> answered / NOERROR.
    write_pcap(
        "01-complete-unfragmented.pcap",
        [query_frame(0x1A2B)] + response_frames(0x1A2B, 0x5001, answers=ANSWERS[:2]),
    )

    # 2) Response in 3 fragments, delivered out of order with a duplicate
    #    -> still answered (order/duplicates must not change the verdict).
    frags = response_frames(0x1A2C, 0x5002, answers=ANSWERS, fragment_size=48)
    assert len(frags) == 3
    write_pcap(
        "02-complete-fragments-out-of-order.pcap",
        [query_frame(0x1A2C), frags[1], frags[2], frags[1], frags[0]],
    )

    # 3) Middle fragment missing -> missing_fragments with a byte range.
    frags = response_frames(0x1A2D, 0x5003, answers=ANSWERS, fragment_size=48)
    write_pcap(
        "03-missing-fragment.pcap",
        [query_frame(0x1A2D), frags[0], frags[2]],
    )

    # 4) Only non-first fragments -> unattributable / only_non_first_fragments.
    frags = response_frames(0x1A2E, 0x5004, answers=ANSWERS, fragment_size=48)
    write_pcap(
        "04-only-non-first-fragments.pcap",
        [query_frame(0x1A2E), frags[1], frags[2]],
    )

    # 5) Two *different* first fragments under the same addresses+ident
    #    -> unattributable / conflicting_first_fragments.
    good = response_frames(0x1A2F, 0x5005, answers=ANSWERS, fragment_size=48)
    other = response_frames(0x2222, 0x5005, answers=ANSWERS, fragment_size=48)
    write_pcap(
        "05-conflicting-first-fragments.pcap",
        [query_frame(0x1A2F), good[0], other[0], good[1], good[2]],
    )

    # 6) Nothing matches: a response for another transaction and an unrelated
    #    UDP flow between the same hosts -> no_response.
    ntp_like = eth_frame(
        ip_packet(SERVER_IP, CLIENT_IP, 0x6006, False, 0, udp_datagram(123, 53211, b"\x1b" + b"\x00" * 47)),
        SERVER_MAC,
        CLIENT_MAC,
    )
    write_pcap(
        "06-no-response.pcap",
        [query_frame(0x1A30)]
        + response_frames(0x9999, 0x5006, answers=ANSWERS[:2])
        + [ntp_like],
    )

    # 7) Complete response whose question section names another domain
    #    -> question_mismatch (no RCODE reported).
    write_pcap(
        "07-question-mismatch.pcap",
        [query_frame(0x1A31)]
        + response_frames(0x1A31, 0x5007, name="other.example.com", answers=ANSWERS[:2], fragment_size=48),
    )

    # 8) Complete NXDOMAIN answer -> answered with RCODE 3.
    write_pcap(
        "08-nxdomain.pcap",
        [query_frame(0x1A32, name="nope.example.com")]
        + response_frames(0x1A32, 0x5008, name="nope.example.com", rcode=3),
    )


if __name__ == "__main__":
    main()
