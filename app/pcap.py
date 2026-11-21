"""Classic PCAP + Ethernet/IPv4/UDP/DNS parsing for the offline fragment check.

Only what the fragment check needs is implemented: classic (libpcap) capture
files, Ethernet link layer (with optional 802.1Q tags), IPv4, and UDP.  The
parsers are defensive: a frame that cannot be parsed is reported as ``None``
and skipped by the caller, while a *file* that cannot be parsed raises
:class:`PcapError` (surfaced to the API client as 422).

Byte offsets in this module are always relative to the start of the UDP
header of the original datagram, i.e. the start of the IPv4 payload, which is
how the API reports missing fragment ranges.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Upload cap for the API: 5 MiB of classic PCAP.
MAX_PCAP_BYTES = 5 * 1024 * 1024

LINKTYPE_ETHERNET = 1

# PCAP magic -> struct endianness prefix.  Both microsecond and nanosecond
# variants carry the same layout; the timestamp resolution does not matter
# for this analysis, only the field endianness does.
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanosecond
}

_ETHERTYPE_IPV4 = 0x0800
_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
_IPPROTO_UDP = 17

_DNS_HEADER_LEN = 12
_MAX_QUESTIONS = 16
_MAX_ANSWERS = 64
_MAX_NAME_LABELS = 128


class PcapError(ValueError):
    """The capture file itself cannot be parsed (bad magic, truncated, ...)."""


class DnsParseError(ValueError):
    """A UDP payload cannot be parsed as a DNS message."""


@dataclass
class Frame:
    """One captured packet.  ``number`` is 1-based, like Wireshark frame.number."""

    number: int
    data: bytes
    captured_len: int
    original_len: int

    @property
    def truncated(self) -> bool:
        """True when snaplen cut the frame short (captured < original)."""
        return self.captured_len < self.original_len


def parse_pcap(blob: bytes) -> list[Frame]:
    """Parse a classic PCAP byte string into frames (1-based numbering)."""
    if len(blob) < 24:
        raise PcapError("文件不足 24 字节，不是经典 PCAP 文件")
    endian = _MAGICS.get(blob[:4])
    if endian is None:
        raise PcapError("无法识别的文件魔数，只支持经典 PCAP（不支持 pcapng）")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack_from(
        endian + "HHIIII", blob, 4
    )
    if linktype != LINKTYPE_ETHERNET:
        raise PcapError(
            f"不支持的链路类型 LINKTYPE={linktype}，只支持以太网（LINKTYPE=1）"
        )
    frames: list[Frame] = []
    pos = 24
    number = 1
    while pos < len(blob):
        if pos + 16 > len(blob):
            raise PcapError(f"第 {number} 帧的记录头不完整，抓包文件可能被截断")
        _ts_sec, _ts_frac, incl, orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        if incl > len(blob) - pos:
            raise PcapError(f"第 {number} 帧的数据不完整，抓包文件可能被截断")
        frames.append(Frame(number, blob[pos : pos + incl], incl, orig))
        pos += incl
        number += 1
    return frames


@dataclass
class UdpInfo:
    """UDP header as seen in a first fragment (offset 0)."""

    src_port: int
    dst_port: int
    length: int  # UDP length field: header + payload of the *whole* datagram
    payload: bytes  # UDP payload bytes present in this frame


@dataclass
class Ipv4Fragment:
    """The IPv4/UDP view of one frame (also used for unfragmented packets)."""

    frame_number: int
    truncated_capture: bool
    src: str
    dst: str
    ident: int
    more_fragments: bool
    offset: int  # byte offset of this fragment within the IPv4 payload
    payload: bytes  # IPv4-payload bytes carried by this frame (as captured)
    udp: UdpInfo | None  # set only when offset == 0 and the UDP header is captured


def parse_ipv4_udp(frame: Frame) -> Ipv4Fragment | None:
    """Return the IPv4/UDP view of a frame, or None if it is not IPv4/UDP."""
    data = frame.data
    if len(data) < 14:
        return None
    eth_type = int.from_bytes(data[12:14], "big")
    off = 14
    for _ in range(2):  # tolerate up to two stacked VLAN tags
        if eth_type in _VLAN_ETHERTYPES and len(data) >= off + 4:
            eth_type = int.from_bytes(data[off + 2 : off + 4], "big")
            off += 4
        else:
            break
    if eth_type != _ETHERTYPE_IPV4:
        return None
    if len(data) < off + 20:
        return None
    version = data[off] >> 4
    ihl = (data[off] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < off + ihl:
        return None
    total_length = int.from_bytes(data[off + 2 : off + 4], "big")
    if total_length < ihl:
        return None
    ident = int.from_bytes(data[off + 4 : off + 6], "big")
    flags_frag = int.from_bytes(data[off + 6 : off + 8], "big")
    more_fragments = bool(flags_frag & 0x2000)
    frag_offset = (flags_frag & 0x1FFF) * 8
    if data[off + 9] != _IPPROTO_UDP:
        return None
    src = ".".join(str(b) for b in data[off + 12 : off + 16])
    dst = ".".join(str(b) for b in data[off + 16 : off + 20])
    # Slice by the IPv4 total length: this drops Ethernet padding and, when
    # the capture was snaplen-truncated, naturally yields fewer bytes.
    payload = data[off + ihl : off + total_length]
    udp = None
    if frag_offset == 0 and len(payload) >= 8:
        src_port, dst_port, udp_len, _sum = struct.unpack_from("!HHHH", payload, 0)
        udp = UdpInfo(src_port, dst_port, udp_len, payload[8:])
    return Ipv4Fragment(
        frame_number=frame.number,
        truncated_capture=frame.truncated,
        src=src,
        dst=dst,
        ident=ident,
        more_fragments=more_fragments,
        offset=frag_offset,
        payload=payload,
        udp=udp,
    )


@dataclass
class DnsQuestion:
    qname: str
    qtype: int
    qclass: int

    def key(self) -> tuple[str, int, int]:
        """Canonical comparison key (DNS names are case-insensitive)."""
        return (self.qname.lower(), self.qtype, self.qclass)


@dataclass
class DnsMessage:
    txid: int
    qr: bool
    rcode: int
    qdcount: int
    ancount: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answers_a: list[str] = field(default_factory=list)  # best effort


def _read_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return (name, next position)."""
    labels: list[str] = []
    seen_offsets: set[int] = set()
    end: int | None = None
    while True:
        if pos >= len(msg):
            raise DnsParseError("名称越界")
        if pos in seen_offsets:
            raise DnsParseError("名称压缩指针成环")
        seen_offsets.add(pos)
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise DnsParseError("压缩指针越界")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            continue
        if length & 0xC0:
            raise DnsParseError("保留的标签类型")
        pos += 1
        if length == 0:
            break
        if pos + length > len(msg):
            raise DnsParseError("标签越界")
        labels.append(msg[pos : pos + length].decode("ascii", "backslashreplace"))
        pos += length
        if len(labels) > _MAX_NAME_LABELS:
            raise DnsParseError("名称过长")
    return (".".join(labels) if labels else "."), (end if end is not None else pos)


def parse_dns(payload: bytes) -> DnsMessage:
    """Parse a DNS message.  Raises DnsParseError if the header/question
    section cannot be parsed; the answer section is parsed best-effort."""
    if len(payload) < _DNS_HEADER_LEN:
        raise DnsParseError("DNS 头不足 12 字节")
    txid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", payload, 0)
    pos = _DNS_HEADER_LEN
    questions: list[DnsQuestion] = []
    for _ in range(min(qd, _MAX_QUESTIONS)):
        name, pos = _read_name(payload, pos)
        if pos + 4 > len(payload):
            raise DnsParseError("问题段越界")
        qtype, qclass = struct.unpack_from("!HH", payload, pos)
        pos += 4
        questions.append(DnsQuestion(name, qtype, qclass))
    answers_a: list[str] = []
    try:
        for _ in range(min(an, _MAX_ANSWERS)):
            _name, pos = _read_name(payload, pos)
            if pos + 10 > len(payload):
                raise DnsParseError("回答段越界")
            rtype, rclass, _ttl, rdlen = struct.unpack_from("!HHIH", payload, pos)
            pos += 10
            if pos + rdlen > len(payload):
                raise DnsParseError("记录数据越界")
            if rtype == 1 and rclass == 1 and rdlen == 4:
                answers_a.append(".".join(str(b) for b in payload[pos : pos + 4]))
            pos += rdlen
    except DnsParseError:
        pass  # answers are informational only; keep what parsed
    return DnsMessage(
        txid=txid,
        qr=bool(flags & 0x8000),
        rcode=flags & 0x000F,
        qdcount=qd,
        ancount=an,
        questions=questions,
        answers_a=answers_a,
    )
