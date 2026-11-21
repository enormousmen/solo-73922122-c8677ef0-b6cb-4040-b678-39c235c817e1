"""Correlate (possibly fragmented) DNS/UDP responses in an offline capture.

Given the frame number of a DNS A query and a cutoff frame, the check scans
the window ``(query_frame, cutoff_frame]`` for the matching response:

* candidate **first fragments** are correlated by reversed address/port and
  the DNS transaction id;
* fragments are then grouped by ``(source, destination, IPv4
  identification)`` and reassembled against the UDP length field, so
  out-of-order or duplicated fragments do not change the verdict;
* a completely reassembled datagram is only accepted as the answer when its
  DNS question section matches the query — then the RCODE is reported;
* a matched but incomplete datagram is reported with the missing byte ranges
  (offsets from the start of the UDP header);
* fragments that cannot be attributed — only non-first fragments, or
  conflicting first fragments under the same addresses+identification — are
  listed separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .pcap import (
    DnsParseError,
    DnsQuestion,
    Frame,
    Ipv4Fragment,
    parse_dns,
    parse_ipv4_udp,
    parse_pcap,
)

QTYPE_A = 1

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
}
QCLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

VERDICT_LABELS = {
    "answered": "收到完整应答",
    "question_mismatch": "应答问题段与查询不一致",
    "missing_fragments": "回包缺片",
    "unattributable": "回包分片无法归属",
    "no_response": "未观察到匹配回包",
}

REASON_LABELS = {
    "only_non_first_fragments": "只有非首片",
    "conflicting_first_fragments": "同组地址与标识下出现不同首片",
    "first_fragment_unverifiable": "首片无法核验（UDP 头/事务号未完整捕获或长度非法）",
}


class CheckError(ValueError):
    """User-facing validation error, surfaced as HTTP 422."""


@dataclass
class QueryContext:
    frame_number: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    txid: int
    questions: list[DnsQuestion]


def _qtype_name(qtype: int) -> str:
    return QTYPE_NAMES.get(qtype, f"TYPE{qtype}")


def _qclass_name(qclass: int) -> str:
    return QCLASS_NAMES.get(qclass, f"CLASS{qclass}")


def _question_json(q: DnsQuestion) -> dict[str, Any]:
    return {"name": q.qname, "qtype": _qtype_name(q.qtype), "qclass": _qclass_name(q.qclass)}


def _extract_query(frame: Frame) -> QueryContext:
    """Validate the query frame and pull out the correlation keys."""
    frag = parse_ipv4_udp(frame)
    if frag is None:
        raise CheckError(f"第 {frame.number} 帧不是以太网/IPv4/UDP 报文，不能作为 DNS 查询帧")
    if frag.offset != 0 or frag.more_fragments:
        raise CheckError(
            f"第 {frame.number} 帧本身是 IP 分片，查询被分片时不支持解析，请换用未分片的查询帧"
        )
    if frag.udp is None:
        raise CheckError(f"第 {frame.number} 帧的 UDP 头未完整捕获，无法解析查询")
    try:
        dns = parse_dns(frag.udp.payload)
    except DnsParseError as exc:
        raise CheckError(f"第 {frame.number} 帧不是可解析的 DNS 报文：{exc}") from exc
    if dns.qr:
        raise CheckError(f"第 {frame.number} 帧是 DNS 应答（QR=1），不是查询")
    if not dns.questions:
        raise CheckError(f"第 {frame.number} 帧没有问题段，不是有效的 DNS 查询")
    if dns.questions[0].qtype != QTYPE_A:
        raise CheckError(
            f"第 {frame.number} 帧的第一个问题是 {_qtype_name(dns.questions[0].qtype)} 查询，"
            "本接口只核查 A 查询"
        )
    return QueryContext(
        frame_number=frame.number,
        src_ip=frag.src,
        src_port=frag.udp.src_port,
        dst_ip=frag.dst,
        dst_port=frag.udp.dst_port,
        txid=dns.txid,
        questions=dns.questions,
    )


def _frags_conflict(a: Ipv4Fragment, b: Ipv4Fragment) -> bool:
    """True if two fragments disagree on any byte they both carry."""
    if a.offset != b.offset:
        return True  # same "first fragment" role but different offsets
    overlap = min(len(a.payload), len(b.payload))
    return a.payload[:overlap] != b.payload[:overlap]


def _union(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def _complement(unioned: list[tuple[int, int]], lo: int, hi: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    cur = lo
    for start, end in unioned:
        if start > cur:
            out.append((cur, start))
        cur = max(cur, end)
    if cur < hi:
        out.append((cur, hi))
    return out


@dataclass
class Reassembly:
    expected: int
    received: list[tuple[int, int]]
    missing: list[tuple[int, int]]
    last_fragment_seen: bool
    overlap_conflict: bool
    payload: bytes | None  # assembled datagram, only when complete

    @property
    def complete(self) -> bool:
        return self.payload is not None


def _reassemble(frags: list[Ipv4Fragment], expected: int) -> Reassembly:
    """Reassemble one fragment group against the UDP length.

    Coverage-based, so out-of-order and duplicated fragments do not change
    the outcome.  Overlapping bytes keep the first captured value; a
    disagreement is flagged in ``overlap_conflict``.
    """
    intervals: list[tuple[int, int]] = []
    buf = bytearray(expected)
    filled = bytearray(expected)
    last_seen = False
    conflict = False
    for frag in sorted(frags, key=lambda f: f.frame_number):
        if not frag.more_fragments:
            last_seen = True
        start = frag.offset
        if start >= expected:
            continue  # carries nothing inside the UDP datagram
        data = frag.payload[: expected - start]
        end = start + len(data)
        if end > start:
            intervals.append((start, end))
        for pos, byte in enumerate(data, start=start):
            if filled[pos]:
                if buf[pos] != byte:
                    conflict = True
            else:
                buf[pos] = byte
                filled[pos] = 1
    received = _union(intervals)
    missing = _complement(received, 0, expected)
    complete = not missing and last_seen
    return Reassembly(
        expected=expected,
        received=received,
        missing=missing,
        last_fragment_seen=last_seen,
        overlap_conflict=conflict,
        payload=bytes(buf) if complete else None,
    )


def _range_json(ranges: list[tuple[int, int]]) -> list[dict[str, int]]:
    return [{"offset": start, "length": end - start} for start, end in ranges]


def _questions_match(a: list[DnsQuestion], b: list[DnsQuestion]) -> bool:
    return len(a) == len(b) and all(x.key() == y.key() for x, y in zip(a, b))


def check_dns_response(blob: bytes, query_frame: int, cutoff_frame: int) -> dict[str, Any]:
    """Run the fragment check and return the JSON-able verdict report."""
    frames = parse_pcap(blob)  # raises PcapError on unreadable files
    if not frames:
        raise CheckError("抓包文件不含任何帧")
    if not 1 <= query_frame <= len(frames):
        raise CheckError(f"查询帧号 {query_frame} 超出范围（抓包共 {len(frames)} 帧）")
    if not 1 <= cutoff_frame <= len(frames):
        raise CheckError(f"截止帧号 {cutoff_frame} 超出范围（抓包共 {len(frames)} 帧）")
    if query_frame >= cutoff_frame:
        raise CheckError("截止帧号必须大于查询帧号（核查窗口为查询帧之后、含截止帧）")

    query = _extract_query(frames[query_frame - 1])

    # --- collect candidate fragments in the window, grouped by addr+ident ---
    groups: dict[tuple[str, str, int], list[Ipv4Fragment]] = {}
    group_order: list[tuple[str, str, int]] = []
    for frame in frames[query_frame:cutoff_frame]:  # numbers query_frame+1 .. cutoff_frame
        frag = parse_ipv4_udp(frame)
        if frag is None:
            continue
        if frag.src != query.dst_ip or frag.dst != query.src_ip:
            continue  # not even the reversed address pair of the query
        key = (frag.src, frag.dst, frag.ident)
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(frag)

    notes: list[str] = []
    matched: list[tuple[tuple[str, str, int], list[Ipv4Fragment], Ipv4Fragment]] = []
    unattributable: list[dict[str, Any]] = []

    for key in group_order:
        src, dst, ident = key
        frags = groups[key]
        frame_numbers = [f.frame_number for f in frags]
        if any(f.truncated_capture for f in frags):
            cut = [f.frame_number for f in frags if f.truncated_capture]
            notes.append(
                f"帧 {cut} 因 snaplen 被抓包截断，未捕获的字节按未收到处理"
            )
        firsts = [f for f in frags if f.offset == 0]
        base: dict[str, Any] = {
            "frames": frame_numbers,
            "identification": ident,
            "source_ip": src,
            "destination_ip": dst,
        }
        if not firsts:
            unattributable.append(
                {
                    **base,
                    "reason": "only_non_first_fragments",
                    "reason_label": REASON_LABELS["only_non_first_fragments"],
                    "detail": "该组分片偏移都大于 0，没有首片，无法核验端口与事务号",
                }
            )
            continue
        anchor = firsts[0]
        if any(_frags_conflict(anchor, other) for other in firsts[1:]):
            unattributable.append(
                {
                    **base,
                    "reason": "conflicting_first_fragments",
                    "reason_label": REASON_LABELS["conflicting_first_fragments"],
                    "conflicting_first_frames": [f.frame_number for f in firsts],
                    "detail": "同一组地址与 IPv4 标识下出现内容不同的首片，无法确定归属",
                }
            )
            continue
        first = max(firsts, key=lambda f: len(f.payload))  # most complete copy
        udp = first.udp
        if udp is None or udp.length < 8 or len(udp.payload) < 2:
            unattributable.append(
                {
                    **base,
                    "reason": "first_fragment_unverifiable",
                    "reason_label": REASON_LABELS["first_fragment_unverifiable"],
                    "detail": "首片的 UDP 头或事务号未完整捕获，或 UDP 长度非法，无法核验",
                }
            )
            continue
        if udp.src_port != query.dst_port or udp.dst_port != query.src_port:
            continue  # a different conversation between the same hosts
        if int.from_bytes(udp.payload[:2], "big") != query.txid:
            continue  # a different DNS transaction
        matched.append((key, frags, first))

    # --- reassemble matched groups and evaluate them ---
    responses: list[dict[str, Any]] = []
    missing_reports: list[dict[str, Any]] = []
    for (src, dst, ident), frags, first in matched:
        reassembly = _reassemble(frags, first.udp.length)
        info: dict[str, Any] = {
            "frames": [f.frame_number for f in frags],
            "identification": ident,
            "source": {"ip": src, "port": first.udp.src_port},
            "destination": {"ip": dst, "port": first.udp.dst_port},
            "udp_length": first.udp.length,
        }
        if not reassembly.complete:
            missing_reports.append(
                {
                    **info,
                    "received_bytes": sum(e - s for s, e in reassembly.received),
                    "received_ranges": _range_json(reassembly.received),
                    "missing_ranges": _range_json(reassembly.missing),
                    "last_fragment_seen": reassembly.last_fragment_seen,
                    "overlap_conflict": reassembly.overlap_conflict,
                }
            )
            continue
        try:
            # The reassembled datagram starts at the UDP header (that is how
            # the missing ranges are counted); the DNS message follows it.
            dns = parse_dns(reassembly.payload[8:])
        except DnsParseError as exc:
            responses.append(
                {
                    **info,
                    "question_match": False,
                    "mismatch_detail": f"组装结果不是可解析的 DNS 报文：{exc}",
                }
            )
            continue
        problems: list[str] = []
        if not dns.qr:
            problems.append("QR 位为 0（不是应答）")
        if dns.txid != query.txid:
            problems.append(f"事务号 0x{dns.txid:04x} 与查询 0x{query.txid:04x} 不一致")
        if not _questions_match(dns.questions, query.questions):
            problems.append("问题段与查询不一致")
        if problems:
            responses.append(
                {
                    **info,
                    "question_match": False,
                    "mismatch_detail": "；".join(problems),
                    "response_questions": [_question_json(q) for q in dns.questions],
                }
            )
            continue
        responses.append(
            {
                **info,
                "question_match": True,
                "rcode": dns.rcode,
                "rcode_name": RCODE_NAMES.get(dns.rcode, f"RCODE{dns.rcode}"),
                "answer_count": dns.ancount,
                "answers_a": dns.answers_a,
            }
        )

    # --- pick the headline verdict ---
    answered = next((r for r in responses if r.get("question_match")), None)
    mismatch = next((r for r in responses if not r.get("question_match")), None)
    if answered is not None:
        verdict = "answered"
        response = answered
        message = (
            f"在帧 {answered['frames']} 中收到完整应答，问题段与查询一致，"
            f"响应码 {answered['rcode_name']}（{answered['rcode']}）。"
        )
    elif mismatch is not None:
        verdict = "question_mismatch"
        response = mismatch
        message = (
            f"帧 {mismatch['frames']} 组装出完整数据报，但{mismatch['mismatch_detail']}，"
            "不按本查询的应答处理，不返回响应码。"
        )
    elif missing_reports:
        verdict = "missing_fragments"
        response = None
        gaps = sum(r["udp_length"] - r["received_bytes"] for r in missing_reports)
        message = (
            "关联到回包首片但数据报未收全："
            + "；".join(
                f"标识 0x{r['identification']:04x} 缺 "
                + "、".join(
                    f"[{g['offset']}, {g['offset'] + g['length']})" for g in r["missing_ranges"]
                )
                for r in missing_reports
            )
            + f"（共缺 {gaps} 字节，偏移自 UDP 头起算）。"
        )
    elif unattributable:
        verdict = "unattributable"
        response = None
        message = "未找到可核验的回包首片；窗口内存在无法归属的分片，详见 unattributable。"
    else:
        verdict = "no_response"
        response = None
        message = "窗口内未观察到与查询反向地址、端口和事务号都匹配的应答分片。"

    return {
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "message": message,
        "query": {
            "frame": query.frame_number,
            "txid": query.txid,
            "txid_hex": f"0x{query.txid:04x}",
            "name": query.questions[0].qname,
            "questions": [_question_json(q) for q in query.questions],
            "source": {"ip": query.src_ip, "port": query.src_port},
            "destination": {"ip": query.dst_ip, "port": query.dst_port},
        },
        "window": {
            "query_frame": query_frame,
            "cutoff_frame": cutoff_frame,
            "frames_scanned": cutoff_frame - query_frame,
        },
        "response": response,
        "missing": missing_reports,
        "unattributable": unattributable,
        "notes": notes,
    }
