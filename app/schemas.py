"""Request/response shapes for the planner, documented for OpenAPI."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TraceStep(BaseModel):
    name: str
    zone: str | None
    outcome: Literal[
        "cname", "a", "nodata", "nxdomain", "external", "loop", "too_long"
    ]
    target: str | None = None
    addresses: list[str] = Field(default_factory=list)


class ChainFailure(BaseModel):
    domain: str
    resolved: bool
    addresses: list[str]
    category: Literal[
        "missing_record", "cname_loop", "external_target", "chain_too_long"
    ]
    category_label: str | None
    detail: str | None = None
    message: str
    chain: str
    trace: list[TraceStep]


class FailureSummary(BaseModel):
    total: int
    by_category: dict[str, int]
    by_category_label: dict[str, int]


class PlanStep(BaseModel):
    step: int
    zone: str
    action: str
    addresses_before: dict[str, list[str]]
    addresses_after: dict[str, list[str]]
    all_required_resolvable: bool


class BlockedZone(BaseModel):
    zone: str
    categories: list[dict[str, str]]
    failures: list[ChainFailure]


class PlanResponse(BaseModel):
    mode: Literal["authoritative_no_cache"]
    zone_count: int
    domain_count: int
    assumptions: list[str]
    status: Literal["already_broken", "safe_order_found", "no_safe_order"]
    status_meaning: str
    message: str
    order: list[str]
    safe_prefix: list[str]
    safe_prefix_is_maximal: bool | None = None
    steps: list[PlanStep]
    final_state_resolvable: bool | None = None
    fault_chains: list[ChainFailure]
    blocked_zones: list[BlockedZone]
    failure_summary: FailureSummary

    model_config = {"extra": "allow"}


class HealthResponse(BaseModel):
    status: str
    version: str


# --------------------------------------------------------------------------- #
# Offline PCAP DNS fragment check
# --------------------------------------------------------------------------- #


class EndpointInfo(BaseModel):
    ip: str
    port: int


class QuestionInfo(BaseModel):
    name: str
    qtype: str
    qclass: str


class QueryInfo(BaseModel):
    frame: int
    txid: int
    txid_hex: str
    name: str
    questions: list[QuestionInfo]
    source: EndpointInfo
    destination: EndpointInfo


class WindowInfo(BaseModel):
    query_frame: int
    cutoff_frame: int
    frames_scanned: int


class ByteRange(BaseModel):
    """Half-open byte range [offset, offset+length), from the UDP header."""

    offset: int
    length: int


class ResponseInfo(BaseModel):
    frames: list[int]
    identification: int
    source: EndpointInfo
    destination: EndpointInfo
    udp_length: int
    question_match: bool
    rcode: int | None = None
    rcode_name: str | None = None
    answer_count: int | None = None
    answers_a: list[str] | None = None
    mismatch_detail: str | None = None
    response_questions: list[QuestionInfo] | None = None


class MissingGroup(BaseModel):
    frames: list[int]
    identification: int
    source: EndpointInfo
    destination: EndpointInfo
    udp_length: int
    received_bytes: int
    received_ranges: list[ByteRange]
    missing_ranges: list[ByteRange]
    last_fragment_seen: bool
    overlap_conflict: bool


class UnattributableGroup(BaseModel):
    reason: Literal[
        "only_non_first_fragments",
        "conflicting_first_fragments",
        "first_fragment_unverifiable",
    ]
    reason_label: str
    detail: str
    frames: list[int]
    identification: int
    source_ip: str
    destination_ip: str
    conflicting_first_frames: list[int] | None = None


class PcapCheckResponse(BaseModel):
    verdict: Literal[
        "answered",
        "question_mismatch",
        "missing_fragments",
        "unattributable",
        "no_response",
    ]
    verdict_label: str
    message: str
    query: QueryInfo
    window: WindowInfo
    response: ResponseInfo | None
    missing: list[MissingGroup]
    unattributable: list[UnattributableGroup]
    notes: list[str]
