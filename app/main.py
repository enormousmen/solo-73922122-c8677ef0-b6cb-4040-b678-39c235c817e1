"""FastAPI entry point for the cross-zone DNS release-order planner."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from . import __version__
from .fragcheck import CheckError, check_dns_response
from .models import PlanRequest
from .pcap import MAX_PCAP_BYTES, PcapError
from .schemas import HealthResponse, PcapCheckResponse, PlanResponse
from .service import build_plan

app = FastAPI(
    title="跨区 DNS 变更发布顺序规划器",
    version=__version__,
    summary="为内网 DNS 值班员推算整区切换的安全顺序，并核查抓包里的 DNS 回包缺片",
    description=(
        "提交最多 8 个互不嵌套的权威区的新旧 A/CNAME 记录，以及必须持续可解析的"
        "业务域名。服务按无缓存权威记录推演每个整区切换后的状态：\n\n"
        "* 若存在安全顺序，返回逐步发布顺序，并附每一步前后的解析结果；\n"
        "* 若现状已无法解析，返回故障链路（缺记录 / 成环 / 链出权威区 / 链过长）；\n"
        "* 若无安全顺序，返回最大安全前缀，以及剩余每个区发布后会断在哪条解析链上。\n\n"
        "假设：每个区一次整区切换，区内没有新旧共存的中间态；解析无缓存；"
        "CNAME 链离开已提交的区即视为无法确认（可把外部区按新旧相同一并提交）。\n\n"
        "另附离线抓包核查：上传经典 PCAP（以太网 / IPv4 / UDP，≤ 5 MiB），"
        "指定 A 查询帧与截止帧，核查两帧之间的 DNS 回包是否缺片或无法归属。"
    ),
)


@app.get("/healthz", response_model=HealthResponse, summary="健康检查")
def healthz() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post(
    "/plan",
    response_model=PlanResponse,
    response_model_exclude_none=True,
    summary="计算跨区发布顺序",
    responses={
        200: {"description": "推演完成，status 指明三种结果之一"},
        422: {"description": "请求校验失败（区/记录/域名不合法或超出限制）"},
    },
)
def plan(request: PlanRequest) -> dict[str, Any]:
    return build_plan(request)


@app.post(
    "/pcap/dns-response-check",
    response_model=PcapCheckResponse,
    response_model_exclude_none=True,
    summary="离线核查抓包里的 DNS 回包缺片",
    responses={
        200: {"description": "核查完成，verdict 指明五种结论之一"},
        413: {"description": "抓包文件超过 5 MiB"},
        422: {"description": "文件无法解析，或帧号/查询帧不合法"},
    },
)
async def pcap_dns_response_check(
    file: UploadFile = File(description="经典 PCAP 文件（以太网 / IPv4 / UDP，≤ 5 MiB）"),
    query_frame: int = Form(ge=1, description="A 查询所在帧号（1 起，与 Wireshark 一致）"),
    cutoff_frame: int = Form(ge=1, description="截止帧号（含），只核查查询帧之后到此帧"),
) -> dict[str, Any]:
    blob = await file.read(MAX_PCAP_BYTES + 1)
    if len(blob) > MAX_PCAP_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"抓包文件超过 5 MiB 上限（收到 {len(blob)} 字节）",
        )
    try:
        return check_dns_response(blob, query_frame, cutoff_frame)
    except (PcapError, CheckError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
