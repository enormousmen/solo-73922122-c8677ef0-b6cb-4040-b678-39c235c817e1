"""Run the bundled sample captures through the fragment check without a server.

Usage (from the repository root)::

    python examples/demo_pcap.py

Each sample uses frame 1 as the A query and the last frame as the cutoff.
Start the service with ``docker compose up --build`` and use
``examples/check_samples.sh`` for the HTTP equivalents.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.fragcheck import check_dns_response  # noqa: E402
from app.pcap import parse_pcap  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent / "pcap"


def summarise(path: pathlib.Path) -> None:
    blob = path.read_bytes()
    frames = len(parse_pcap(blob))
    out = check_dns_response(blob, 1, frames)
    print(f"=== {path.name} -> {out['verdict']}（{out['verdict_label']}）")
    print(out["message"])
    response = out.get("response")
    if response and response.get("question_match"):
        print(f"  响应码: {response['rcode_name']}，A 记录: {response['answers_a']}")
    for group in out["missing"]:
        gaps = ", ".join(
            f"[{g['offset']}, {g['offset'] + g['length']})" for g in group["missing_ranges"]
        )
        print(f"  缺片: 标识 0x{group['identification']:04x} 缺 {gaps}（帧 {group['frames']}）")
    for group in out["unattributable"]:
        print(f"  无法归属[{group['reason_label']}]: 帧 {group['frames']}")
    print()


def main() -> None:
    for path in sorted(HERE.glob("*.pcap")):
        summarise(path)


if __name__ == "__main__":
    main()
