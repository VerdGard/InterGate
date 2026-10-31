"""用量解析:从 JSON 响应或 SSE 行中提取 usage。"""
from __future__ import annotations

import json
import re
from typing import Any, Dict


def parse_usage_from_json(body: bytes) -> Dict[str, Any]:
    """OpenAI 兼容:从响应 JSON 提取 usage 字段。"""
    try:
        j = json.loads(body)
    except Exception:
        return {}
    if not isinstance(j, dict):
        return {}
    usage = j.get("usage")
    if isinstance(usage, dict):
        return _normalize_usage(usage)
    # Google 风格: usageMetadata
    um = j.get("usageMetadata")
    if isinstance(um, dict):
        return _normalize_usage(um)
    return {}


def parse_usage_from_sse_line(line: bytes) -> Dict[str, Any]:
    """SSE 行形如: data: {"choices":[...], "usage":{...}}"""
    if not line.startswith(b"data:"):
        return {}
    payload = line[5:].strip()
    if payload in (b"[DONE]", b""):
        return {}
    try:
        j = json.loads(payload)
    except Exception:
        return {}
    if not isinstance(j, dict):
        return {}
    usage = j.get("usage")
    if isinstance(usage, dict):
        return _normalize_usage(usage)
    return {}


def _normalize_usage(u: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    # openai
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if k in u:
            out[k] = int(u[k])
    # google
    if "promptTokenCount" in u:
        out["prompt_tokens"] = int(u["promptTokenCount"])
        out["completion_tokens"] = int(u.get("candidatesTokenCount", 0))
        out["total_tokens"] = out["prompt_tokens"] + out["completion_tokens"]
    return out
