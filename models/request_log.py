"""请求日志模型"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional


class RequestLog:
    def __init__(
        self,
        path: str,
        method: str,
        status: int,
        provider: str = "",
        key_id: str = "",
        model: str = "",
        latency_ms: int = 0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cached: bool = False,
        error: str = "",
        ts: Optional[int] = None,
    ):
        self.ts = ts or int(time.time() * 1000)
        self.path = path
        self.method = method
        self.status = status
        self.provider = provider
        self.key_id = key_id
        self.model = model
        self.latency_ms = latency_ms
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens
        self.cached = cached
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "path": self.path,
            "method": self.method,
            "status": self.status,
            "provider": self.provider,
            "key_id": self.key_id,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cached": self.cached,
            "error": self.error,
        }
