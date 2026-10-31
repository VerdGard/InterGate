"""上游转发:httpx 异步客户端,支持流式 SSE 透传。"""
from __future__ import annotations

import logging
import json
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, AsyncIterator, Dict, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from config import constants as C
from services.usage import parse_usage_from_json

log = logging.getLogger("intergate.upstream")


@dataclass
class UpstreamResult:
    status: int
    headers: Dict[str, str]
    body: bytes
    usage: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class UpstreamError(Exception):
    def __init__(self, message: str, status: int = 502,
                 category: str = "upstream", retryable: bool = True,
                 body: bytes = b""):
        super().__init__(message)
        self.message = message
        self.status = status
        self.category = category          # upstream / timeout / quota / auth / tpm
        self.retryable = retryable
        self.body = body


class UpstreamClient:
    """按 Base URL 维护连接池。"""

    def __init__(self, timeout: float = C.UPSTREAM_TIMEOUT_SECONDS,
                 max_body: int = C.MAX_REQUEST_BODY_BYTES,
                 max_response: int = 16 * 1024 * 1024,
                 max_connections: int = C.DEFAULT_UPSTREAM_MAX_CONNECTIONS,
                 max_keepalive: int = C.DEFAULT_UPSTREAM_MAX_KEEPALIVE):
        self._timeout = timeout
        self._max_body = max_body
        self._max_response = max_response
        self._max_connections = max_connections
        self._max_keepalive = max_keepalive
        self._clients: Dict[str, httpx.AsyncClient] = {}

    def _client(self, base_url: str) -> httpx.AsyncClient:
        if base_url not in self._clients:
            self._clients[base_url] = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout, connect=15.0),
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=self._max_connections,
                    max_keepalive_connections=self._max_keepalive,
                ),
                headers={"User-Agent": f"InterGate/{C.APP_VERSION}"},
            )
        return self._clients[base_url]

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()

    # ---------- 非流式 ----------
    async def forward(self, method: str, url: str, headers: Dict[str, str],
                      body: bytes | None) -> UpstreamResult:
        client = self._client(_base_of(url))
        try:
            resp = await client.request(method, url, headers=headers, content=body)
        except httpx.TimeoutException as e:
            raise UpstreamError(f"上游超时: {e}", category="timeout") from e
        except httpx.HTTPError as e:
            raise UpstreamError(f"上游连接失败: {e}", category="upstream") from e

        data = await resp.aread()
        if len(data) > self._max_response:
            raise UpstreamError("上游响应过大", status=502, category="upstream")

        result = UpstreamResult(status=resp.status_code, headers=dict(resp.headers), body=data)
        try:
            result.usage = parse_usage_from_json(data)
        except Exception:
            result.usage = {}
        if resp.status_code >= 400:
            result.error = _extract_error_message(data)
        return result

    # ---------- 流式 ----------
    async def open_stream(self, method: str, url: str, headers: Dict[str, str],
                          body: bytes | None
                          ) -> Tuple[int, Dict[str, str], AsyncIterator[bytes]]:
        """发起流式请求,返回 (status, headers, chunks 生成器)。"""
        client = self._client(_base_of(url))
        try:
            req = client.build_request(method, url, headers=headers, content=body)
            resp = await client.send(req, stream=True)
        except httpx.TimeoutException as e:
            raise UpstreamError(f"上游超时: {e}", category="timeout") from e
        except httpx.HTTPError as e:
            raise UpstreamError(f"上游连接失败: {e}", category="upstream") from e

        async def gen() -> AsyncIterator[bytes]:
            try:
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
            finally:
                await resp.aclose()

        return resp.status_code, dict(resp.headers), gen()

    # ---------- 简单 GET(模型同步) ----------
    async def get_json(self, url: str, headers: Optional[Dict[str, str]] = None
                       ) -> Optional[Dict[str, Any]]:
        client = self._client(_base_of(url))
        try:
            resp = await client.get(url, headers=headers or {})
            if resp.status_code < 400:
                return resp.json()
        except Exception as e:
            log.debug("GET JSON 失败 url=%s: %s", url, e)
            return None
        return None

    # ---------- Key 测试 ----------
    async def test_key(self, base_url: str, api_key: str) -> Tuple[bool, str]:
        url = base_url + "/models"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            client = self._client(base_url)
            resp = await client.get(url, headers=headers)
            if resp.status_code < 400:
                return True, "OK"
            # 兼容 google key 查询参数
            alt = base_url + "/v1beta/models?key=" + api_key
            r2 = await client.get(alt)
            if r2.status_code < 400:
                return True, "OK"
            body = resp.text[:200].replace("\n", " ")
            return False, f"HTTP {resp.status_code}: {body}" if body else f"HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.HTTPError) as e:
            detail = str(e) or type(e).__name__
            return False, f"{type(e).__name__}: {detail}"
        except Exception as e:
            log.warning("测试 Key 意外异常 url=%s: %s", url, e)
            detail = str(e) or type(e).__name__
            return False, f"{type(e).__name__}: {detail}"


def _base_of(url: str) -> str:
    s = urlsplit(url)
    return f"{s.scheme}://{s.netloc}"


def _extract_error_message(body: bytes) -> str:
    try:
        j = json.loads(body)
        if isinstance(j, dict):
            err = j.get("error")
            if isinstance(err, dict):
                return str(err.get("message", ""))
            if isinstance(err, str):
                return err
            return json.dumps(j, ensure_ascii=False)[:500]
    except Exception:
        pass
    return body.decode("utf-8", errors="replace")[:500]
