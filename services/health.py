"""网关健康自检:探测各 Key 上游连通性,供 /healthz 与控制台状态展示。"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from crypto import aes
from providers.registry import resolve_base_url

log = logging.getLogger('intergate.health')

PROBE_TIMEOUT = 5.0
MAX_KEYS_PER_PROBE = 30


class HealthProbe:
    """对一组 ApiKey 做轻量上游连通性探测。"""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client or httpx.AsyncClient(
            timeout=PROBE_TIMEOUT, follow_redirects=True)

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()

    async def probe_key(self, key: Any) -> Dict[str, Any]:
        """探测单个 Key:GET {base}/models 是否可达。"""
        key_id = getattr(key, 'id', '?')
        name = getattr(key, 'name', '')
        provider = getattr(key, 'provider', '')
        result: Dict[str, Any] = {
            'key_id': key_id, 'name': name, 'provider': provider,
            'ok': False, 'latency_ms': 0, 'error': '',
        }
        base = resolve_base_url(provider, getattr(key, 'base_url', None))
        if not base:
            result['error'] = 'base_url 无法解析'
            return result
        plain = ''
        try:
            plain = aes.decrypt_plaintext(getattr(key, 'encrypted_key', ''))
        except Exception as exc:
            result['error'] = f'密钥解密失败: {exc}'
            return result
        if not plain:
            result['error'] = '密钥为空'
            return result
        url = base + '/models'
        headers = {'Authorization': f'Bearer {plain}'}
        if provider == 'google':
            url = base + '/v1beta/models?key=' + plain
            headers = {}
        start = time.monotonic()
        try:
            resp = await self._client.get(url, headers=headers)
            latency = int((time.monotonic() - start) * 1000)
            result['latency_ms'] = latency
            if resp.status_code < 400:
                result['ok'] = True
            else:
                result['error'] = f'HTTP {resp.status_code}'
        except httpx.TimeoutException:
            result['error'] = '连接超时'
        except httpx.HTTPError as exc:
            result['error'] = f'连接失败: {exc}'
        except Exception as exc:
            result['error'] = f'探测异常: {exc}'
        return result

    async def probe_all(self, keys: List[Any]) -> List[Dict[str, Any]]:
        """并发探测全部 Key(最多 MAX_KEYS_PER_PROBE 个)。"""
        results = await asyncio.gather(
            *(self.probe_key(k) for k in keys[:MAX_KEYS_PER_PROBE]))
        return list(results)

    @staticmethod
    def summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(results)
        ok = sum(1 for r in results if r.get('ok'))
        latencies = [r.get('latency_ms', 0) for r in results if r.get('ok')]
        avg = int(sum(latencies) / len(latencies)) if latencies else 0
        return {
            'total': total, 'ok': ok, 'failed': total - ok,
            'up_rate': round(ok / total, 3) if total else 0.0,
            'avg_latency_ms': avg,
        }
