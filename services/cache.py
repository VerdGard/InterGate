"""响应缓存:内存 LRU,缓存幂等 2xx 响应(对齐 RelayGo CacheManager)。"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass
class CacheEntry:
    status: int
    headers: Dict[str, str]
    body: bytes
    created: float = field(default_factory=time.time)


class ResponseCache:
    """内存 LRU 缓存。

    设计说明: 缓存为瞬时数据, 重启后清空。
    这是有意设计——缓存命中仅用于降低重复请求成本,
    不保证数据持久性。命中率统计同样为运行时数据。
    """
    def __init__(self, enabled: bool = True, ttl_seconds: int = 300,
                 max_entries: int = 500, max_body_bytes: int = 1024 * 1024):
        self.enabled = enabled
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self.max_body_bytes = max_body_bytes
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(method: str, path: str, body: bytes, scope: str = "") -> str:
        """缓存键: method + path + body + 访问域(scope)。

        scope 用于隔离不同租户/凭证的响应, 避免跨租户命中他人数据。
        """
        h = hashlib.sha256()
        h.update(method.encode())
        h.update(b"\x00")
        h.update(path.encode())
        h.update(b"\x00")
        h.update(scope.encode())
        h.update(b"\x00")
        h.update(body)
        return h.hexdigest()

    def get(self, key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        if not self.enabled:
            self.misses += 1
            return None
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return None
            if time.time() - entry.created > self.ttl:
                self._store.pop(key, None)
                self.misses += 1
                return None
            self._store.move_to_end(key)
            self.hits += 1
            return entry.status, dict(entry.headers), entry.body

    def put(self, key: str, status: int, headers: Dict[str, str], body: bytes) -> None:
        if not self.enabled:
            return
        if status < 200 or status >= 300:
            return
        if len(body) > self.max_body_bytes:
            return
        with self._lock:
            self._store[key] = CacheEntry(status, headers, body)
            self._store.move_to_end(key)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    def invalidate(self, prefix: str = "") -> int:
        with self._lock:
            keys = [k for k in self._store if k.startswith(prefix)] if prefix else list(self._store)
            for k in keys:
                self._store.pop(k, None)
            return len(keys)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "entries": len(self._store),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / max(1, self.hits + self.misses), 4),
            }
