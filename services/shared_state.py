"""多 Worker 共享状态: 基于 SQLite 的分布式滑动窗口计数与响应缓存。

背景: 多 Worker(workers>1)时, 各进程的缓存/限流计数器彼此独立, 导致
限流额度放大 N 倍、缓存重复。本模块提供可选的 SQLite 共享后端, 让
各 worker 读写同一份计数与缓存。

注意: SQLite 写操作在极高并发下有锁竞争, 仅建议在需要跨进程一致性时开启。
单进程(workers=1)场景无需开启, 内存实现更快。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "shared_state.db")
_LOCK = threading.Lock()
_CONN: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _CONN
    if _CONN is not None:
        return _CONN
    with _LOCK:
        if _CONN is None:
            os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
            conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS counters(
                ckey TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0,
                window_start REAL NOT NULL DEFAULT 0,
                window_sec REAL NOT NULL DEFAULT 60)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS cache(
                ckey TEXT PRIMARY KEY, status INTEGER NOT NULL,
                headers TEXT NOT NULL, body BLOB NOT NULL,
                created REAL NOT NULL)""")
            conn.commit()
            _CONN = conn
    return _CONN


def cleanup_expired() -> None:
    """清理过期计数与缓存条目(后台周期调用)。"""
    try:
        conn = _get_conn()
        now_ms = int(time.time() * 1000)
        with conn:
            stale = time.time() - 600
            conn.execute("DELETE FROM counters WHERE window_start < ?", (stale,))
            conn.execute("DELETE FROM cache WHERE created < ?",
                         (time.time() - 86400,))
    except Exception:
        pass


class SharedCounter:
    """SQLite 分布式固定窗口计数器(跨进程共享限流)。

    采用固定窗口(token-bucket 近似): 窗口起始点在窗口滑过后自动重置。
    多 worker 共享同一份计数, 解决限流额度放大问题。
    """

    def __init__(self, window_sec: float = 60.0, max_entries: int = 10000):
        self.window_sec = window_sec
        self._max = max_entries
        self._lock = threading.Lock()

    def add(self, key: str, weight: int = 1) -> int:
        """记录一个(加权)事件, 返回当前窗口累计权重。"""
        conn = _get_conn()
        now = time.time()
        with self._lock:
            try:
                with conn:
                    row = conn.execute(
                        "SELECT value, window_start, window_sec FROM counters "
                        "WHERE ckey=?", (key,)).fetchone()
                    if row and now - row[1] > row[2]:
                        # 窗口已过, 重置
                        conn.execute(
                            "UPDATE counters SET value=?, window_start=? WHERE ckey=?",
                            (weight, now, key))
                        return weight
                    if row:
                        val = int(row[0]) + weight
                        conn.execute("UPDATE counters SET value=? WHERE ckey=?",
                                     (val, key))
                        return val
                    conn.execute(
                        "INSERT INTO counters(ckey, value, window_start, window_sec) "
                        "VALUES(?,?,?,?)",
                        (key, weight, now, self.window_sec))
                    return weight
            except Exception:
                # SQLite 繁忙降级为计数, 保证可用性
                return weight


class SharedCache:
    """SQLite 分布式响应缓存(跨进程共享)。"""

    def __init__(self, ttl_seconds: int = 300, max_entries: int = 500,
                 max_body_bytes: int = 1024 * 1024):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self.max_body_bytes = max_body_bytes
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(method: str, path: str, body: bytes, scope: str = "") -> str:
        """缓存键: method + path + body + 访问域(scope), 与内存版保持一致。"""
        import hashlib
        h = hashlib.sha256()
        h.update(method.encode()); h.update(b"\x00")
        h.update(path.encode()); h.update(b"\x00")
        h.update(scope.encode()); h.update(b"\x00")
        h.update(body)
        return h.hexdigest()

    def get(self, key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT status, headers, body, created FROM cache WHERE ckey=?",
                (key,)).fetchone()
            if not row or time.time() - row[3] > self.ttl:
                self.misses += 1
                return None
            self.hits += 1
            return row[0], json.loads(row[1]), bytes(row[2])
        except Exception:
            self.misses += 1
            return None

    def put(self, key: str, status: int, headers: Dict[str, str], body: bytes) -> None:
        if status < 200 or status >= 300 or len(body) > self.max_body_bytes:
            return
        conn = _get_conn()
        try:
            with self._lock:
                with conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO cache(ckey, status, headers, body, created) "
                        "VALUES(?,?,?,?,?)",
                        (key, status, json.dumps(headers, ensure_ascii=False), body,
                         time.time()))
                    # 裁剪超量条目
                    conn.execute(
                        "DELETE FROM cache WHERE ckey IN "
                        "(SELECT ckey FROM cache ORDER BY created LIMIT "
                        "MAX(0, (SELECT COUNT(*) FROM cache) - ?))",
                        (self.max_entries,))
        except Exception:
            pass

    def invalidate(self, prefix: str = "") -> int:
        conn = _get_conn()
        try:
            with conn:
                if prefix:
                    cur = conn.execute("DELETE FROM cache WHERE ckey LIKE ?",
                                       (prefix + "%",))
                else:
                    cur = conn.execute("DELETE FROM cache")
                return cur.rowcount
        except Exception:
            return 0

    def stats(self) -> Dict[str, Any]:
        conn = _get_conn()
        entries = 0
        try:
            row = conn.execute("SELECT COUNT(*) FROM cache").fetchone()
            entries = int(row[0]) if row else 0
        except Exception:
            pass
        return {"enabled": True, "entries": entries,
                "max_entries": self.max_entries, "ttl_seconds": self.ttl,
                "hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / max(1, self.hits + self.misses), 4)}
