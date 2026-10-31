"""SQLite 持久化:api_keys / settings / request_logs / stats_daily。

线程安全:单连接 + 全局锁;所有操作均为同步短事务。
"""
from __future__ import annotations

import atexit
import datetime
import json
import logging
import os
import sqlite3
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

DB_FILE = "data/intergate.db"
_lock = threading.Lock()
_db: Optional["Database"] = None


class Database:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # WAL + NORMAL 大幅提升并发读写; busy_timeout 避免多进程写锁互相快速失败
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA busy_timeout=10000;")
        except sqlite3.Error as e:
            logging.getLogger("intergate.db").warning("SQLite 调优失败: %s", e)
        self._lock = threading.Lock()
        self._init_schema()
        # 后台批量写:频率高的写操作(日志/统计/用量)先进队列, 攒批一次性落库,
        # 避免同步写阻塞事件循环。低频管理写仍走原同步方法保证即时可见。
        # 后台批量写: 频率高的写(日志/统计/用量)先进队列, 由独立写线程攒批落库,
        # 避免同步写阻塞事件循环, 也用独立写连接避免与读线程共享同一连接引发
        # WAL 快照不可见问题。低频管理写仍走 self._conn 同步(即时可见)。
        self._write_conn = sqlite3.connect(path, check_same_thread=False, timeout=10.0)
        self._write_conn.row_factory = sqlite3.Row
        try:
            self._write_conn.execute("PRAGMA journal_mode=WAL;")
            self._write_conn.execute("PRAGMA synchronous=NORMAL;")
            self._write_conn.execute("PRAGMA busy_timeout=10000;")
        except sqlite3.Error as e:
            logging.getLogger("intergate.db").warning("SQLite 写连接调优失败: %s", e)
        self._batch_lock = threading.Lock()
        self._batch_pending: Deque[tuple] = deque()
        self._batch_wake = threading.Event()
        self._flush_wait = False          # 是否有调用方在等本次冲刷完成
        self._flush_done = threading.Event()
        self._cache_stats_ts: Optional[float] = None
        self._cache_stats_val: Optional[Dict[str, Any]] = None
        self._writer = threading.Thread(target=self._batch_writer_loop,
                                        daemon=True, name="intergate-db-writer")
        self._writer.start()
        with _BATCH_REG_LOCK:
            _BATCH_INSTANCES.append(self)

    # ---------- schema ----------
    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    provider_id TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    base_url TEXT,
                    grp TEXT NOT NULL DEFAULT '',
                    priority INTEGER NOT NULL DEFAULT 100,
                    weight INTEGER NOT NULL DEFAULT 1,
                    max_requests_per_minute INTEGER NOT NULL DEFAULT 60,
                    daily_quota INTEGER NOT NULL DEFAULT 1000000,
                    used_today INTEGER NOT NULL DEFAULT 0,
                    used_month INTEGER NOT NULL DEFAULT 0,
                    requests_today INTEGER NOT NULL DEFAULT 0,
                    requests_month INTEGER NOT NULL DEFAULT 0,
                    errors_today INTEGER NOT NULL DEFAULT 0,
                    day_stamp TEXT NOT NULL DEFAULT '',
                    month_stamp TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    last_tested INTEGER,
                    test_result TEXT,
                    test_error TEXT,
                    created_at INTEGER NOT NULL,
                    last_used INTEGER NOT NULL DEFAULT 0,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    cooldown_until INTEGER,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    provider TEXT NOT NULL DEFAULT '',
                    key_id TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    latency_ms INTEGER NOT NULL DEFAULT 0,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    cached INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS model_states (
                    model_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS model_routes (
                    model TEXT PRIMARY KEY,
                    key_ids_json TEXT NOT NULL DEFAULT '[]',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    note TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS stats_daily (
                    date TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    cost_usd REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (date, provider, key_id)
                );
                CREATE INDEX IF NOT EXISTS idx_logs_ts ON request_logs(ts);
                CREATE INDEX IF NOT EXISTS idx_keys_provider ON api_keys(provider);

                -- 告警持久化(QuotaMonitor 重启后可恢复)
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    type TEXT NOT NULL DEFAULT '',
                    key_id TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL DEFAULT '',
                    acknowledged INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

                -- 模型列表缓存(ModelSyncer 重启后可恢复, 避免冷启动无模型)
                CREATE TABLE IF NOT EXISTS model_cache (
                    model_key TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    base_url TEXT NOT NULL DEFAULT '',
                    source_key TEXT NOT NULL DEFAULT '',
                    source_keys_json TEXT NOT NULL DEFAULT '[]',
                    sources_json TEXT NOT NULL DEFAULT '[]',
                    owned_by TEXT NOT NULL DEFAULT '',
                    created INTEGER,
                    capabilities_json TEXT NOT NULL DEFAULT '[]',
                    enabled INTEGER NOT NULL DEFAULT 1
                );

                -- 失败请求审计
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    path TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '',
                    status INTEGER NOT NULL DEFAULT 0,
                    provider TEXT NOT NULL DEFAULT '',
                    key_id TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

                -- 租户 Token(多租户额度凭证)
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    token TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    daily_quota_usd REAL NOT NULL DEFAULT 0,
                    max_requests_per_minute INTEGER NOT NULL DEFAULT 0,
                    models_json TEXT NOT NULL DEFAULT '[]',
                    provider TEXT NOT NULL DEFAULT '',
                    used_today_usd REAL NOT NULL DEFAULT 0,
                    requests_today INTEGER NOT NULL DEFAULT 0,
                    day_stamp TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at INTEGER NOT NULL,
                    last_used INTEGER NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT ''
                );
                """
                
            )
            self._conn.commit()

    # ---------- settings ----------
    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT value_json FROM settings WHERE key=?", (key,)
            ).fetchone()
        if row is None:
            return default
        return json.loads(row["value_json"])

    def set_setting(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key,value_json) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                (key, json.dumps(value, ensure_ascii=False)),
            )
            self._conn.commit()

    # ---------- model states ----------
    def get_model_states(self) -> Dict[str, bool]:
        """读取全部模型的开关状态(model_id -> enabled)。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT model_id, enabled FROM model_states"
            ).fetchall()
        return {r["model_id"]: bool(r["enabled"]) for r in rows}

    def set_model_state(self, model_id: str, enabled: bool) -> None:
        """持久化单个模型的开关状态。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO model_states(model_id, enabled) VALUES(?,?) "
                "ON CONFLICT(model_id) DO UPDATE SET enabled=excluded.enabled",
                (model_id, 1 if enabled else 0),
            )
            self._conn.commit()

    # ---------- model routes ----------
    def get_routes(self) -> Dict[str, Dict[str, Any]]:
        """读取全部模型路由规则(model -> {key_ids, enabled, note})。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT model, key_ids_json, enabled, note, updated_at FROM model_routes"
            ).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            try:
                key_ids = json.loads(r["key_ids_json"])
            except Exception:
                key_ids = []
            out[r["model"]] = {
                "key_ids": key_ids,
                "enabled": bool(r["enabled"]),
                "note": r["note"],
                "updated_at": r["updated_at"],
            }
        return out

    def set_route(self, model: str, key_ids: List[str], enabled: bool = True,
                  note: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO model_routes(model,key_ids_json,enabled,note,updated_at) "
                "VALUES(?,?,?,?,?) "
                "ON CONFLICT(model) DO UPDATE SET "
                "key_ids_json=excluded.key_ids_json, enabled=excluded.enabled, "
                "note=excluded.note, updated_at=excluded.updated_at",
                (model, json.dumps(key_ids, ensure_ascii=False),
                 1 if enabled else 0, note, int(time.time() * 1000)),
            )
            self._conn.commit()

    def delete_route(self, model: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM model_routes WHERE model=?", (model,))
            self._conn.commit()

    # ---------- api keys ----------
    def upsert_key(self, d: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    id, provider, encrypted_key, name, provider_id, note, base_url, grp,
                    priority, weight, max_requests_per_minute, daily_quota,
                    used_today, used_month, requests_today, requests_month, errors_today,
                    day_stamp, month_stamp, status, last_tested, test_result, test_error,
                    created_at, last_used, failure_count, cooldown_until, metadata_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    provider=excluded.provider,
                    encrypted_key=excluded.encrypted_key,
                    name=excluded.name,
                    provider_id=excluded.provider_id,
                    note=excluded.note,
                    base_url=excluded.base_url,
                    grp=excluded.grp,
                    priority=excluded.priority,
                    weight=excluded.weight,
                    max_requests_per_minute=excluded.max_requests_per_minute,
                    daily_quota=excluded.daily_quota,
                    used_today=excluded.used_today,
                    used_month=excluded.used_month,
                    requests_today=excluded.requests_today,
                    requests_month=excluded.requests_month,
                    errors_today=excluded.errors_today,
                    day_stamp=excluded.day_stamp,
                    month_stamp=excluded.month_stamp,
                    status=excluded.status,
                    last_tested=excluded.last_tested,
                    test_result=excluded.test_result,
                    test_error=excluded.test_error,
                    last_used=excluded.last_used,
                    failure_count=excluded.failure_count,
                    cooldown_until=excluded.cooldown_until,
                    metadata_json=excluded.metadata_json
                """,
                (
                    d["id"], d["provider"], d["encrypted_key"], d["name"], d["provider_id"],
                    d["note"], d.get("base_url"), d["grp"], d["priority"], d["weight"],
                    d["max_requests_per_minute"], d["daily_quota"], d["used_today"],
                    d["used_month"], d["requests_today"], d["requests_month"],
                    d["errors_today"], d["day_stamp"], d["month_stamp"], d["status"],
                    d.get("last_tested"), d.get("test_result"), d.get("test_error"),
                    d["created_at"], d["last_used"], d["failure_count"],
                    d.get("cooldown_until"), d.get("metadata_json", "{}"),
                ),
            )
            self._conn.commit()

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE id=?", (key_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_keys(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM api_keys ORDER BY provider, priority, created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_key(self, key_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
            self._conn.commit()

    # ---------- request logs ----------
    def insert_log(self, d: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(_SQL_INSERT_LOG, _log_row(d))
            self._conn.commit()

    # ---------- 后台批量写(热路径) ----------
    def enqueue_log(self, d: Dict[str, Any]) -> None:
        """异步入队一条请求日志(批量落库, 不阻塞事件循环)。"""
        with self._batch_lock:
            self._batch_pending.append(("log", d))
        self._batch_wake.set()

    def enqueue_stats(self, date: str, provider: str, key_id: str,
                      requests: int = 0, errors: int = 0,
                      prompt_tokens: int = 0, completion_tokens: int = 0,
                      cost_usd: float = 0.0) -> None:
        """异步入队一条日统计(按 pk 累加, 批量落库)。"""
        with self._batch_lock:
            self._batch_pending.append((
                "stats", (date, provider, key_id, requests, errors,
                          prompt_tokens, completion_tokens, cost_usd)))
        self._batch_wake.set()

    def enqueue_key(self, d: Dict[str, Any]) -> None:
        """异步入队一次 Key 全字段写回(批量落库)。"""
        with self._batch_lock:
            self._batch_pending.append(("key", d))
        self._batch_wake.set()

    def _batch_writer_loop(self) -> None:
        wc = self._write_conn          # 仅本线程使用, 无竞争
        while True:
            self._batch_wake.wait(0.25)
            self._batch_wake.clear()
            self._write_flush(wc)
            with self._batch_lock:
                wait = self._flush_wait
                self._flush_wait = False
            if wait:
                self._flush_done.set()

    def _write_flush(self, wc: sqlite3.Connection) -> None:
        with self._batch_lock:
            if not self._batch_pending:
                return
            items = list(self._batch_pending)
            self._batch_pending.clear()
        if not items:
            return
        logs = [d for k, d in items if k == "log"]
        stats = [a for k, a in items if k == "stats"]
        keys = [d for k, d in items if k == "key"]
        # 三类写各自独立提交: 某类失败(如单条违反约束)不能连带丢弃其它类
        self._flush_group(wc, "log", logs,
                          lambda rows: wc.executemany(
                              _SQL_INSERT_LOG, [_log_row(d) for d in rows]))
        self._flush_group(wc, "stats", stats,
                          lambda rows: wc.executemany(_SQL_UPSERT_STATS, rows))
        self._flush_group(wc, "key", keys,
                          lambda rows: wc.executemany(
                              _SQL_UPSERT_KEY, [_key_row(d) for d in rows]))

    def _flush_group(self, wc: sqlite3.Connection, kind: str, rows: list,
                     write) -> None:
        """落库一类批量写。整批失败时逐条重试, 只丢弃真正非法的单条。"""
        if not rows:
            return
        logr = logging.getLogger("intergate.db")
        try:
            write(rows)
            wc.commit()
            return
        except Exception as e:
            try:
                wc.rollback()
            except Exception:
                pass
            logr.warning("批量落库 %s 失败(%d 条), 降级逐条重试: %s",
                         kind, len(rows), e)
        dropped = 0
        for row in rows:
            try:
                write([row])
                wc.commit()
            except Exception as e:
                try:
                    wc.rollback()
                except Exception:
                    pass
                dropped += 1
                if dropped <= 5:
                    logr.warning("丢弃 1 条 %s 记录: %s", kind, e)
        if dropped:
            logr.warning("%s 共丢弃 %d/%d 条非法记录", kind, dropped, len(rows))

    def flush_now(self, timeout: float = 5.0) -> None:
        """冲刷积压的批量写并等待落库完成(供测试/优雅关闭同步检查)。"""
        with self._batch_lock:
            self._flush_wait = True
        if self._batch_pending:
            self._batch_wake.set()
        else:
            self._batch_wake.set()      # 确保 writer 醒来确认(即便无数据)
        self._flush_done.wait(timeout)
        self._flush_done.clear()

    def query_logs(self, limit: int = 200, offset: int = 0,
                   provider: str = "", status: Optional[int] = None,
                   key_id: str = "", model: str = "",
                   ts_from: Optional[int] = None, ts_to: Optional[int] = None,
                   before_ts: Optional[int] = None,
                   total: bool = False) -> List[Dict[str, Any]]:
        """查询请求日志,支持时间范围/提供商/状态/Key/模型过滤与分页。

        before_ts: 游标分页(仅返回 ts < before_ts 的旧日志, 规避 OFFSET 深翻页慢)。
        total=True 时返回 (rows, count) 两元组。
        """
        where = "WHERE 1=1"
        args: List[Any] = []
        if provider:
            where += " AND provider=?"
            args.append(provider)
        if status is not None:
            where += " AND status=?"
            args.append(status)
        if key_id:
            where += " AND key_id=?"
            args.append(key_id)
        if model:
            where += " AND model LIKE ?"
            args.append(f"%{model}%")
        if ts_from is not None:
            where += " AND ts>=?"
            args.append(ts_from)
        if ts_to is not None:
            where += " AND ts<=?"
            args.append(ts_to)
        if before_ts is not None:
            where += " AND ts<?"
            args.append(before_ts)
        count = 0
        if total:
            with self._lock:
                row = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM request_logs {where}", args).fetchone()
            count = int(row["n"])
        sql = f"SELECT * FROM request_logs {where} ORDER BY ts DESC LIMIT ? OFFSET ?"
        args2 = args + [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, args2).fetchall()
        out = [dict(r) for r in rows]
        return (out, count) if total else out

    def clear_logs(self) -> int:
        """清空全部请求日志,返回删除条数。"""
        with self._lock:
            cur = self._conn.execute("DELETE FROM request_logs")
            self._conn.commit()
            return cur.rowcount

    def token_usage_since(self, ts_ms: int) -> List[Dict[str, Any]]:
        """按模型聚合 ts>=ts_ms 的成功请求(2xx/3xx) token 用量,用于价格预估。"""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT COALESCE(model,'') AS model,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens
                FROM request_logs
                WHERE status < 400 AND ts >= ?
                GROUP BY model
                ORDER BY (SUM(prompt_tokens) + SUM(completion_tokens)) DESC
                """,
                (ts_ms,),
            ).fetchall()
        return [dict(r) for r in rows]

    def token_usage_by_model(self, days: int = 7) -> List[Dict[str, Any]]:
        """近 N 天按模型聚合成功请求 token 用量(便捷封装)。"""
        return self.token_usage_since(int(time.time() * 1000) - days * 86400 * 1000)

    def hourly_trend(self, hours: int = 24) -> List[Dict[str, Any]]:
        """近 N 小时按小时聚合 request_logs, 用于 24 小时用量趋势。

        桶按绝对小时(ts/3600000)对齐, 返回 bucket(小时 epoch)、请求/错误/token。
        由调用方(webapp)补齐缺失小时并生成本地时间标签。
        """
        since = int(time.time() * 1000) - hours * 3600 * 1000
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT CAST(ts/3600000 AS INTEGER) AS bucket,
                       COUNT(*) AS requests,
                       COALESCE(SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),0) AS errors,
                       COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,
                       COALESCE(SUM(completion_tokens),0) AS completion_tokens
                FROM request_logs
                WHERE ts >= ?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (since,),
            ).fetchall()
        return [dict(r) for r in rows]

    def cache_stats_today(self, ttl: float = 3.0) -> Dict[str, Any]:
        """今日缓存命中统计(带短 TTL 缓存)。

        /api/status、健康检查等高频调用会触发, 全表扫今日日志在当前量级下
        有开销, 加 3 秒内存缓存避免每次刷新都聚合。日志由后台批量写入,
        3 秒内的延时在概览场景下可接受。
        """
        now = time.monotonic()
        if self._cache_stats_ts is not None and now - self._cache_stats_ts < ttl:
            return self._cache_stats_val
        import datetime as _dt
        today0 = int(_dt.datetime.combine(_dt.date.today(), _dt.time.min).timestamp() * 1000)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN cached=1 THEN 1 ELSE 0 END),0) AS hits
                FROM request_logs WHERE ts >= ?
                """,
                (today0,),
            ).fetchone()
        total = row["total"] or 0
        hits = row["hits"] or 0
        result = {"requests_today": total, "hits_today": hits,
                  "hit_rate_today": round(hits / total, 4) if total else 0.0}
        self._cache_stats_ts = now
        self._cache_stats_val = result
        return result

    def prune_logs(self, retention_days: int, max_entries: int) -> int:
        with self._lock:
            cutoff = int(time.time() * 1000) - retention_days * 86400 * 1000
            cur = self._conn.execute(
                "DELETE FROM request_logs WHERE ts < ?", (cutoff,)
            )
            n = cur.rowcount
            self._conn.execute(
                "DELETE FROM request_logs WHERE id NOT IN "
                "(SELECT id FROM request_logs ORDER BY ts DESC LIMIT ?)",
                (max_entries,),
            )
            self._conn.commit()
            return n

    # ---------- stats ----------
    def upsert_stats(self, date: str, provider: str, key_id: str,
                     requests: int = 0, errors: int = 0,
                     prompt_tokens: int = 0, completion_tokens: int = 0,
                     cost_usd: float = 0.0) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO stats_daily(date, provider, key_id, requests, errors,
                                        prompt_tokens, completion_tokens, cost_usd)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(date, provider, key_id) DO UPDATE SET
                    requests=stats_daily.requests+excluded.requests,
                    errors=stats_daily.errors+excluded.errors,
                    prompt_tokens=stats_daily.prompt_tokens+excluded.prompt_tokens,
                    completion_tokens=stats_daily.completion_tokens+excluded.completion_tokens,
                    cost_usd=stats_daily.cost_usd+excluded.cost_usd
                """,
                (date, provider, key_id, requests, errors,
                 prompt_tokens, completion_tokens, cost_usd),
            )
            self._conn.commit()

    def stats_range(self, date_from: str, date_to: str) -> List[Dict[str, Any]]:
        """按日期范围返回每日统计明细(用于导出 CSV 与趋势图)。"""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT date, provider, key_id,
                       SUM(requests) AS requests, SUM(errors) AS errors,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens,
                       SUM(cost_usd) AS cost_usd
                FROM stats_daily
                WHERE date >= ? AND date <= ?
                GROUP BY date, provider, key_id
                ORDER BY date
                """,
                (date_from, date_to),
            ).fetchall()
        return [dict(r) for r in rows]

    def stats_summary(self, days: int = 7) -> Dict[str, Any]:
        # 用本地日期而非 SQLite 的 UTC date('now'), 与 webapp 趋势/导出口径一致
        import datetime as _dt
        end = _dt.date.today()
        start = end - _dt.timedelta(days=days - 1)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT provider, SUM(requests) AS requests, SUM(errors) AS errors,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens,
                       SUM(cost_usd) AS cost_usd
                FROM stats_daily
                WHERE date >= ? AND date <= ?
                GROUP BY provider ORDER BY requests DESC
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
            total = self._conn.execute(
                """
                SELECT COALESCE(SUM(requests),0) AS requests,
                       COALESCE(SUM(errors),0) AS errors,
                       COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,
                       COALESCE(SUM(completion_tokens),0) AS completion_tokens,
                       COALESCE(SUM(cost_usd),0) AS cost_usd
                FROM stats_daily WHERE date >= ? AND date <= ?
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchone()
        return {
            "providers": [dict(r) for r in rows],
            "total": dict(total),
        }


    # ---------- alerts ----------
    def insert_alert(self, ts: int, alert_type: str, key_id: str,
                     provider: str, message: str) -> int:
        """持久化一条告警记录, 返回自增 ID。"""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts(ts, type, key_id, provider, message) "
                "VALUES(?,?,?,?,?)",
                (ts, alert_type, key_id, provider, message),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_alerts(self, limit: int = 200) -> List[Dict[str, Any]]:
        """查询最近的告警记录(按时间倒序)。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_alerts(self, max_count: int = 200) -> int:
        """裁剪告警表, 仅保留最近 max_count 条。"""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM alerts WHERE id NOT IN "
                "(SELECT id FROM alerts ORDER BY ts DESC LIMIT ?)",
                (max_count,),
            )
            self._conn.commit()
            return cur.rowcount

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def clear_alerts(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alerts")
            self._conn.commit()
            return cur.rowcount

    # ---------- model cache ----------
    def save_model_cache(self, models: List[Dict[str, Any]]) -> int:
        """全量覆盖模型缓存表(同步后调用)。"""
        import json as _json
        with self._lock:
            self._conn.execute("DELETE FROM model_cache")
            for m in models:
                mkey = f"{m.get('id','')}|{m.get('source','')}|{m.get('base_url','')}"
                self._conn.execute(
                    """INSERT OR REPLACE INTO model_cache
                    (model_key, model_id, name, provider, source, base_url,
                     source_key, source_keys_json, sources_json, owned_by,
                     created, capabilities_json, enabled)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (mkey, m.get("id", ""), m.get("name", ""), m.get("provider", ""),
                     m.get("source", ""), m.get("base_url", ""),
                     m.get("source_key", ""),
                     _json.dumps(m.get("source_keys", []), ensure_ascii=False),
                     _json.dumps(m.get("sources", []), ensure_ascii=False),
                     m.get("owned_by", ""), m.get("created"),
                     _json.dumps(m.get("capabilities", []), ensure_ascii=False),
                     1 if m.get("enabled", True) else 0),
                )
            self._conn.commit()
            return len(models)

    def load_model_cache(self) -> List[Dict[str, Any]]:
        """加载缓存的模型列表(重启后可立即恢复)。"""
        import json as _json
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM model_cache"
            ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["model_id"],
                "name": r["name"],
                "provider": r["provider"],
                "source": r["source"],
                "base_url": r["base_url"],
                "source_key": r["source_key"],
                "source_keys": _json.loads(r["source_keys_json"]),
                "sources": _json.loads(r["sources_json"]),
                "owned_by": r["owned_by"],
                "created": r["created"],
                "capabilities": _json.loads(r["capabilities_json"]),
                "enabled": bool(r["enabled"]),
            })
        return out

    def set_model_cache_enabled(self, model_id: str, enabled: bool) -> None:
        """更新模型缓存中的开关状态。"""
        with self._lock:
            self._conn.execute(
                "UPDATE model_cache SET enabled=? WHERE model_id=?",
                (1 if enabled else 0, model_id),
            )
            self._conn.commit()


    # ---------- 租户 Token ----------
    def list_tokens(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tokens ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE id=?", (token_id,)).fetchone()
        return dict(row) if row else None

    def upsert_token(self, d: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tokens (id, name, token, enabled, daily_quota_usd,
                    max_requests_per_minute, models_json, provider,
                    used_today_usd, requests_today, day_stamp, status,
                    created_at, last_used, note)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, token=excluded.token,
                    enabled=excluded.enabled,
                    daily_quota_usd=excluded.daily_quota_usd,
                    max_requests_per_minute=excluded.max_requests_per_minute,
                    models_json=excluded.models_json,
                    provider=excluded.provider,
                    status=excluded.status, note=excluded.note
                """,
                (d["id"], d["name"], d["token"], 1 if d["enabled"] else 0,
                 d["daily_quota_usd"], d["max_requests_per_minute"],
                 json.dumps(d["models"], ensure_ascii=False), d["provider"],
                 d["used_today_usd"], d["requests_today"], d["day_stamp"],
                 d["status"], d["created_at"], d["last_used"], d["note"]),
            )
            self._conn.commit()

    def delete_token(self, token_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM tokens WHERE id=?", (token_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def record_token_usage(self, token_id: str, cost_usd: float,
                           requests: int = 1) -> None:
        """按天累计租户用量, 跨天自动归零。"""
        today = datetime.date.today().isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT used_today_usd, requests_today, day_stamp "
                "FROM tokens WHERE id=?", (token_id,)).fetchone()
            if not row:
                return
            used = 0.0 if row["day_stamp"] != today else float(row["used_today_usd"])
            req = 0 if row["day_stamp"] != today else int(row["requests_today"])
            self._conn.execute(
                "UPDATE tokens SET used_today_usd=?, requests_today=?, "
                "day_stamp=?, last_used=? WHERE id=?",
                (used + cost_usd, req + requests, today,
                 int(time.time() * 1000), token_id))
            self._conn.commit()

    def insert_audit(self, d: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_logs(ts, path, method, status, provider, "
                "key_id, model, error, body) VALUES(?,?,?,?,?,?,?,?,?)",
                (int(d["ts"]), d["path"], d["method"], int(d["status"]),
                 d.get("provider", ""), d.get("key_id", ""), d.get("model", ""),
                 d.get("error", "")[:500], d.get("body", "")),
            )
            self._conn.commit()

    def query_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_logs ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def clear_audit(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM audit_logs")
            self._conn.commit()
            return cur.rowcount

_SQL_INSERT_LOG = """
    INSERT INTO request_logs (
        ts, path, method, status, provider, key_id, model, latency_ms,
        prompt_tokens, completion_tokens, total_tokens, cached, error
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
"""

_SQL_UPSERT_STATS = """
    INSERT INTO stats_daily(date, provider, key_id, requests, errors,
                            prompt_tokens, completion_tokens, cost_usd)
    VALUES (?,?,?,?,?,?,?,?)
    ON CONFLICT(date, provider, key_id) DO UPDATE SET
        requests=stats_daily.requests+excluded.requests,
        errors=stats_daily.errors+excluded.errors,
        prompt_tokens=stats_daily.prompt_tokens+excluded.prompt_tokens,
        completion_tokens=stats_daily.completion_tokens+excluded.completion_tokens,
        cost_usd=stats_daily.cost_usd+excluded.cost_usd
"""

_SQL_UPSERT_KEY = """
    INSERT INTO api_keys (
        id, provider, encrypted_key, name, provider_id, note, base_url, grp,
        priority, weight, max_requests_per_minute, daily_quota,
        used_today, used_month, requests_today, requests_month, errors_today,
        day_stamp, month_stamp, status, last_tested, test_result, test_error,
        created_at, last_used, failure_count, cooldown_until, metadata_json
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
        provider=excluded.provider, encrypted_key=excluded.encrypted_key,
        name=excluded.name, provider_id=excluded.provider_id, note=excluded.note,
        base_url=excluded.base_url, grp=excluded.grp, priority=excluded.priority,
        weight=excluded.weight, max_requests_per_minute=excluded.max_requests_per_minute,
        daily_quota=excluded.daily_quota,
        used_today=excluded.used_today, used_month=excluded.used_month,
        requests_today=excluded.requests_today, requests_month=excluded.requests_month,
        errors_today=excluded.errors_today,
        day_stamp=excluded.day_stamp, month_stamp=excluded.month_stamp,
        status=excluded.status, last_tested=excluded.last_tested,
        test_result=excluded.test_result, test_error=excluded.test_error,
        last_used=excluded.last_used, failure_count=excluded.failure_count,
        cooldown_until=excluded.cooldown_until, metadata_json=excluded.metadata_json
"""


def _log_row(d: Dict[str, Any]) -> tuple:
    # model 等列在 schema 中是 NOT NULL, 而 /v1/models 等请求没有 model 字段,
    # 传 None 会触发 IntegrityError 并(修复前)连带丢弃整批写。
    return (d["ts"], d["path"], d["method"], d["status"], d.get("provider") or "",
            d.get("key_id") or "", d.get("model") or "", d.get("latency_ms", 0),
            d.get("prompt_tokens", 0), d.get("completion_tokens", 0),
            d.get("total_tokens", 0), 1 if d.get("cached") else 0,
            d.get("error") or "")


def _key_row(d: Dict[str, Any]) -> tuple:
    return (d["id"], d["provider"], d["encrypted_key"], d["name"], d["provider_id"],
            d["note"], d.get("base_url"), d["grp"], d["priority"], d["weight"],
            d["max_requests_per_minute"], d["daily_quota"], d["used_today"],
            d["used_month"], d["requests_today"], d["requests_month"],
            d["errors_today"], d["day_stamp"], d["month_stamp"], d["status"],
            d.get("last_tested"), d.get("test_result"), d.get("test_error"),
            d["created_at"], d["last_used"], d["failure_count"],
            d.get("cooldown_until"), d.get("metadata_json", "{}"))


# 全局待刷盘数据库实例,异常退出(如多进程被 terminate)也能尽量冲刷
_BATCH_INSTANCES = []
_BATCH_REG_LOCK = threading.Lock()


def _flush_all_instances() -> None:
    for inst in list(_BATCH_INSTANCES):
        try:
            inst.flush_now()
        except Exception:
            pass


# SQLite 写操作不保证在 atexit/退出时自动执行, 注册兜底冲刷
atexit.register(_flush_all_instances)



def get_db() -> Database:
    global _db
    if _db is None:
        base = os.environ.get("INTERGATE_DATA_DIR") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
        )
        _db = Database(os.path.join(base, "intergate.db"))
    return _db
