"""租户 Token 管理:加密存取、鉴权索引、额度/限流检查与用量累计。"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from crypto.aes import encrypt_plaintext, decrypt_plaintext
from db.database import Database
from models.api_token import ApiToken, TokenStatus

log = logging.getLogger("intergate.token_manager")


class TokenManager:
    def __init__(self, db: Database):
        self._db = db
        self._lock = threading.RLock()
        self._cache: Dict[str, ApiToken] = {}
        # token 密文 -> id 的索引(鉴权 O(1))
        self._index: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        with self._lock:
            try:
                for row in self._db.list_tokens():
                    t = ApiToken(
                        id=row["id"], name=row["name"], token=row["token"],
                        enabled=bool(row["enabled"]),
                        daily_quota_usd=float(row["daily_quota_usd"] or 0),
                        max_requests_per_minute=int(row["max_requests_per_minute"] or 0),
                        models=json.loads(row.get("models_json") or "[]"),
                        provider=row.get("provider", ""),
                        used_today_usd=float(row.get("used_today_usd") or 0),
                        requests_today=int(row.get("requests_today") or 0),
                        day_stamp=row.get("day_stamp", ""),
                        status=row.get("status", TokenStatus.ACTIVE),
                        created_at=row.get("created_at"),
                        last_used=int(row.get("last_used") or 0),
                        note=row.get("note", ""),
                    )
                    self._cache[t.id] = t
                    # 预建 hash 索引, 重启后首次鉴权无需全表解密扫描
                    try:
                        self._index[_hash(decrypt_plaintext(t.token))] = t.id
                    except Exception:
                        pass  # 解密失败(密钥不匹配等)的 Token 不入索引
            except Exception as e:
                log.warning("加载租户 Token 失败: %s", e)

    # ---------- CRUD ----------
    def add(self, name: str, plain_token: str = "", enabled: bool = True,
            daily_quota_usd: float = 0.0, max_requests_per_minute: int = 0,
            models: Optional[List[str]] = None, provider: str = "",
            note: str = "") -> ApiToken:
        """新增 Token。plain_token 为空时自动生成。"""
        plain = (plain_token or _gen_token()).strip()
        if plain and _hash(plain) in self._index:
            raise ValueError("该 Token 明文已存在, 请更换")
        t = ApiToken(
            name=name, token=encrypt_plaintext(plain),
            enabled=enabled, daily_quota_usd=daily_quota_usd,
            max_requests_per_minute=max_requests_per_minute,
            models=models or [], provider=provider, note=note,
            status=TokenStatus.ACTIVE,
        )
        with self._lock:
            self._db.upsert_token(t.to_dict())
            self._cache[t.id] = t
            self._index[_hash(plain)] = t.id
        t._plain = plain
        return t

    def update(self, t: ApiToken, plain_token: Optional[str] = None,
               enabled: Optional[bool] = None, daily_quota_usd: Optional[float] = None,
               max_requests_per_minute: Optional[int] = None,
               models: Optional[List[str]] = None, provider: Optional[str] = None,
               note: Optional[str] = None, reset_usage: bool = False) -> ApiToken:
        with self._lock:
            if plain_token:
                new_plain = plain_token.strip()
                if _hash(new_plain) in self._index:
                    existing = self._cache.get(self._index[_hash(new_plain)])
                    if existing and existing.id != t.id:
                        raise ValueError("该 Token 明文已存在, 请更换")
                # 移除旧明文的 hash(修复: 原实现误删新 hash, 旧 token 轮换后仍可鉴权)
                try:
                    old_hash = _hash(decrypt_plaintext(t.token))
                    if self._index.get(old_hash) == t.id:
                        self._index.pop(old_hash, None)
                except Exception:
                    pass
                t.token = encrypt_plaintext(new_plain)
            if enabled is not None:
                t.enabled = enabled
            if daily_quota_usd is not None:
                t.daily_quota_usd = daily_quota_usd
            if max_requests_per_minute is not None:
                t.max_requests_per_minute = max_requests_per_minute
            if models is not None:
                t.models = models
            if provider is not None:
                t.provider = provider
            if note is not None:
                t.note = note
            if reset_usage:
                t.used_today_usd = 0.0
                t.requests_today = 0
                t.day_stamp = ""
            if plain_token:
                self._index[_hash(plain_token.strip())] = t.id
            self._db.upsert_token(t.to_dict())
            self._cache[t.id] = t
        return t

    def delete(self, token_id: str) -> bool:
        with self._lock:
            t = self._cache.pop(token_id, None)
            if t is not None:
                # 清理 hash 索引, 防止残留指向已删除的 Token
                try:
                    h = _hash(decrypt_plaintext(t.token))
                    if self._index.get(h) == t.id:
                        self._index.pop(h, None)
                except Exception:
                    pass
            return self._db.delete_token(token_id) or (t is not None)

    def get(self, token_id: str) -> Optional[ApiToken]:
        return self._cache.get(token_id)

    def list_all(self) -> List[ApiToken]:
        return list(self._cache.values())

    # ---------- 鉴权 ----------
    def resolve(self, plain_token: str) -> Optional[ApiToken]:
        """按明文 Token O(1) 反查租户。明文不入库, 用密文做索引。"""
        with self._lock:
            h = _hash(plain_token.strip())
            tid = self._index.get(h)
            if not tid:
                # 索引缺失(如重启后首次)则全表扫描重建
                for t in self._cache.values():
                    try:
                        if decrypt_plaintext(t.token) == plain_token.strip():
                            self._index[h] = t.id
                            tid = t.id
                            break
                    except Exception:
                        continue
            if not tid:
                return None
            t = self._cache.get(tid)
            if not t or not t.enabled or t.status != TokenStatus.ACTIVE:
                return None
            t.last_used = int(time.time() * 1000)
            return t

    # ---------- 额度检查 ----------
    def check_quota(self, t: ApiToken, est_cost_usd: float) -> Optional[str]:
        """返回 None=允许; 否则返回拒绝原因。"""
        if t.daily_quota_usd <= 0:
            return None
        if t.today_used_usd + est_cost_usd > t.daily_quota_usd:
            return "quota_exhausted"
        return None

    def record_usage(self, t: ApiToken, cost_usd: float, requests: int = 1) -> None:
        with self._lock:
            today = time.strftime("%Y-%m-%d")
            if t.day_stamp != today:
                t.day_stamp = today
                t.used_today_usd = 0.0
                t.requests_today = 0
            t.used_today_usd += cost_usd
            t.requests_today += requests
            t.last_used = int(time.time() * 1000)
        # 异步批量落库, 避免阻塞热路径
        self._db.record_token_usage(t.id, cost_usd, requests)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()
            self._index.clear()
        self._load()


def _gen_token() -> str:
    import secrets
    return "ig-" + secrets.token_urlsafe(24)


def _hash(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def json_dumps(d: List) -> str:
    return json.dumps(d, ensure_ascii=False)
