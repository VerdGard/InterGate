"""Key 管理:加密存储、生命周期、失败冷却、用量累计。"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from config import constants as C
from crypto.aes import decrypt_plaintext, encrypt_plaintext
from db.database import Database
from models.api_key import ApiKey, KeyStatus

log = logging.getLogger("intergate.key_manager")


class KeyManager:
    def __init__(self, db: Database,
                 auto_disable_provider: Optional[Callable[[], bool]] = None):
        self._db = db
        # 运行时开关提供器: 返回 auto_disable_enabled; 未注入时默认开启
        self._auto_disable_provider = auto_disable_provider
        # RLock: list_active 在持锁状态会触发 _auto_recover->_persist_async,
        # 后者内部再次加锁, 需可重入以避免死锁
        self._lock = threading.RLock()
        self._cache: Dict[str, ApiKey] = {}
        self._load()

    def _load(self) -> None:
        with self._lock:
            for row in self._db.list_keys():
                try:
                    k = ApiKey.from_dict(row)
                    self._cache[k.id] = k
                except Exception as e:
                    log.warning("加载 Key 失败 row=%s: %s", row.get("id", "?"), e)
                    continue

    # ---------- CRUD ----------
    def add_key(self, provider: str, plain_key: str, name: str = "",
                base_url: str | None = None, grp: str = "",
                priority: int = 100, weight: int = 1,
                daily_quota: int = 1_000_000,
                max_requests_per_minute: int = 60,
                note: str = "", provider_id: str = "") -> ApiKey:
        k = ApiKey(
            provider=provider,
            encrypted_key=encrypt_plaintext(plain_key.strip()),
            name=name or f"{provider}-key",
            base_url=base_url or None,
            grp=grp,
            priority=priority,
            weight=weight,
            daily_quota=daily_quota,
            max_requests_per_minute=max_requests_per_minute,
            note=note,
            provider_id=provider_id,
            status=KeyStatus.ACTIVE,
        )
        with self._lock:
            self._db.upsert_key(k.to_db_dict())
            self._cache[k.id] = k
        return k

    def update_key(self, k: ApiKey, plain_key: str | None = None) -> ApiKey:
        if plain_key:
            k.encrypted_key = encrypt_plaintext(plain_key.strip())
        with self._lock:
            self._db.upsert_key(k.to_db_dict())
            self._cache[k.id] = k
        return k

    def delete_key(self, key_id: str) -> bool:
        with self._lock:
            existed = key_id in self._cache
            self._db.delete_key(key_id)
            self._cache.pop(key_id, None)
        return existed

    def get(self, key_id: str) -> ApiKey | None:
        with self._lock:
            return self._cache.get(key_id)

    def list_all(self) -> List[ApiKey]:
        with self._lock:
            return sorted(self._cache.values(), key=lambda k: (k.provider, k.priority))

    def list_active(self, provider: str | None = None,
                    exclude_cooldown: bool = True) -> List[ApiKey]:
        """返回可用的 Key:状态为 ACTIVE 且(可选)不在冷却期。

        自动恢复规则:
        - ERROR 且冷却已到期 -> 自动恢复为 ACTIVE(避免永久停用)
        - INACTIVE(手动停用) -> 不自动恢复, 保持停用状态
        - EXHAUSTED(额度耗尽) -> 不自动恢复, 需手动处理

        exclude_cooldown=False 时, ERROR 状态且在冷却期的 Key 也会被返回
        (可用于展示或强制重试场景), INACTIVE/EXHAUSTED 仍然被排除。
        """
        now = int(time.time() * 1000)
        out = []
        with self._lock:
            for k in self._cache.values():
                if k.status == KeyStatus.EXHAUSTED:
                    continue  # 额度耗尽必须手动处理
                if k.status == KeyStatus.INACTIVE:
                    continue  # 手动停用, 不自动恢复
                # ERROR 状态: 检查冷却是否到期
                if k.status == KeyStatus.ERROR and not k.in_cooldown:
                    # 冷却已到期 -> 自动恢复
                    self._auto_recover(k)
                if k.status != KeyStatus.ACTIVE:
                    # ERROR 且仍在冷却期
                    if not exclude_cooldown:
                        # 允许返回冷却中的 Key(但标记其状态)
                        if provider and k.provider != provider:
                            continue
                        out.append(k)
                    continue
                if provider and k.provider != provider:
                    continue
                if exclude_cooldown and k.cooldown_until and k.cooldown_until > now:
                    continue
                out.append(k)
        return out

    def _auto_recover(self, k: ApiKey) -> None:
        """冷却到期的 ERROR Key 恢复为 ACTIVE。

        仅对 ERROR 状态(运行时自动冷却)生效; INACTIVE(手动停用)和
        EXHAUSTED(额度耗尽)不会自动恢复, 必须用户手动处理。
        """
        if k.status not in (KeyStatus.ERROR,):
            return  # 只恢复 ERROR 状态, 不动 INACTIVE / EXHAUSTED
        k.status = KeyStatus.ACTIVE
        k.failure_count = 0
        k.cooldown_until = None
        self._persist_async(k)

    # ---------- 转发统计 ----------
    def decrypt(self, k: ApiKey) -> str:
        try:
            return decrypt_plaintext(k.encrypted_key)
        except Exception as e:
            log.warning("解密 Key %s 失败: %s", k.id, e)
            return ""

    def record_success(self, key_id: str, latency_ms: int = 0) -> None:
        """记录一次成功(只管理状态;请求/用量计数由 QuotaMonitor 负责)。

        不要把"手动停用/额度耗尽"的 Key 复活: 在途请求可能在管理员停用之后
        才返回, 无条件置 ACTIVE 会覆盖管理动作。只有运行时冷却(ERROR)
        才由成功请求提前解除。
        """
        k = self.get(key_id)
        if not k:
            return
        now = int(time.time() * 1000)
        k.last_used = now
        k.failure_count = 0
        k.cooldown_until = None
        if k.status == KeyStatus.ERROR:
            k.status = KeyStatus.ACTIVE      # 冷却中恢复
        # INACTIVE(手动停用) / EXHAUSTED(额度耗尽) 保持原状
        self._persist_async(k)

    def record_failure(self, key_id: str, category: str = "upstream",
                      msg: str = "") -> None:
        """记录一次失败(只管理冷却/状态;请求/错误计数由 QuotaMonitor 负责)。

        分类:
        - quota: 额度耗尽, 长期停用(EXHAUSTED, 30 分钟冷却)
        - auth: 认证失败, 短冷却后自动恢复(ERROR)
        - health: 后台健康巡检发现不可达, 连续失败达阈值才冷却
        - 其他(upstream/timeout/tpm): 连续失败达阈值才冷却; 未达阈值仅累计,
          避免单次 500 就永久停用。达到阈值置 ERROR 并冷却, 到期自动恢复。
        """
        k = self.get(key_id)
        if not k:
            return
        now = int(time.time() * 1000)
        k.failure_count += 1
        k.last_used = now
        if msg:
            log.info("Key %s(%s) 失败 category=%s msg=%s",
                     key_id, k.name, category, msg)
        # auto_disable_enabled=False: 仅记录失败与日志, 不自动关闭 Key
        # (额度告警仍由 QuotaMonitor 触发, 但不会置 EXHAUSTED)
        if self._auto_disable_provider is not None:
            auto = bool(self._auto_disable_provider())
        else:
            auto = True
        if not auto:
            self._persist_async(k)
            return
        if category == "quota":
            k.status = KeyStatus.EXHAUSTED
            k.cooldown_until = now + C.QUOTA_EXHAUSTED_COOLDOWN_MS
        elif category == "auth":
            k.status = KeyStatus.ERROR
            k.cooldown_until = now + C.COOLDOWN_SECONDS * 1000
        elif k.failure_count >= C.MAX_FAILURE_THRESHOLD:
            # upstream/timeout/tpm 连续失败达阈值 -> 冷却, 到期自动恢复
            k.status = KeyStatus.ERROR
            k.cooldown_until = now + C.COOLDOWN_SECONDS * 1000
        self._persist_async(k)

    def set_status(self, key_id: str, status: str) -> None:
        k = self.get(key_id)
        if not k:
            return
        k.status = status
        if status == KeyStatus.ACTIVE:
            k.cooldown_until = None
            k.failure_count = 0
        self._persist(k)

    def _persist(self, k: ApiKey) -> None:
        """同步持久化(低频管理操作用, 保证即时落库)。"""
        with self._lock:
            self._db.upsert_key(k.to_db_dict())
            self._cache[k.id] = k

    def _persist_async(self, k: ApiKey) -> None:
        """异步持久化(热路径用): 内存即时生效, DB 进入后台批量队列。

        热路径(成功/失败/用量写回)每次请求都会触发, 不必同步等磁盘,
        批量队列稍后一次性落库。内存 _cache 立即更新保证调用方读到最新值。
        """
        with self._lock:
            self._db.enqueue_key(k.to_db_dict())
            self._cache[k.id] = k

    # ---------- 批量测试 ----------
    async def test_key(self, key_id: str, base_url_hint: str | None = None,
                       client=None) -> Dict[str, Any]:
        from providers.registry import resolve_base_url
        from providers.upstream import UpstreamClient
        k = self.get(key_id)
        if not k:
            return {"ok": False, "message": "key not found"}
        base = resolve_base_url(k.provider, base_url_hint or k.base_url)
        if not base:
            return {"ok": False, "message": "未配置 Base URL"}
        up = client or UpstreamClient()
        plain = self.decrypt(k)
        ok, msg = await up.test_key(base, plain)
        k.last_tested = int(time.time() * 1000)
        k.test_result = "ok" if ok else "fail"
        k.test_error = "" if ok else msg
        if not ok:
            k.status = KeyStatus.ERROR
            k.cooldown_until = int(time.time() * 1000) + C.COOLDOWN_SECONDS * 1000
        else:
            k.status = KeyStatus.ACTIVE
            k.cooldown_until = None
            k.failure_count = 0
        self._persist(k)
        return {"ok": ok, "message": msg, "key": k.to_dict()}
