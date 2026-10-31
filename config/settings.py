"""运行时用户设置(可持久化到 SQLite)"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, ClassVar, Dict, FrozenSet

from . import constants as C

# 修改这些字段后需要重启服务才能生效(运行时无法热加载)
RESTART_FIELDS: FrozenSet[str] = frozenset({
    "port",        # 端口变更需要重新 bind
    "web_port",    # Web 端口变更需要重新 bind
    "host",        # 监听地址变更需要重新 bind
    "max_concurrent",  # 并发连接数变更需要重新配置 ASGI server
    "workers",     # worker 数量变更需要重启
})


@dataclasses.dataclass
class UserSettings:
    # 网关
    gateway_enabled: bool = True   # 运行时开关(Web 控制台可暂停)
    host: str = C.DEFAULT_HOST
    port: int = C.DEFAULT_PORT
    gateway_key: str = ""            # 网关访问密钥(留空=不鉴权)
    gateway_key_enabled: bool = True   # 网关是否启用访问密钥鉴权(开关持久化; 关闭=无需 key 即可调用)
    jwt_enabled: bool = False          # 是否接受 HS256 JWT 作为网关访问凭证
    jwt_secret: str = ""               # JWT 签名密钥
    tokens_enabled: bool = False       # 是否启用多租户 Token 体系(默认关闭)
    max_concurrent: int = C.MAX_CONCURRENT_CONNECTIONS
    workers: int = 1                  # Uvicorn worker 数量(>1 时启用多进程)

    # 负载均衡
    load_balance_strategy: str = "smart"

    # 缓存
    cache_enabled: bool = True
    cache_ttl_seconds: int = C.DEFAULT_CACHE_TTL_SECONDS
    cache_max_entries: int = C.DEFAULT_CACHE_MAX_ENTRIES
    shared_cache_enabled: bool = False          # 多 Worker 共享缓存(SQLite)

    # 限流
    rate_limit_enabled: bool = True
    ip_rate_limit_per_minute: int = C.DEFAULT_IP_RATE_LIMIT_PER_MINUTE
    global_rpm_limit: int = C.DEFAULT_GLOBAL_RPM_LIMIT
    token_rate_limit_per_minute: int = C.DEFAULT_TOKEN_RATE_LIMIT_PER_MINUTE
    burst_multiplier: float = C.DEFAULT_BURST_MULTIPLIER
    adaptive_tpm_enabled: bool = True
    shared_rate_limit_enabled: bool = False     # 多 Worker 共享限流(SQLite)

    # 额度
    quota_warn_threshold: float = C.DEFAULT_QUOTA_WARN_THRESHOLD
    quota_warn_enabled: bool = True

    # 同步
    sync_enabled: bool = True
    sync_interval_minutes: int = 60

    # 后台健康巡检(自动熔断异常上游)
    health_patrol_enabled: bool = True
    health_patrol_interval: int = 60            # 秒

    # 自动关闭异常 Key(失败冷却/额度耗尽禁用)。False = 仍记录失败与告警,
    # 但不自动将 Key 置为 ERROR/EXHAUSTED, 也不会进入冷却
    auto_disable_enabled: bool = True

    # 失败请求审计(记录失败请求体摘要, 便于排查)
    audit_failures_enabled: bool = False
    audit_body_snippet_bytes: int = 2048        # 记录请求体前 N 字节

    # 日志
    log_retention_days: int = C.DEFAULT_LOG_RETENTION_DAYS
    max_log_entries: int = C.DEFAULT_MAX_LOG_ENTRIES

    # 管理 Web
    web_enabled: bool = True
    web_port: int = C.DEFAULT_WEB_PORT
    web_password: str = ""           # 管理台密码(留空=仅本机可访问)
    language: str = "zh"             # 控制台界面语言: zh / en

    # 告警 Webhook(配额耗尽/错误率过高等事件推送)
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_secret: str = ""

    # Telegram 推送(可选)
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # 上游连接池(httpx)
    upstream_max_connections: int = 100       # 每上游最大连接数
    upstream_max_keepalive: int = 20         # 每上游保持连接数
    # 上限(字节)
    upstream_max_response_bytes: int = 16 * 1024 * 1024   # 上游响应体上限
    upstream_max_request_bytes: int = 32 * 1024 * 1024    # 请求体上限

    # 落盘时需要 AES 加密的敏感字段(网关 Key / Webhook Secret)
    SENSITIVE_FIELDS: ClassVar[FrozenSet[str]] = frozenset({
        "gateway_key", "webhook_secret", "telegram_bot_token", "jwt_secret",
    })

    def to_persist_dict(self) -> Dict[str, Any]:
        """返回用于落盘的 dict: 敏感字段加密, 密码已哈希。"""
        from services.secret import encrypt_field
        # 密码: 若非哈希格式则先哈希(旧明文迁移)
        if self.web_password and not from_services_secret_is_hashed(self.web_password):
            self.web_password = from_services_secret_hash(self.web_password)
        d = self.to_dict()
        for f in self.SENSITIVE_FIELDS:
            if d.get(f):
                d[f] = encrypt_field(d[f])
        return d

    @classmethod
    def from_persist_dict(cls, d: Dict[str, Any]) -> "UserSettings":
        """从落盘 dict 恢复: 解密敏感字段为明文, 保存在内存供热路径使用。"""
        from services.secret import decrypt_field
        d = dict(d)
        for f in cls.SENSITIVE_FIELDS:
            val = d.get(f, "")
            if val:
                d[f] = decrypt_field(val)
        return cls.from_dict(d)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "UserSettings":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


def _from_services_secret_import():
    from services.secret import is_hashed as h, hash_password as hp
    return h, hp


def from_services_secret_is_hashed(v: str) -> bool:
    return _from_services_secret_import()[0](v)


def from_services_secret_hash(v: str) -> str:
    return _from_services_secret_import()[1](v)
