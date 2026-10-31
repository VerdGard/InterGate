"""租户 Token 模型:给下游客户端分配独立凭证, 带额度/限流/模型白名单。

区别于上游 API Key(管理受管上游)与网关 Key(控制台/运维权限)。
租户 Token 是"客户端访问网关"的带配额凭证。
"""
from __future__ import annotations

import datetime
import time
import uuid
from typing import Any, Dict, List, Optional


class TokenStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXHAUSTED = "exhausted"


class ApiToken:
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "",
        token: str = "",              # 密文
        enabled: bool = True,
        daily_quota_usd: float = 0.0, # 美元/日(0=不限)
        max_requests_per_minute: int = 0,
        models: Optional[List[str]] = None,   # 模型白名单(空=全部)
        provider: str = "",           # 限定提供商(空=全部)
        used_today_usd: float = 0.0,
        requests_today: int = 0,
        day_stamp: str = "",
        status: str = TokenStatus.ACTIVE,
        created_at: Optional[int] = None,
        last_used: int = 0,
        note: str = "",
    ):
        self.id = id or uuid.uuid4().hex[:12]
        self.name = name or ("token-" + self.id[:6])
        self.token = token
        self.enabled = enabled
        self.daily_quota_usd = daily_quota_usd
        self.max_requests_per_minute = max_requests_per_minute
        self.models = models or []
        self.provider = provider
        self.used_today_usd = used_today_usd
        self.requests_today = requests_today
        self.day_stamp = day_stamp
        self.status = status
        self.created_at = created_at or int(time.time() * 1000)
        self.last_used = last_used
        self.note = note

    def _is_today(self) -> bool:
        return self.day_stamp == datetime.date.today().isoformat()

    @property
    def today_used_usd(self) -> float:
        return round(self.used_today_usd if self._is_today() else 0.0, 6)

    @property
    def today_requests(self) -> int:
        return self.requests_today if self._is_today() else 0

    @property
    def quota_ratio(self) -> float:
        if self.daily_quota_usd <= 0:
            return 0.0
        return min(1.0, self.today_used_usd / self.daily_quota_usd)

    @property
    def quota_remaining_usd(self) -> float:
        if self.daily_quota_usd <= 0:
            return -1.0
        return max(0.0, round(self.daily_quota_usd - self.today_used_usd, 6))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name,
            "token": self.token,
            "enabled": self.enabled,
            "daily_quota_usd": self.daily_quota_usd,
            "max_requests_per_minute": self.max_requests_per_minute,
            "models": self.models, "provider": self.provider,
            "today_used_usd": self.today_used_usd,
            "today_requests": self.today_requests,
            "used_today_usd": round(self.used_today_usd, 6),
            "requests_today": self.requests_today,
            "day_stamp": self.day_stamp,
            "quota_ratio": self.quota_ratio,
            "quota_remaining_usd": self.quota_remaining_usd,
            "status": self.status,
            "created_at": self.created_at, "last_used": self.last_used,
            "note": self.note,
        }
