"""API Key 模型(字段对齐 Android 版 InterGate / RelayGo)"""
from __future__ import annotations

import datetime
import time
import uuid
from typing import Any, Dict, Optional


class KeyStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXHAUSTED = "exhausted"
    ERROR = "error"


class ApiKey:
    def __init__(
        self,
        id: Optional[str] = None,
        provider: str = "openai",
        encrypted_key: str = "",
        name: str = "",
        provider_id: str = "",
        note: str = "",
        base_url: Optional[str] = None,
        grp: str = "",
        priority: int = 100,
        weight: int = 1,
        max_requests_per_minute: int = 60,
        daily_quota: int = 1_000_000,
        used_today: int = 0,
        used_month: int = 0,
        requests_today: int = 0,
        requests_month: int = 0,
        errors_today: int = 0,
        day_stamp: str = "",
        month_stamp: str = "",
        status: str = KeyStatus.ACTIVE,
        last_tested: Optional[int] = None,
        test_result: Optional[str] = None,
        test_error: Optional[str] = None,
        created_at: Optional[int] = None,
        last_used: int = 0,
        failure_count: int = 0,
        cooldown_until: Optional[int] = None,
        metadata: Optional[Dict[str, str]] = None,
    ):
        self.id = id or uuid.uuid4().hex[:12]
        self.provider = provider
        self.encrypted_key = encrypted_key
        self.name = name or (provider + "-key")
        self.provider_id = provider_id
        self.note = note
        self.base_url = base_url
        self.grp = grp
        self.priority = priority
        self.weight = weight
        self.max_requests_per_minute = max_requests_per_minute
        self.daily_quota = daily_quota
        self.used_today = used_today
        self.used_month = used_month
        self.requests_today = requests_today
        self.requests_month = requests_month
        self.errors_today = errors_today
        self.day_stamp = day_stamp
        self.month_stamp = month_stamp
        self.status = status
        self.last_tested = last_tested
        self.test_result = test_result
        self.test_error = test_error
        self.created_at = created_at or int(time.time() * 1000)
        self.last_used = last_used
        self.failure_count = failure_count
        self.cooldown_until = cooldown_until
        self.metadata = metadata or {}

    # ---------- 派生属性 ----------
    @property
    def masked_key(self) -> str:
        if not self.encrypted_key:
            return "****"
        if len(self.encrypted_key) <= 8:
            return "*" * len(self.encrypted_key)
        return self.encrypted_key[:4] + "••••" + self.encrypted_key[-4:]

    # ---------- 今日/本月判断 ----------
    def _is_today(self) -> bool:
        """day_stamp 是否落在今天: 不是则今日计数应视为 0。"""
        return self.day_stamp == datetime.date.today().isoformat()

    def _is_this_month(self) -> bool:
        """month_stamp 是否落在本月: 不是则本月计数应视为 0。"""
        return self.month_stamp == datetime.date.today().strftime("%Y-%m")

    @property
    def today_used(self) -> int:
        return self.used_today if self._is_today() else 0

    @property
    def today_requests(self) -> int:
        return self.requests_today if self._is_today() else 0

    @property
    def today_errors(self) -> int:
        return self.errors_today if self._is_today() else 0

    @property
    def this_month_used(self) -> int:
        return self.used_month if self._is_this_month() else 0

    @property
    def this_month_requests(self) -> int:
        return self.requests_month if self._is_this_month() else 0

    @property
    def quota_ratio(self) -> float:
        if self.daily_quota <= 0:
            return 0.0
        return min(1.0, self.today_used / self.daily_quota)

    @property
    def quota_remaining(self) -> int:
        if self.daily_quota <= 0:
            return -1
        return max(0, self.daily_quota - self.today_used)

    @property
    def error_rate(self) -> float:
        if not self._is_today() or self.today_requests == 0:
            return 0.0
        return self.today_errors / self.today_requests

    @property
    def in_cooldown(self) -> bool:
        return self.cooldown_until is not None and self.cooldown_until > int(time.time() * 1000)

    # ---------- 序列化 ----------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "key": self.encrypted_key,          # 密文,前端只显示 masked
            "masked_key": self.masked_key,
            "name": self.name,
            "provider_id": self.provider_id,
            "note": self.note,
            "base_url": self.base_url or "",
            "group": self.grp,
            "priority": self.priority,
            "weight": self.weight,
            "max_requests_per_minute": self.max_requests_per_minute,
            "daily_quota": self.daily_quota,
            "used_today": self.today_used,
            "used_month": self.this_month_used,
            "requests_today": self.today_requests,
            "requests_month": self.this_month_requests,
            "errors_today": self.today_errors,
            "day_stamp": self.day_stamp,
            "month_stamp": self.month_stamp,
            "status": self.status,
            "last_tested": self.last_tested,
            "test_result": self.test_result,
            "test_error": self.test_error,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "failure_count": self.failure_count,
            "cooldown_until": self.cooldown_until,
            "quota_ratio": self.quota_ratio,
            "quota_remaining": self.quota_remaining,
            "error_rate": self.error_rate,
            "in_cooldown": self.in_cooldown,
            "metadata": self.metadata,
        }

    def to_db_dict(self) -> Dict[str, Any]:
        d = self.to_dict()
        d["encrypted_key"] = d.pop("key")     # db 层字段名
        d["grp"] = self.grp
        d["metadata_json"] = json_dumps(self.metadata)
        # 跨日/跨月后 to_dict 已将今日/本月计数归零, 同步 stamp 保证落库一致
        if not self._is_today():
            d["day_stamp"] = datetime.date.today().isoformat()
        if not self._is_this_month():
            d["month_stamp"] = datetime.date.today().strftime("%Y-%m")
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ApiKey":
        return cls(
            id=d.get("id"),
            provider=d.get("provider", "openai"),
            encrypted_key=d.get("encrypted_key") or d.get("key", ""),
            name=d.get("name", ""),
            provider_id=d.get("provider_id", ""),
            note=d.get("note", ""),
            base_url=d.get("base_url") or None,
            grp=d.get("group") or d.get("grp", ""),
            priority=int(d.get("priority", 100)),
            weight=int(d.get("weight", 1)),
            max_requests_per_minute=int(d.get("max_requests_per_minute", 60)),
            daily_quota=int(d.get("daily_quota", 1_000_000)),
            used_today=int(d.get("used_today", 0)),
            used_month=int(d.get("used_month", 0)),
            requests_today=int(d.get("requests_today", 0)),
            requests_month=int(d.get("requests_month", 0)),
            errors_today=int(d.get("errors_today", 0)),
            day_stamp=d.get("day_stamp", ""),
            month_stamp=d.get("month_stamp", ""),
            status=d.get("status", KeyStatus.ACTIVE),
            last_tested=d.get("last_tested"),
            test_result=d.get("test_result"),
            test_error=d.get("test_error"),
            created_at=d.get("created_at"),
            last_used=int(d.get("last_used", 0)),
            failure_count=int(d.get("failure_count", 0)),
            cooldown_until=d.get("cooldown_until"),
            metadata=d.get("metadata") or {},
        )


def json_dumps(d: Dict[str, str]) -> str:
    import json
    return json.dumps(d, ensure_ascii=False)
