"""后台健康巡检:周期探测各 Key 上游连通性, 连续失败自动熔断(冷却)。

配合 load_balancer 的失败冷却机制: 巡检发现异常 Key 时调用 key_manager.
record_failure(category="health"), 使其进入冷却并撤出负载池; 冷却过期后由
key_manager._auto_recover 自动恢复。仅巡检 active 且近期有流量/异常的 Key,
避免对大量闲置 Key 频繁探测造成上游负担。
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from services.health import HealthProbe, MAX_KEYS_PER_PROBE

log = logging.getLogger("intergate.patrol")


class HealthPatrol:
    def __init__(self, gateway: Any, interval: int = 60):
        self.gateway = gateway
        self.interval = max(15, interval)
        self._probe = HealthProbe()
        self.last_run: Optional[int] = None
        self.last_results: List[Dict[str, Any]] = []
        self.last_summary: Dict[str, Any] = {}

    async def aclose(self) -> None:
        await self._probe.aclose()

    async def patrol_once(self) -> Dict[str, Any]:
        """执行一轮巡检。返回结果摘要。"""
        keys = self.gateway.key_manager.list_all()
        # 仅巡检 active 状态 Key(停用/已冷却的跳过)
        targets = [k for k in keys if getattr(k, "status", "") == "active"]
        if not targets:
            return {"total": 0, "cooldown": 0, "summary": self.last_summary}
        results = await self._probe.probe_all(targets)
        cooldown = 0
        for r in results:
            if not r.get("ok"):
                k = self.gateway.key_manager.get(r["key_id"])
                if k and k.status == "active" and not k.in_cooldown:
                    # 连续失败计数由 record_failure 内部维护, 超过阈值进入冷却
                    self.gateway.key_manager.record_failure(
                        k.id, category="health", msg=r.get("error", ""))
                    cooldown += 1
        self.last_results = results
        self.last_summary = HealthProbe.summary(results)
        self.last_run = int(time.time() * 1000)
        return {"total": len(results), "cooldown": cooldown,
                "summary": self.last_summary}

    async def run_loop(self) -> None:
        await asyncio.sleep(self.interval)   # 启动后首个周期不立即打扰
        while True:
            try:
                if self.gateway.settings.health_patrol_enabled:
                    res = await self.patrol_once()
                    if res["total"]:
                        log.info("健康巡检: %d 个 Key, %d 个进入冷却",
                                 res["total"], res["cooldown"])
            except Exception as e:
                log.warning("健康巡检异常: %s", e)
            await asyncio.sleep(self.interval)
