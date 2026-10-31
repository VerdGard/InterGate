"""6 种负载均衡策略(对齐 RelayGo LoadBalancer)。"""
from __future__ import annotations

import logging
import itertools
import random
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from models.api_key import ApiKey

log = logging.getLogger("intergate.load_balancer")


class LoadBalancer:
    """6 种负载均衡策略。

    设计说明: 延迟记录和活跃连接数为瞬时数据, 重启后清空。
    这不影响正确性——冷启动时无延迟记录, _response_time 策略
    会优先选择无样本的 Key(等效于随机), 随着请求积累快速收敛。
    """
    STRATEGIES = (
        "round_robin", "weighted_round_robin", "priority",
        "least_connections", "response_time", "smart",
    )

    def __init__(self):
        # round_robin 游标: group_key -> [游标, 上次的 key_id 元组]
        self._rr: Dict[str, List[object]] = {}
        self._lock = threading.Lock()
        # response_time 策略维护: key_id -> [latency...]
        self._latencies: Dict[str, List[float]] = defaultdict(list)
        # least_connections: key_id -> active 数(由 gateway 汇报)
        self._active: Dict[str, int] = defaultdict(int)

    # ---------- 上下文 ----------
    def report_active(self, key_id: str, delta: int) -> None:
        with self._lock:
            self._active[key_id] = max(0, self._active.get(key_id, 0) + delta)

    def report_latency(self, key_id: str, latency_ms: float) -> None:
        with self._lock:
            q = self._latencies[key_id]
            q.append(latency_ms)
            if len(q) > 20:
                # 切片赋值避免 del q[:-20] 产生中间列表拷贝
                q[:len(q)-20] = []

    # ---------- 选择 ----------
    def pick(self, keys: List[ApiKey], strategy: str,
             last_key_id: Optional[str] = None,
             model: Optional[str] = None,
             path: Optional[str] = None) -> Optional[ApiKey]:
        if not keys:
            return None
        if strategy not in self.STRATEGIES:
            strategy = "smart"
        with self._lock:
            if strategy == "round_robin":
                return self._round_robin(keys)
            if strategy == "weighted_round_robin":
                return self._weighted(keys)
            if strategy == "priority":
                return self._priority(keys)
            if strategy == "least_connections":
                return self._least_connections(keys)
            if strategy == "response_time":
                return self._response_time(keys)
            return self._smart(keys, model, path)

    # ---------- 各策略实现 ----------
    def _round_robin(self, keys: List[ApiKey]) -> ApiKey:
        """在可用集合中维护游标, 真正轮流选择。

        按 (provider, base_url, grp) 分组维护游标, 同名/同端点的多个
        Key 在同一组内轮流, 避免固定选第一个。
        """
        group_key = (keys[0].provider, keys[0].base_url or "", keys[0].grp)
        entry = self._rr.get(group_key)
        ids = tuple(k.id for k in keys)
        # 游标对应的 key 集合与当前候选不一致时重建(候选 key 增删/状态变化)
        if entry is None or entry[1] != ids:
            entry = [0, ids]
            self._rr[group_key] = entry
        idx = entry[0] % len(keys)
        entry[0] = idx + 1
        return keys[idx]

    def _weighted(self, keys: List[ApiKey]) -> ApiKey:
        total = sum(max(1, k.weight) for k in keys)
        r = random.uniform(0, total)
        acc = 0.0
        for k in keys:
            acc += max(1, k.weight)
            if r <= acc:
                return k
        return keys[-1]

    def _priority(self, keys: List[ApiKey]) -> ApiKey:
        """priority 越小越优先,同优先级轮询(使用 round_robin 游标)。"""
        sorted_keys = sorted(keys, key=lambda k: (k.priority, k.id))
        best = sorted_keys[0].priority
        pool = [k for k in sorted_keys if k.priority == best]
        if len(pool) == 1:
            return pool[0]
        # 复用 round_robin 游标机制实现同优先级轮询
        return self._round_robin(pool)

    def _least_connections(self, keys: List[ApiKey]) -> ApiKey:
        return min(keys, key=lambda k: self._active.get(k.id, 0))

    def _response_time(self, keys: List[ApiKey]) -> ApiKey:
        best: Optional[ApiKey] = None
        best_avg: float | None = None
        for k in keys:
            q = self._latencies.get(k.id)
            avg = sum(q) / len(q) if q else None
            if avg is None:
                return k  # 无样本的优先尝试
            if best_avg is None or avg < best_avg:
                best, best_avg = k, avg
        return best or keys[0]

    def _smart(self, keys: List[ApiKey], model: Optional[str],
               path: Optional[str]) -> ApiKey:
        """综合评分:优先级 + 错误率 + 当前负载 + 额度余量 + 权重。"""
        def score(k: ApiKey) -> float:
            s = 0.0
            s += (100 - k.priority) * 1.0            # 优先级
            s += (1.0 - k.error_rate) * 20.0         # 错误率越低越好
            s -= self._active.get(k.id, 0) * 2.0     # 负载惩罚
            s += min(1.0, k.quota_remaining / max(1, k.daily_quota)) * 10.0
            s += max(1, k.weight) * 0.5
            # 最近成功过的小额加分(避免频繁切换)
            if k.last_used and time.time() * 1000 - k.last_used < 60_000:
                s += 2.0
            return s

        return max(keys, key=score)
