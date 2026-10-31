"""负载均衡器全策略测试。"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("INTERGATE_DATA_DIR", "/tmp/ig_lb_test")

from models.api_key import ApiKey  # noqa: E402
from services.load_balancer import LoadBalancer  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


def _make_keys():
    return [
        ApiKey(id="k1", provider="openai", encrypted_key="a", name="k1",
               priority=10, weight=1),
        ApiKey(id="k2", provider="openai", encrypted_key="b", name="k2",
               priority=50, weight=3),
        ApiKey(id="k3", provider="openai", encrypted_key="c", name="k3",
               priority=100, weight=1),
    ]


def test_round_robin():
    print("round_robin")
    keys = _make_keys()
    lb = LoadBalancer()
    picks = [lb.pick(keys, "round_robin").id for _ in range(6)]
    # 3 个 key, 轮询 6 次, 应该每个被选 2 次
    check("k1 选 2 次", picks.count("k1") == 2, str(picks))
    check("k2 选 2 次", picks.count("k2") == 2, str(picks))
    check("k3 选 2 次", picks.count("k3") == 2, str(picks))
    # 顺序应为 k1,k2,k3,k1,k2,k3
    check("轮询顺序正确", picks == ["k1", "k2", "k3", "k1", "k2", "k3"], str(picks))


def test_round_robin_single_key():
    print("round_robin 单 Key")
    keys = [ApiKey(id="solo", provider="openai", encrypted_key="x", name="solo")]
    lb = LoadBalancer()
    for _ in range(5):
        check("单 Key 始终返回", lb.pick(keys, "round_robin").id == "solo")


def test_weighted_round_robin():
    print("weighted_round_robin")
    keys = _make_keys()
    lb = LoadBalancer()
    # 权重 1:3:1, 选 50 次应大致按比例分配
    picks = [lb.pick(keys, "weighted_round_robin").id for _ in range(50)]
    check("k2 权重最高选中最多", picks.count("k2") > picks.count("k1"), str(picks))
    check("k2 比 k1 多", picks.count("k2") >= 20, f"k2={picks.count('k2')}")


def test_priority():
    print("priority")
    keys = _make_keys()
    lb = LoadBalancer()
    # k1 优先级 10 最高(值越小越优先)
    for _ in range(5):
        check("始终选 k1", lb.pick(keys, "priority").id == "k1")


def test_priority_tie():
    print("priority 同优先级轮询")
    keys = [
        ApiKey(id="a", provider="openai", encrypted_key="x", name="a", priority=10),
        ApiKey(id="b", provider="openai", encrypted_key="y", name="b", priority=10),
    ]
    lb = LoadBalancer()
    picks = [lb.pick(keys, "priority").id for _ in range(4)]
    # 同优先级的两个 key 都应被选中
    check("两个 key 都被选中", "a" in picks and "b" in picks, str(picks))


def test_least_connections():
    print("least_connections")
    keys = _make_keys()
    lb = LoadBalancer()
    # 模拟 k1 有 3 个活跃连接
    lb.report_active("k1", 3)
    lb.report_active("k2", 1)
    lb.report_active("k3", 0)
    pick = lb.pick(keys, "least_connections")
    check("选最少连接的 k3", pick.id == "k3", pick.id)
    # 增加 k3 连接后应选 k2
    lb.report_active("k3", 5)
    pick = lb.pick(keys, "least_connections")
    check("选 k2(1 连接)", pick.id == "k2", pick.id)


def test_response_time():
    print("response_time")
    keys = _make_keys()
    lb = LoadBalancer()
    # k1 快(5ms), k2 慢(500ms), k3 无样本
    lb.report_latency("k1", 5)
    lb.report_latency("k2", 500)
    # k3 无样本应被优先选中
    pick = lb.pick(keys, "response_time")
    check("无样本 k3 优先", pick.id == "k3", pick.id)
    # 给 k3 也加延迟
    lb.report_latency("k3", 100)
    # 现在应选 k1(5ms 最低)
    pick = lb.pick(keys, "response_time")
    check("选最快 k1", pick.id == "k1", pick.id)


def test_smart():
    print("smart")
    keys = _make_keys()
    lb = LoadBalancer()
    # k1 优先级最高, 应综合评分最高
    pick = lb.pick(keys, "smart", model="gpt-4o", path="/v1/chat/completions")
    check("smart 可选", pick is not None)
    check("smart 倾向高优先级", pick.id == "k1", pick.id)

    # 给所有 Key 相同优先级, 让错误率成为区分因素
    for k in keys:
        k.priority = 50
        k.requests_today = 10
        k.errors_today = 0
    # k1 错误率 100%
    keys[0].errors_today = 10
    # k2 和 k3 错误率 0%
    pick = lb.pick(keys, "smart")
    check("smart 避开高错误率 Key", pick.id in ("k2", "k3"), pick.id)


def test_empty_keys():
    print("空 Key 列表")
    lb = LoadBalancer()
    check("空列表返回 None", lb.pick([], "round_robin") is None)


def test_unknown_strategy_falls_back():
    print("未知策略回退")
    keys = _make_keys()
    lb = LoadBalancer()
    pick = lb.pick(keys, "nonexistent_strategy")
    check("回退到 smart", pick is not None)


def test_report_active_negative_guard():
    print("活跃连接负数保护")
    keys = _make_keys()
    lb = LoadBalancer()
    lb.report_active("k1", -5)  # 不应变为负数
    check("活跃数不低于 0", lb._active.get("k1", 0) >= 0)


def test_latency_capped():
    print("延迟记录上限")
    key = ApiKey(id="k1", provider="openai", encrypted_key="x", name="k1")
    lb = LoadBalancer()
    for i in range(30):
        lb.report_latency("k1", float(i))
    check("延迟最多 20 条", len(lb._latencies["k1"]) == 20, str(len(lb._latencies["k1"])))


if __name__ == "__main__":
    test_round_robin()
    test_round_robin_single_key()
    test_weighted_round_robin()
    test_priority()
    test_priority_tie()
    test_least_connections()
    test_response_time()
    test_smart()
    test_empty_keys()
    test_unknown_strategy_falls_back()
    test_report_active_negative_guard()
    test_latency_capped()
    print(f"\n全部通过: {PASS} 项断言")
