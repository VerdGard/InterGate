"""限流器测试:滑动窗口/IP/全局/Key RPM/自适应 TPM。"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("INTERGATE_DATA_DIR", "/tmp/ig_rl_test")

from config.settings import UserSettings  # noqa: E402
from services.rate_limiter import SlidingWindow, AdaptiveTPM, RateLimiter  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


def test_sliding_window_basic():
    print("滑动窗口基础")
    w = SlidingWindow(window_sec=0.5)
    check("初始计数 0", w.count() == 0)
    w.add()
    check("加 1 后计数 1", w.count() == 1)
    w.add()
    w.add()
    check("加 3 后计数 3", w.count() == 3)


def test_sliding_window_expiry():
    print("滑动窗口过期")
    w = SlidingWindow(window_sec=0.3)
    for _ in range(5):
        w.add()
    check("5 次后计数 5", w.count() == 5)
    time.sleep(0.4)
    check("窗口过期后计数 0", w.count() == 0)
    check("过期后可重新计数", w.add() == 1)


def test_adaptive_tpm_aimd():
    print("自适应 TPM AIMD")
    tpm = AdaptiveTPM(enabled=True, min_tpm=60.0, max_tpm=1000.0)
    # 初始应为 max
    check("初始 max", tpm.limit_for("k1") == 1000.0)
    # 降速: 乘性减
    tpm.adjust_down("k1")
    check("降速后 < max", tpm.limit_for("k1") < 1000.0)
    # 多次降速不低于 min
    for _ in range(50):
        tpm.adjust_down("k1")
    check("不低于 min", tpm.limit_for("k1") >= 60.0)
    # 加速: 加性增
    limit_before = tpm.limit_for("k1")
    tpm.adjust_up("k1")
    check("加速后增大", tpm.limit_for("k1") > limit_before)


def test_adaptive_tpm_disabled():
    print("自适应 TPM 关闭")
    tpm = AdaptiveTPM(enabled=False)
    check("关闭后不降速", tpm.limit_for("k1") == 100_000.0)
    tpm.adjust_down("k1")
    check("关闭降速无效", tpm.limit_for("k1") == 100_000.0)


def test_ip_rate_limit():
    print("IP 限流")
    s = UserSettings(rate_limit_enabled=True, ip_rate_limit_per_minute=3)
    rl = RateLimiter(s)
    check("第 1 次放行", rl.check("1.1.1.1", None)[0])
    check("第 2 次放行", rl.check("1.1.1.1", None)[0])
    check("第 3 次放行", rl.check("1.1.1.1", None)[0])
    ok, retry, reason = rl.check("1.1.1.1", None)
    check("第 4 次拦截", not ok)
    check("拦截原因 ip", reason == "ip")
    check("retry_after >= 1", retry >= 1)
    # 不同 IP 不受影响
    check("其他 IP 放行", rl.check("2.2.2.2", None)[0])


def test_global_rate_limit():
    print("全局 RPM 限流")
    s = UserSettings(rate_limit_enabled=True, global_rpm_limit=2)
    rl = RateLimiter(s)
    check("全局放行 1", rl.check("1.1.1.1", None)[0])
    check("全局放行 2", rl.check("2.2.2.2", None)[0])
    # 第 3 次(任意 IP)应被拦截
    ok, _, reason = rl.check("3.3.3.3", None)
    check("全局拦截", not ok)
    check("拦截原因 global", reason == "global")


def test_key_rpm_limit():
    print("Key RPM 限流")
    s = UserSettings(rate_limit_enabled=True)
    rl = RateLimiter(s)
    check("RPM=0 不限", rl.check_key_rpm("k1", 0)[0])
    check("RPM=2 第 1 次", rl.check_key_rpm("k1", 2)[0])
    check("RPM=2 第 2 次", rl.check_key_rpm("k1", 2)[0])
    check("RPM=2 第 3 次拦截", not rl.check_key_rpm("k1", 2)[0])
    # 另一个 key 不受影响
    check("不同 Key 放行", rl.check_key_rpm("k2", 2)[0])


def test_rate_limit_disabled():
    print("限流关闭")
    s = UserSettings(rate_limit_enabled=False, ip_rate_limit_per_minute=1)
    rl = RateLimiter(s)
    for _ in range(100):
        check("关闭后始终放行", rl.check("1.1.1.1", None)[0])


def test_tpm_check():
    print("自适应 TPM 检查")
    s = UserSettings(rate_limit_enabled=True, adaptive_tpm_enabled=True)
    rl = RateLimiter(s)
    # 初始 max_tpm=100000, 小量 token 应放行
    ok, wait, limit = rl.check_tpm("k1", 100)
    check("小量 token 放行", ok)
    check("放行无需等待", wait == 0.0)

    # 大量 token 超限
    ok, wait, limit = rl.check_tpm("k2", 200_000)
    check("超大 token 拦截", not ok)
    check("拦截有等待时间", wait > 0)
    check("等待在预算内", wait <= 8000)  # TPM_WAIT_BUDGET_MS


def test_tpm_disabled():
    print("TPM 关闭")
    s = UserSettings(adaptive_tpm_enabled=False)
    rl = RateLimiter(s)
    ok, wait, limit = rl.check_tpm("k1", 1_000_000)
    check("关闭后始终放行", ok)
    check("无等待", wait == 0.0)


def test_stats():
    print("统计信息")
    s = UserSettings(rate_limit_enabled=True)
    rl = RateLimiter(s)
    rl.check("1.1.1.1", None)
    rl.check_key_rpm("k1", 60)
    stats = rl.stats()
    check("stats 有 ip_count", "ip_count" in stats)
    check("stats 有 key_count", "key_count" in stats)
    check("stats 有 adaptive_tpm", "adaptive_tpm" in stats)


def test_retry_after():
    print("retry_after 计算")
    from services.rate_limiter import _retry_after
    check("0 返回 1", _retry_after(0) == 1)
    check("60 返回 >=1", _retry_after(60) >= 1)
    check("100 返回 >=1", _retry_after(100) >= 1)


if __name__ == "__main__":
    test_sliding_window_basic()
    test_sliding_window_expiry()
    test_adaptive_tpm_aimd()
    test_adaptive_tpm_disabled()
    test_ip_rate_limit()
    test_global_rate_limit()
    test_key_rpm_limit()
    test_rate_limit_disabled()
    test_tpm_check()
    test_tpm_disabled()
    test_stats()
    test_retry_after()
    print(f"\n全部通过: {PASS} 项断言")
