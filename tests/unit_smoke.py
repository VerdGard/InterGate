"""纯逻辑冒烟测试:不依赖 fastapi/httpx,安装基础依赖后即可运行。

运行: python3 tests/unit_smoke.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_test_")

import datetime  # noqa: E402

from crypto.aes import decrypt_plaintext, encrypt_plaintext  # noqa: E402
from db.database import Database  # noqa: E402
from models.api_key import ApiKey, KeyStatus  # noqa: E402
from providers.registry import detect_provider, endpoint_kind  # noqa: E402
from services.cache import ResponseCache  # noqa: E402
from services.load_balancer import LoadBalancer  # noqa: E402
from services.quota import QuotaMonitor  # noqa: E402
from services.rate_limiter import RateLimiter  # noqa: E402
from config.settings import UserSettings  # noqa: E402

PASS = 0


def check(name: str, cond: bool) -> None:
    global PASS
    assert cond, f"[FAIL] {name}"
    PASS += 1
    print(f"  ✓ {name}")


def test_crypto():
    print("crypto")
    plain = "sk-test-1234567890abcdef"
    blob = encrypt_plaintext(plain)
    check("密文与明文不同", blob != plain)
    check("可解密还原", decrypt_plaintext(blob) == plain)
    check("空值安全", decrypt_plaintext("") == "")


def test_db():
    print("db")
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "t.db"))
    db.set_setting("k", {"a": 1})
    check("settings 读写", db.get_setting("k") == {"a": 1})
    k = ApiKey(provider="openai", encrypted_key="enc", name="n1")
    db.upsert_key(k.to_db_dict())
    check("key upsert", db.get_key(k.id)["name"] == "n1")
    db.insert_log({"ts": 1, "path": "/v1/x", "method": "POST", "status": 200})
    check("log 写入", len(db.query_logs()) == 1)
    db.upsert_stats(datetime.date.today().isoformat(), "openai", k.id, requests=2)
    s = db.stats_summary(7)
    check("stats 汇总", s["total"]["requests"] == 2)
    db.delete_key(k.id)
    check("key 删除", db.get_key(k.id) is None)


def test_models():
    print("models")
    k = ApiKey(provider="openai", encrypted_key="sk-abcdefgh1234", name="t")
    check("masked_key", k.masked_key == "sk-a••••1234")
    check("quota_remaining", k.quota_remaining == 1_000_000)
    check("in_cooldown 默认否", not k.in_cooldown)


def test_registry():
    print("registry")
    check("路径识别 anthropic", detect_provider("/v1/messages") == "anthropic")
    check("模型识别", detect_provider("/v1/chat/completions", "claude-3") == "anthropic")
    check("gemini", detect_provider("/v1beta/models", "gemini-pro") == "google")
    check("endpoint_kind", endpoint_kind("/v1/chat/completions") == "chat")


def test_load_balancer():
    print("load_balancer")
    ks = [ApiKey(provider="openai", encrypted_key="a", name="k1", priority=50),
          ApiKey(provider="openai", encrypted_key="b", name="k2", priority=10)]
    lb = LoadBalancer()
    for s in lb.STRATEGIES:
        k = lb.pick(ks, s)
        check(f"策略 {s} 可选", k is not None)
    check("priority 选 k2", lb.pick(ks, "priority").name == "k2")
    lb.report_latency("k1", 5); lb.report_latency("k2", 50)
    check("response_time 选 k1", lb.pick(ks, "response_time").name == "k1")


def test_rate_limiter():
    print("rate_limiter")
    s = UserSettings(rate_limit_enabled=True, global_rpm_limit=100,
                     ip_rate_limit_per_minute=2)
    rl = RateLimiter(s)
    check("IP 放行1", rl.check("1.1.1.1", None)[0])
    check("IP 放行2", rl.check("1.1.1.1", None)[0])
    check("IP 超限拦截", not rl.check("1.1.1.1", None)[0])
    check("其他 IP 放行", rl.check("2.2.2.2", None)[0])
    check("key rpm 放行", rl.check_key_rpm("k1", 1)[0])
    check("key rpm 拦截", not rl.check_key_rpm("k1", 1)[0])
    g = RateLimiter(UserSettings(rate_limit_enabled=True, global_rpm_limit=2))
    check("全局放行", g.check("1.1.1.1", None)[0])
    check("全局放行2", g.check("2.2.2.2", None)[0])
    check("全局拦截", not g.check("3.3.3.3", None)[0])


def test_cache():
    print("cache")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=2)
    key = c.make_key("POST", "/v1/chat/completions", b"{}")
    c.put(key, 200, {"a": "b"}, b"body1")
    check("缓存命中", c.get(key)[2] == b"body1")
    c.put(c.make_key("GET", "/x", b"1"), 200, {}, b"2")
    c.put(c.make_key("GET", "/y", b"2"), 200, {}, b"3")
    check("LRU 淘汰", c.get(key) is None)
    check("stats", c.stats()["entries"] == 2)


def test_quota():
    print("quota")
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "q.db"))
    q = QuotaMonitor(db, warn_threshold=0.9, warn_enabled=True)
    k = ApiKey(provider="openai", encrypted_key="x", name="q1", daily_quota=100)
    k.day_stamp = datetime.date.today().isoformat()   # 模拟已加载的当日 Key
    k.used_today = 95
    r = q.record(k, 200, {"prompt_tokens": 10, "completion_tokens": 5})
    check("额度预警", any("额度" in w for w in r["warnings"]))
    check("用量累计", k.used_today == 110)
    db.flush_now()  # 统计现已后台批量落库, 显式冲刷后再断言
    check("summary", q.summary(7)["total"]["requests"] == 1)


def test_url_join():
    print("url 拼接去重")
    from gateway import _join_base_and_path as j
    cases = [
        ("https://token.sensenova.cn/v1", "/v1/chat/completions",
         "https://token.sensenova.cn/v1/chat/completions"),
        ("https://api.openai.com", "/v1/chat/completions",
         "https://api.openai.com/v1/chat/completions"),
        ("https://host.com/v1/", "/v1/models", "https://host.com/v1/models"),
        ("https://host.com/api", "/v1/chat/completions",
         "https://host.com/api/v1/chat/completions"),
    ]
    for base, path, exp in cases:
        got = j(base, path)
        check(f"join {base} {path}", got == exp)


def test_pricing_overrides():
    print("价格表覆盖")
    from config.pricing import set_overrides, price_for, estimate_cost
    set_overrides({"sensenova": (2.0, 6.0)})
    check("前缀覆盖生效", price_for("sensenova-x") == (2.0, 6.0))
    check("未覆盖回退内置", price_for("deepseek-v4") == (0.27, 1.10))
    cost, pin, pout = estimate_cost("sensenova-x", 1000, 500)
    check("费用计算", abs(cost - 0.005) < 1e-9 and pin == 2.0 and pout == 6.0)
    set_overrides({})


def test_logs_query_extra():
    print("日志增强筛选")
    import tempfile, os
    db = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
    db.insert_log({"ts": 1000, "path": "/v1/chat/completions", "method": "POST",
                   "status": 200, "provider": "openai", "key_id": "k1",
                   "model": "deepseek-v4-flash", "latency_ms": 10,
                   "prompt_tokens": 10, "completion_tokens": 5, "cached": 0, "error": ""})
    db.insert_log({"ts": 2000, "path": "/v1/chat/completions", "method": "POST",
                   "status": 500, "provider": "deepseek", "key_id": "k2",
                   "model": "glm-5.2", "latency_ms": 20,
                   "prompt_tokens": 1, "completion_tokens": 1, "cached": 0, "error": "boom"})
    rows, total = db.query_logs(limit=10, offset=0, model="deepseek", total=True)
    check("模型模糊筛选", total == 1 and rows[0]["key_id"] == "k1")
    rows2, t2 = db.query_logs(limit=10, offset=0, status=500, total=True)
    check("状态筛选", t2 == 1 and rows2[0]["model"] == "glm-5.2")
    rows3, t3 = db.query_logs(limit=10, offset=0, ts_from=1500, total=True)
    check("时间范围筛选", t3 == 1 and rows3[0]["ts"] == 2000)
    rows4, t4 = db.query_logs(limit=1, offset=1, total=True)
    check("分页 offset", len(rows4) == 1 and t4 == 2)


def test_model_routes_db():
    print("模型路由 CRUD")
    import tempfile, os
    db = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
    db.set_route("m1", ["k1", "k2"], enabled=True, note="test")
    routes = db.get_routes()
    check("路由写入", routes["m1"]["key_ids"] == ["k1", "k2"] and routes["m1"]["enabled"])
    db.set_route("m1", ["k1"], enabled=False)
    routes = db.get_routes()
    check("路由更新", routes["m1"]["key_ids"] == ["k1"] and not routes["m1"]["enabled"])
    db.delete_route("m1")
    check("路由删除", "m1" not in db.get_routes())


def test_stats_range():
    print("统计区间查询(趋势)")
    import tempfile, os
    db = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
    db.upsert_stats("2026-08-19", "openai", "k1", requests=3, errors=1,
                    prompt_tokens=100, completion_tokens=50, cost_usd=0.01)
    db.upsert_stats("2026-08-20", "deepseek", "k2", requests=5, errors=0,
                    prompt_tokens=200, completion_tokens=100, cost_usd=0.02)
    rows = db.stats_range("2026-08-19", "2026-08-20")
    check("区间返回2天", len(rows) == 2)
    check("区间合计正确", sum(r["requests"] for r in rows) == 8)
    rows1 = db.stats_range("2026-08-20", "2026-08-20")
    check("单日查询", len(rows1) == 1 and rows1[0]["provider"] == "deepseek")


def test_webhook_sign():
    print("webhook 签名与空URL")
    import asyncio, types
    from services.webhook import notify_webhook
    import hashlib, hmac
    captured = []
    async def fake_post(self, url, **kw):
        captured.append((kw.get("headers", {}).get("X-InterGate-Signature", ""),
                         kw.get("content", "")))
        return types.SimpleNamespace(is_success=True, status_code=200, headers={})
    import httpx
    orig = httpx.AsyncClient.post
    httpx.AsyncClient.post = fake_post
    try:
        ok = asyncio.run(notify_webhook("http://x", "T", "C", "sec"))
        check("推送成功", ok is True)
        sig, body = captured[0]
        expect = hmac.new(b"sec", body.encode(), hashlib.sha256).hexdigest()
        check("HMAC 签名一致", sig == expect)
        check("空URL返回False", asyncio.run(notify_webhook("", "T", "C", "")) is False)
    finally:
        httpx.AsyncClient.post = orig


def test_health_probe_summary():
    print("健康探测汇总")
    from services.health import HealthProbe
    results = [{"ok": True, "latency_ms": 100}, {"ok": True, "latency_ms": 200},
               {"ok": False, "latency_ms": 0, "error": "timeout"}]
    s = HealthProbe.summary(results)
    check("汇总total", s["total"] == 3)
    check("汇总ok", s["ok"] == 2)
    check("平均延迟", s["avg_latency_ms"] == 150)
    check("可用率", abs(s["up_rate"] - 0.667) < 0.001)


if __name__ == "__main__":
    test_crypto()
    test_url_join()
    test_db()
    test_models()
    test_registry()
    test_load_balancer()
    test_rate_limiter()
    test_cache()
    test_quota()
    test_pricing_overrides()
    test_logs_query_extra()
    test_model_routes_db()
    test_stats_range()
    test_webhook_sign()
    test_health_probe_summary()
    print(f"\n全部通过: {PASS} 项断言")
