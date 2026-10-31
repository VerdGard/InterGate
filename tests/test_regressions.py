"""漏洞修复回归测试。

每个用例对应一次实际修复, 用于防止问题被重新引入:
  1. 租户鉴权引用未定义变量 provider
  2. 响应缓存跨租户串数据
  3/10. 管理端点匿名或租户可读
  4. 流式读取超时被误判为流结束
  5. 一条非法日志导致整批写库丢弃
  6. 附加网关密钥回传后被清空
  7. 敏感字段明文落盘
  8. 在途请求成功覆盖手动停用/额度耗尽
  9. 自适应 TPM 单位不一致导致限流失效
 11. /api/settings 明文回传敏感字段
 12. 配置导出/导入不对称
 13. 查询串转发丢失
 14. Anthropic 上游鉴权头
 15. 额度耗尽告警风暴
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("INTERGATE_DATA_DIR", tempfile.mkdtemp(prefix="ig_regress_"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from config.settings import UserSettings  # noqa: E402
from db.database import Database  # noqa: E402
from gateway import GatewayApp  # noqa: E402
from models.api_key import KeyStatus  # noqa: E402
from providers.upstream import UpstreamResult  # noqa: E402
from services.rate_limiter import RateLimiter  # noqa: E402
from services.secret import hash_password  # noqa: E402
from webapp import WebApp  # noqa: E402

_COUNTER = [0]


def _db(name: str) -> Database:
    _COUNTER[0] += 1
    return Database(os.path.join(os.environ["INTERGATE_DATA_DIR"],
                                 f"{name}{_COUNTER[0]}.db"))


class StubUpstream:
    """可编排的上游桩。"""

    def __init__(self):
        self.answer = "A"
        self.urls = []
        self.headers = []

    async def forward(self, method, url, headers, body):
        self.urls.append(url)
        self.headers.append(dict(headers))
        return UpstreamResult(200, {"content-type": "application/json"},
                              json.dumps({"result": self.answer}).encode())

    async def open_stream(self, method, url, headers, body):
        self.urls.append(url)

        async def gen():
            yield b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
            yield b"data: [DONE]\n\n"
        return 200, {"content-type": "text/event-stream"}, gen()

    async def aclose(self):
        pass


def make_gateway(settings=None, base_url="https://fake.example/v1"):
    settings = settings or UserSettings()
    db = _db("gw")
    gw = GatewayApp(settings, db)
    gw.upstream = StubUpstream()
    gw.key_manager.add_key("custom", "sk-upstream", name="k", base_url=base_url)
    return gw, db


def web_client(gw, db, password="pw"):
    gw.settings.web_password = hash_password(password)
    app = WebApp(gw, db)
    c = TestClient(app.app)
    token = c.post("/api/login", json={"password": password}).json()["token"]
    return c, {"Authorization": "Bearer " + token}


class _FakeReq:
    def __init__(self, headers):
        self.headers = headers


# ---------------------------------------------------------------- 1
def test_tenant_with_provider_does_not_crash():
    """租户限定提供商时不得因 provider 未赋值而 500。"""
    gw, db = make_gateway()
    gw.settings.tokens_enabled = True
    gw.tokens.add(name="t", plain_token="ig-tenant", provider="openai")
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               headers={"Authorization": "Bearer ig-tenant"},
               json={"model": "gpt-4o", "messages": []})
    assert r.status_code != 500, r.text
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------- 2
def test_cache_isolated_between_tenants():
    """不同租户的相同请求不得命中同一份缓存。"""
    gw, db = make_gateway()
    stub = gw.upstream
    gw.settings.tokens_enabled = True
    gw.tokens.add(name="A", plain_token="ig-A")
    gw.tokens.add(name="B", plain_token="ig-B")
    c = TestClient(gw.app)
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "同一句话"}]}

    stub.answer = "A的私有数据"
    r1 = c.post("/v1/chat/completions",
                headers={"Authorization": "Bearer ig-A"}, json=body)
    stub.answer = "B的私有数据"
    r2 = c.post("/v1/chat/completions",
                headers={"Authorization": "Bearer ig-B"}, json=body)
    assert r1.json()["result"] == "A的私有数据"
    assert r2.json()["result"] == "B的私有数据", "租户 B 命中了租户 A 的缓存"
    assert r2.headers.get("x-relay-cache") != "HIT"


# ---------------------------------------------------------------- 3 / 10
def test_management_endpoints_require_credentials():
    """匿名与租户 Token 都不得读取管理端点; 代理路径保持开放。"""
    gw, db = make_gateway()
    c = TestClient(gw.app)
    for p in ("/relay/version", "/relay/stats", "/relay/report",
              "/relay/cache", "/relay/metrics"):
        assert c.get(p).status_code == 401, f"{p} 匿名可读"
    assert c.post("/v1/chat/completions",
                  json={"model": "gpt-4o", "messages": []}).status_code == 200

    gw.settings.tokens_enabled = True
    gw.tokens.add(name="t", plain_token="ig-tenant")
    h = {"Authorization": "Bearer ig-tenant"}
    assert c.get("/relay/report", headers=h).status_code == 401
    assert c.post("/v1/chat/completions", headers=h,
                  json={"model": "gpt-4o", "messages": []}).status_code == 200


# ---------------------------------------------------------------- 4
def test_stream_survives_slow_upstream(monkeypatch):
    """上游静默超过心跳阈值时, 后续数据仍须继续送达。"""
    gw, db = make_gateway()
    gw.settings.cache_enabled = False

    class SlowStream:
        async def open_stream(self, method, url, headers, body):
            async def gen():
                for i in range(3):
                    await asyncio.sleep(0.2)
                    yield ('data: {"choices":[{"delta":{"content":"t%d"}}]}\n\n'
                           % i).encode()
                yield b"data: [DONE]\n\n"
            return 200, {"content-type": "text/event-stream"}, gen()

        async def forward(self, *a, **kw):
            raise AssertionError("不应走非流式路径")

    gw.upstream = SlowStream()
    import gateway as gwmod
    orig = asyncio.wait_for
    calls = [0]

    async def short(fut, timeout=None):
        calls[0] += 1
        return await orig(fut, 0.05)

    monkeypatch.setattr(gwmod.asyncio, "wait_for", short)
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "m", "stream": True, "messages": []})
    body = r.text
    assert calls[0] > 0
    for i in range(3):
        assert ("t%d" % i) in body, "第 %d 个分片丢失(流被提前判定结束)" % i
    assert "[DONE]" in body


# ---------------------------------------------------------------- 5
def test_log_row_without_model_is_storable():
    """无 model 字段的请求(/v1/models)必须能落库。"""
    db = _db("nullmodel")
    db.enqueue_log({"ts": 1, "path": "/v1/models", "method": "GET", "status": 200,
                    "provider": "custom", "key_id": "", "model": None,
                    "latency_ms": 0, "prompt_tokens": 0, "completion_tokens": 0,
                    "total_tokens": 0, "cached": 0, "error": ""})
    db.flush_now()
    rows = db.query_logs(limit=5)
    assert len(rows) == 1 and rows[0]["model"] == ""


def test_bad_log_row_does_not_drop_batch():
    """一条非法记录只丢弃自己, 不得连带丢弃统计与 Key 写回。"""
    db = _db("batch")
    db.enqueue_log({"ts": 1, "path": "/v1/models", "method": "GET", "status": 200,
                    "provider": "custom", "key_id": "", "model": None,
                    "latency_ms": 0, "prompt_tokens": 0, "completion_tokens": 0,
                    "total_tokens": 0, "cached": 0, "error": ""})
    db.enqueue_log({"ts": 2, "path": "/ok", "method": "GET", "status": 200,
                    "provider": "custom", "key_id": "k1", "model": "m",
                    "latency_ms": 1, "prompt_tokens": 1, "completion_tokens": 1,
                    "total_tokens": 2, "cached": 0, "error": ""})
    db.enqueue_stats("2026-01-01", "custom", "k1", 1, 0, 1, 1, 0.01)
    db.enqueue_log({"path": "/x", "method": "GET", "status": 500})   # 缺 ts
    db.flush_now()
    assert len(db.query_logs(limit=10)) == 2
    assert len(db.stats_range("2026-01-01", "2026-01-02")) == 1


# ---------------------------------------------------------------- 6
def test_gateway_keys_survive_roundtrip():
    """前端回传脱敏对象不得清空已保存的附加密钥。"""
    gw, db = make_gateway()
    c, h = web_client(gw, db)
    c.put("/api/gateway-keys",
          json={"keys": [{"key": "sk-extra-000111", "name": "e",
                          "permission": "full"}]}, headers=h)
    listed = c.get("/api/gateway-keys", headers=h).json()["keys"]
    assert len(listed) == 1 and "key" not in listed[0]

    r = c.put("/api/gateway-keys", json={"keys": listed}, headers=h)
    assert r.json()["count"] == 1, "回传后密钥被清空"
    perm = gw._authorize(_FakeReq({"authorization": "Bearer sk-extra-000111"}))
    assert perm is not None, "密钥已失效"


# ---------------------------------------------------------------- 7
def test_toggle_does_not_write_plaintext():
    """切换网关开关不得把内存中的明文敏感字段写库。"""
    gw, db = make_gateway()
    gw.settings.gateway_key = "sk-MASTER-PLAINTEXT"
    gw.settings.jwt_secret = "jwt-SECRET"
    gw.settings.webhook_secret = "wh-SECRET"
    c, h = web_client(gw, db)
    db.set_setting("user_settings", gw.settings.to_persist_dict())

    c.post("/api/gateway/toggle", json={"enabled": False}, headers=h)
    c.post("/api/gateway/toggle", json={"enabled": True}, headers=h)
    raw = db.get_setting("user_settings")
    for f in ("gateway_key", "jwt_secret", "webhook_secret"):
        assert str(raw[f]).startswith("enc$"), "%s 被明文落盘: %r" % (f, raw[f])


# ---------------------------------------------------------------- 8
def test_success_does_not_revive_disabled_key():
    """在途请求成功不得覆盖手动停用或额度耗尽状态。"""
    gw, db = make_gateway()
    km = gw.key_manager
    kid = km.list_all()[0].id

    km.record_failure(kid, "quota")
    assert km.get(kid).status == KeyStatus.EXHAUSTED
    km.record_success(kid)
    assert km.get(kid).status == KeyStatus.EXHAUSTED

    km.set_status(kid, KeyStatus.INACTIVE)
    km.record_success(kid)
    assert km.get(kid).status == KeyStatus.INACTIVE

    km.set_status(kid, KeyStatus.ACTIVE)
    km.record_failure(kid, "auth")
    assert km.get(kid).status == KeyStatus.ERROR
    km.record_success(kid)
    assert km.get(kid).status == KeyStatus.ACTIVE, "运行时冷却应可被成功请求解除"


# ---------------------------------------------------------------- 9
def test_tpm_actually_limits():
    """TPM 与 token 同量纲比较, 超限必须真的被拦。"""
    s = UserSettings()
    s.adaptive_tpm_enabled = True
    rl = RateLimiter(s)
    blocked = sum(1 for _ in range(60) if not rl.check_tpm("k", 4000)[0])
    assert blocked > 0, "20 万 token 全部放行, TPM 限流未生效"
    assert rl._tpm["k"].count() >= 4000


def test_tpm_aimd_does_not_collapse():
    """饱和期间 AIMD 不应把上限连降到底(降档需冷却)。"""
    s = UserSettings()
    s.adaptive_tpm_enabled = True
    rl = RateLimiter(s)
    for _ in range(60):
        rl.check_tpm("k", 4000)
    assert rl.adaptive.limit_for("k") > rl.adaptive._min * 10


# ---------------------------------------------------------------- 11
def test_settings_are_masked_and_roundtrip_safe():
    """/api/settings 不得回传明文, 且前端整体回传不得污染配置。"""
    gw, db = make_gateway()
    gw.settings.gateway_key = "sk-MASTER-PLAINTEXT-LONG"
    gw.settings.jwt_secret = "jwt-SECRET"
    gw.settings.telegram_bot_token = "123456:SECRET-TOKEN"
    c, h = web_client(gw, db)

    d = c.get("/api/settings", headers=h).json()
    assert d["gateway_key"] != "sk-MASTER-PLAINTEXT-LONG"
    assert "••••" in d["gateway_key"]
    assert d["jwt_secret"] == "••••"
    assert d["web_password"] == "••••••"

    r = c.put("/api/settings", json=d, headers=h)
    assert r.status_code == 200
    assert gw.settings.gateway_key == "sk-MASTER-PLAINTEXT-LONG"
    assert gw.settings.jwt_secret == "jwt-SECRET"
    assert gw.settings.telegram_bot_token == "123456:SECRET-TOKEN"
    assert gw.settings.web_password.startswith("$pbkdf2$")

    assert c.get("/api/settings/secret/gateway_key", headers=h).json()["value"] \
        == "sk-MASTER-PLAINTEXT-LONG"
    assert c.get("/api/settings/secret/webhook_url", headers=h).status_code == 400


# ---------------------------------------------------------------- 12
def test_export_import_roundtrip():
    """导出再导入必须还原 Key / Token / 附加密钥(跨机可用)。"""
    gw, db = make_gateway()
    gw.settings.tokens_enabled = True
    c, h = web_client(gw, db)
    original_plain = gw.key_manager.decrypt(gw.key_manager.list_all()[0])
    gw.tokens.add(name="t", plain_token="PLAIN-TENANT")
    c.put("/api/gateway-keys",
          json={"keys": [{"key": "sk-extra-999", "name": "e"}]}, headers=h)

    conf = c.get("/api/settings/export", headers=h).json()
    assert conf["format"] == "intergate-config/2"
    assert conf["keys"][0]["key"] == original_plain, "Key 导出应为明文"
    assert conf["tokens"][0]["token"] == "PLAIN-TENANT", "Token 导出应为明文"

    gw2, db2 = make_gateway()
    gw2.settings.tokens_enabled = True
    c2, h2 = web_client(gw2, db2)
    res = c2.post("/api/settings/import", json=conf, headers=h2).json()
    assert res["legacy"] is False
    plains = [gw2.key_manager.decrypt(k) for k in gw2.key_manager.list_all()]
    assert original_plain in plains, "导入后 Key 无法还原"
    assert gw2.tokens.resolve("PLAIN-TENANT") is not None


def test_legacy_import_skips_undecryptable():
    """旧版导出的异机密文应被跳过, 不得当成明文写入。"""
    gw, db = make_gateway()
    c, h = web_client(gw, db)
    legacy = {
        "app": "InterGate",
        "settings": {},
        "keys": [{"provider": "custom", "encrypted_key": "ZmFrZS1jaXBoZXI=",
                  "name": "old"}],
        "tokens": [{"name": "oldt", "token": "ZmFrZS10b2tlbg=="}],
    }
    res = c.post("/api/settings/import", json=legacy, headers=h).json()
    assert res["legacy"] is True and res["skipped"] == 2
    assert res["keys"] == 0 and res["tokens"] == 0
    plains = [gw.key_manager.decrypt(k) for k in gw.key_manager.list_all()]
    assert all(plains), "产生了空密钥/把密文当明文"


# ---------------------------------------------------------------- 13
def test_query_string_is_forwarded():
    """查询串必须透传给上游(alt=sse / api-version 等)。"""
    gw, db = make_gateway()
    stub = gw.upstream
    gw.settings.cache_enabled = False
    c = TestClient(gw.app)
    c.post("/v1/embeddings?trace=1", json={"model": "m", "input": "x"})
    assert stub.urls[-1].endswith("/v1/embeddings?trace=1"), stub.urls[-1]

    gw2, _ = make_gateway()
    stub2 = gw2.upstream
    gw2.settings.cache_enabled = False
    gw2.key_manager.delete_key(gw2.key_manager.list_all()[0].id)
    gw2.key_manager.add_key("google", "sk-g", name="g")
    c2 = TestClient(gw2.app)
    c2.post("/v1beta/models/gemini-pro:generateContent?alt=sse",
            json={"contents": []})
    assert "alt=sse" in stub2.urls[-1], stub2.urls[-1]


# ---------------------------------------------------------------- 14
def test_anthropic_auth_header():
    """Anthropic 上游须带 x-api-key; 其它上游不得串味。"""
    gw, db = make_gateway()
    req = _FakeReq({"anthropic-version": "2023-06-01",
                    "authorization": "Bearer gw",
                    "x-api-key": "client-key",
                    "x-forwarded-for": "1.2.3.4",
                    "via": "proxy",
                    "user-agent": "app/1"})
    ant = gw._build_upstream_headers(req, "sk-ant", "anthropic")
    assert ant["x-api-key"] == "sk-ant"
    assert ant["anthropic-version"] == "2023-06-01"
    assert "x-forwarded-for" not in ant and "via" not in ant

    oai = gw._build_upstream_headers(req, "sk-oai", "openai")
    assert "x-api-key" not in oai
    assert "anthropic-version" not in oai, "anthropic 协议头污染了 openai 上游"
    assert oai["Authorization"] == "Bearer sk-oai"


# ---------------------------------------------------------------- 15
def test_quota_alert_is_throttled():
    """额度耗尽不得每个请求都写告警/推 webhook。"""
    gw, db = make_gateway()
    pushed = []
    gw.quota._webhook = lambda title, content: pushed.append(title)
    k = gw.key_manager.list_all()[0]
    k.daily_quota = 100
    for _ in range(30):
        gw.quota.record(k, 200, {"prompt_tokens": 50, "completion_tokens": 10})
    assert len(gw.quota.alerts) == 1, "告警风暴: %d 条" % len(gw.quota.alerts)
    assert len(pushed) == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
