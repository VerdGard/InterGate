"""网关 + Web 集成冒烟测试(需先安装 fastapi/uvicorn/httpx/cryptography)。

运行: python3 tests/gateway_smoke.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_gw_")

from fastapi.testclient import TestClient  # noqa: E402

from config.settings import UserSettings  # noqa: E402
from db.database import Database  # noqa: E402
from gateway import GatewayApp  # noqa: E402
from providers.upstream import UpstreamResult  # noqa: E402
from webapp import WebApp  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


class FakeUpstream:
    """模拟上游:可配置响应序列。"""

    def __init__(self):
        self.responses: list = []
        self.calls: list = []
        self.fail_first = 0   # 前 N 次 forward 返回 500

    def _next(self):
        self.calls.append(len(self.calls))
        if self.fail_first > 0:
            self.fail_first -= 1
            return UpstreamResult(500, {}, b'{"error":{"message":"upstream boom"}}',
                                  error="upstream boom")
        if self.responses:
            return self.responses.pop(0)
        return UpstreamResult(
            200, {"content-type": "application/json"},
            json.dumps({"id": "chatcmpl-1", "model": "gpt-4o",
                        "choices": [{"message": {"content": "hi"}}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5,
                                  "total_tokens": 15}}).encode(),
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    async def forward(self, method, url, headers, body):
        self.last_url = url
        return self._next()

    async def open_stream(self, method, url, headers, body):
        async def gen():
            yield b'data: {"choices":[{"delta":{"content":"he"}}]}\n\n'
            yield b'data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}\n\n'
            yield b"data: [DONE]\n\n"
        return 200, {"content-type": "text/event-stream"}, gen()

    async def get_json(self, url, headers=None):
        return {"data": [{"id": "gpt-4o", "owned_by": "openai"}]}

    async def aclose(self):
        pass


def make_gateway(settings: UserSettings):
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "gw.db"))
    gw = GatewayApp(settings, db)
    gw.upstream = FakeUpstream()
    # 添加两个 key(用于失败切换测试)
    gw.key_manager.add_key("custom", "sk-fake-1", name="k1",
                           base_url="https://fake.example/v1", priority=10)
    gw.key_manager.add_key("custom", "sk-fake-2", name="k2",
                           base_url="https://fake.example/v1", priority=20)
    return gw, db


def test_gateway_proxy():
    print("gateway 代理转发")
    gw, db = make_gateway(UserSettings())
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    check("转发 200", r.status_code == 200, str(r.status_code))
    check("返回体透传", r.json().get("choices", [{}])[0].get("message", {}).get("content") == "hi")
    db.flush_now()   # 冲刷批量异步写, 使统计/日志立即可见
    check("用量已统计", gw.quota.summary(7)["total"]["requests"] == 1)
    check("日志已记录", len(gw.db.query_logs()) == 1)
    # base_url 含 /v1 时不应产生双 /v1
    check("URL 去重(无双 /v1)", gw.upstream.last_url ==
          "https://fake.example/v1/chat/completions",
          getattr(gw.upstream, "last_url", "None"))

    # 缓存命中
    r2 = c.post("/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    check("缓存命中头", r2.headers.get("x-relay-cache") == "HIT")
    check("缓存命中响应", r2.json().get("id") == "chatcmpl-1")

    # 健康检查
    check("health", c.get("/health").json()["status"] == "ok")
    # 管理端点匿名访问应被拒绝(未配置网关密钥时不再放行)
    check("version 匿名 401", c.get("/relay/version").status_code == 401)

    # 流式
    r3 = c.post("/v1/chat/completions",
                json={"model": "gpt-4o", "stream": True,
                      "messages": [{"role": "user", "content": "s"}]})
    check("SSE 200", r3.status_code == 200)
    check("SSE 内容", "data: [DONE]" in r3.text)


def test_failover():
    print("失败自动切换")
    gw, _ = make_gateway(UserSettings())
    gw.upstream.fail_first = 1   # 第一次 500,第二次成功
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]})
    check("切换后 200", r.status_code == 200, str(r.status_code))
    k1 = next((k for k in gw.key_manager.list_all() if k.name == "k1"), None)
    check("k1 失败计数=1", k1 is not None and k1.failure_count == 1,
          str(k1.failure_count if k1 else None))


def test_auth_and_ratelimit():
    print("鉴权与限流")
    gw, _ = make_gateway(UserSettings(gateway_key="secret"))
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": []})
    check("无鉴权 401", r.status_code == 401, str(r.status_code))
    r = c.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": []},
               headers={"Authorization": "Bearer secret"})
    check("带鉴权放行", r.status_code == 200)

    gw2, _ = make_gateway(UserSettings(ip_rate_limit_per_minute=1))
    c2 = TestClient(gw2.app)
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "a"}]}
    check("限流前放行", c2.post("/v1/chat/completions", json=body).status_code == 200)
    r = c2.post("/v1/chat/completions", json=body)
    check("IP 限流 429", r.status_code == 429, str(r.status_code))


def test_webapp():
    print("Web 管理 API")
    gw, db = make_gateway(UserSettings(web_password="test-pwd"))
    web = WebApp(gw, db)
    # 登录获取签名 token, 后续请求携带
    login = TestClient(web.app)
    tok = login.post("/api/login", json={"password": "test-pwd"}).json()["token"]
    c = TestClient(web.app, headers={"Authorization": f"Bearer {tok}"})

    r = c.get("/api/status")
    check("status", r.status_code == 200 and r.json()["app"] == "InterGate")

    # 网关开关真正控制转发
    gwc = TestClient(gw.app)
    r = c.post("/api/gateway/toggle", json={"enabled": False})
    check("暂停网关", r.json()["gateway_enabled"] is False)
    body = {"model": "gpt-4o", "messages": []}
    r = gwc.post("/v1/chat/completions", json=body)
    check("暂停后转发 503(gateway_paused)",
          r.status_code == 503 and r.json()["error"]["type"] == "gateway_paused",
          r.text)
    r = gwc.get("/health")
    check("暂停时管理接口可用", r.status_code == 200)
    r = c.post("/api/gateway/toggle", json={"enabled": True})
    check("恢复网关", r.json()["gateway_enabled"] is True)
    r = gwc.post("/v1/chat/completions", json=body)
    check("恢复后转发正常(200)", r.status_code == 200, r.text[:200])

    # 模型开关: 关闭后不暴露给网关
    gw.syncer._models = {
        "gpt-4o": {"id": "gpt-4o", "provider": "openai",
                   "capabilities": ["chat"], "enabled": True},
        "deepseek-v4-flash": {"id": "deepseek-v4-flash", "provider": "deepseek",
                              "capabilities": ["chat"], "enabled": True},
    }
    gw.syncer.last_sync = 123
    r = gwc.get("/v1/models")
    ids = [m["id"] for m in r.json()["data"]]
    check("初始暴露全部模型", "gpt-4o" in ids and "deepseek-v4-flash" in ids,
          str(ids))

    r = c.put("/api/models/deepseek-v4-flash", json={"enabled": False})
    check("关闭模型开关", r.json()["enabled"] is False and
          r.json()["models_count"] == 1, r.text)
    r = gwc.get("/v1/models")
    ids = [m["id"] for m in r.json()["data"]]
    check("关闭后网关不暴露", "deepseek-v4-flash" not in ids and
          "gpt-4o" in ids, str(ids))

    # 持久化: 新实例加载开关状态
    db2 = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "gw.db"))
    gw2 = GatewayApp(UserSettings(), db2)
    gw2.syncer._models = {
        "deepseek-v4-flash": {"id": "deepseek-v4-flash", "provider": "deepseek",
                              "capabilities": ["chat"],
                              "enabled": gw2.syncer._states.get(
                                  "deepseek-v4-flash", True)},
    }
    check("开关状态持久化", gw2.syncer.get("deepseek-v4-flash")["enabled"] is False)

    r = c.put("/api/models/deepseek-v4-flash", json={"enabled": True})
    r = gwc.get("/v1/models")
    ids = [m["id"] for m in r.json()["data"]]
    check("重新开启后恢复暴露", "deepseek-v4-flash" in ids, str(ids))

    r = c.get("/")
    check("控制台页面", r.status_code == 200 and "<html" in r.text.lower())

    # 通过 Web API 添加 Key(加密存储)
    r = c.post("/api/keys", json={"provider": "openai", "api_key": "sk-web-abc",
                                  "name": "web-key"})
    check("Web 添加 Key", r.status_code == 200, r.text)
    kid = r.json()["id"]
    check("密文非明文", r.json()["key"] != "sk-web-abc" and r.json()["key"])

    keys = c.get("/api/keys").json()
    check("Key 列表", any(k["id"] == kid for k in keys))

    # 编辑
    r = c.put(f"/api/keys/{kid}", json={"priority": 5})
    check("编辑 Key", r.status_code == 200 and r.json()["priority"] == 5)

    # 设置保存
    r = c.put("/api/settings", json={"port": 51234, "load_balance_strategy": "priority"})
    check("保存设置", r.status_code == 200 and r.json()["ok"])

    # 日志查询
    r = c.get("/api/logs")
    check("日志接口", r.status_code == 200)

    # 删除
    r = c.delete(f"/api/keys/{kid}")
    check("删除 Key", r.status_code == 200)


if __name__ == "__main__":
    test_gateway_proxy()
    test_failover()
    test_auth_and_ratelimit()
    test_webapp()
    print(f"\n全部通过: {PASS} 项断言")
