"""网关请求流程测试:鉴权/缓存/失败切换/SSE/限流/健康检查。"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_gw_flow_")

from fastapi.testclient import TestClient  # noqa: E402

from config.settings import UserSettings  # noqa: E402
from db.database import Database  # noqa: E402
from gateway import GatewayApp  # noqa: E402
from providers.upstream import UpstreamResult  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


class FakeUpstream:
    """模拟上游客户端。"""
    def __init__(self):
        self.fail_first = 0
        self.last_url = ""
        self.call_count = 0
        self._next_status = 200
        self._next_body = None

    async def forward(self, method, url, headers, body):
        self.call_count += 1
        self.last_url = url
        if self.fail_first > 0:
            self.fail_first -= 1
            return UpstreamResult(500, {}, b'{"error":{"message":"fail"}}', error="fail")
        if self._next_body is not None:
            body_data = self._next_body
            self._next_body = None
            return UpstreamResult(self._next_status, {"content-type": "application/json"},
                                  body_data,
                                  usage={"prompt_tokens": 10, "completion_tokens": 5})
        return UpstreamResult(200, {"content-type": "application/json"},
                              json.dumps({
                                  "id": "chatcmpl-1", "model": "gpt-4o",
                                  "choices": [{"message": {"content": "hello"}}],
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                              }).encode(),
                              usage={"prompt_tokens": 10, "completion_tokens": 5})

    async def open_stream(self, method, url, headers, body):
        async def gen():
            yield b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
            yield b'data: {"usage":{"prompt_tokens":3,"completion_tokens":2}}\n\n'
            yield b"data: [DONE]\n\n"
        return 200, {"content-type": "text/event-stream"}, gen()

    async def get_json(self, url, headers=None):
        return {"data": [{"id": "gpt-4o", "owned_by": "openai"}]}

    async def aclose(self):
        pass


def _make_gateway(settings=None, n_keys=2):
    settings = settings or UserSettings()
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], f"gw_{PASS}.db"))
    gw = GatewayApp(settings, db)
    gw.upstream = FakeUpstream()
    for i in range(n_keys):
        gw.key_manager.add_key("custom", f"sk-fake-{i}", name=f"k{i}",
                               base_url="https://fake.example/v1", priority=10+i*10)
    return gw, db


def test_basic_proxy():
    print("基础代理转发")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o",
                     "messages": [{"role": "user", "content": "hi"}]})
    check("转发 200", r.status_code == 200, str(r.status_code))
    check("响应透传", r.json()["choices"][0]["message"]["content"] == "hello")
    check("URL 去重", gw.upstream.last_url ==
          "https://fake.example/v1/chat/completions",
          getattr(gw.upstream, "last_url", ""))


def test_cache_hit():
    print("缓存命中")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "same"}]}
    r1 = c.post("/v1/chat/completions", json=body)
    check("首次 MISS", r1.headers.get("x-relay-cache") == "MISS")
    r2 = c.post("/v1/chat/completions", json=body)
    check("二次 HIT", r2.headers.get("x-relay-cache") == "HIT")
    check("缓存内容一致", r1.json() == r2.json())


def test_failover():
    print("失败自动切换")
    gw, _ = _make_gateway(n_keys=3)
    gw.upstream.fail_first = 1  # 第一个 Key 失败
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]})
    check("切换后成功", r.status_code == 200, str(r.status_code))
    check("调用了 2 次(1 失败 + 1 成功)", gw.upstream.call_count == 2,
          str(gw.upstream.call_count))


def test_all_fail():
    print("全部失败")
    gw, _ = _make_gateway(n_keys=2)
    gw.upstream.fail_first = 10  # 全部失败
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]})
    check("返回 500", r.status_code == 500, str(r.status_code))


def test_auth_required():
    print("鉴权要求")
    gw, _ = _make_gateway(UserSettings(gateway_key="secret"))
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": []})
    check("无 Key 401", r.status_code == 401)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": []},
               headers={"Authorization": "Bearer secret"})
    check("正确 Key 放行", r.status_code == 200)


def test_auth_disabled():
    print("鉴权关闭")
    gw, _ = _make_gateway(UserSettings(gateway_key_enabled=False, gateway_key="secret"))
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "a"}]})
    check("关闭鉴权后放行", r.status_code == 200, str(r.status_code))


def test_gateway_paused():
    print("网关暂停")
    gw, _ = _make_gateway()
    gw.settings.gateway_enabled = False
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": []})
    check("暂停后 503", r.status_code == 503)
    check("错误类型 gateway_paused", r.json()["error"]["type"] == "gateway_paused")
    # 健康检查不受影响
    r = c.get("/health")
    check("健康检查仍可用", r.status_code == 200)


def test_health_check():
    print("健康检查")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    r = c.get("/health")
    check("200", r.status_code == 200)
    body = r.json()
    check("status=ok", body["status"] == "ok")
    check("有 active_keys", "active_keys" in body)
    check("有 uptime", "uptime_s" in body)


def test_sse_stream():
    print("SSE 流式")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "stream": True,
                     "messages": [{"role": "user", "content": "s"}]})
    check("SSE 200", r.status_code == 200)
    check("SSE 包含 DONE", "data: [DONE]" in r.text)
    check("SSE 内容透传", "hi" in r.text)


def test_ip_rate_limit():
    print("IP 限流")
    gw, _ = _make_gateway(UserSettings(ip_rate_limit_per_minute=1))
    c = TestClient(gw.app)
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "a"}]}
    r1 = c.post("/v1/chat/completions", json=body)
    check("首次放行", r1.status_code == 200)
    r2 = c.post("/v1/chat/completions", json=body)
    check("二次 429", r2.status_code == 429, str(r2.status_code))


def test_management_endpoints():
    print("管理接口")
    gw, _ = _make_gateway(UserSettings(gateway_key="secret"))
    c = TestClient(gw.app)
    h = {"Authorization": "Bearer secret"}
    r = c.get("/relay/version", headers=h)
    check("version", r.status_code == 200 and "version" in r.json())
    r = c.get("/relay/stats", headers=h)
    check("stats", r.status_code == 200 and "active_keys" in r.json())
    r = c.get("/relay/report", headers=h)
    check("report", r.status_code == 200 and "summary" in r.json())
    r = c.get("/relay/metrics", headers=h)
    check("metrics", r.status_code == 200
          and "intergate_keys_total" in r.text
          and "text/plain" in r.headers.get("content-type", ""))


def test_no_available_key():
    print("无可用 Key")
    settings = UserSettings()
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], f"gw_{PASS}_nokey.db"))
    gw = GatewayApp(settings, db)
    gw.upstream = FakeUpstream()
    # 不添加任何 Key
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]})
    check("503 无可用 Key", r.status_code == 503)


def test_local_models():
    print("本地模型列表")
    gw, _ = _make_gateway()
    gw.syncer._models = {
        ("gpt-4o", "k0", "https://fake.example/v1"): {
            "id": "gpt-4o", "name": "gpt-4o", "provider": "openai",
            "capabilities": ["chat"], "enabled": True,
        },
    }
    gw.syncer.last_sync = 123
    c = TestClient(gw.app)
    r = c.get("/v1/models")
    check("200", r.status_code == 200)
    check("返回模型列表", r.json()["object"] == "list")
    check("包含 gpt-4o", any(m["id"] == "gpt-4o" for m in r.json()["data"]))


def test_log_written():
    print("日志写入")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    c.post("/v1/chat/completions",
           json={"model": "gpt-4o", "messages": [{"role": "user", "content": "a"}]})
    gw.db.flush_now()
    logs = gw.db.query_logs()
    check("日志 1 条", len(logs) == 1)
    check("日志 status=200", logs[0]["status"] == 200)


def test_quota_recorded():
    print("额度统计")
    gw, _ = _make_gateway()
    c = TestClient(gw.app)
    c.post("/v1/chat/completions",
           json={"model": "gpt-4o", "messages": [{"role": "user", "content": "a"}]})
    gw.db.flush_now()
    summary = gw.quota.summary(7)
    check("统计 1 次请求", summary["total"]["requests"] == 1)
    check("统计有 prompt_tokens", summary["total"]["prompt_tokens"] > 0)


if __name__ == "__main__":
    test_basic_proxy()
    test_cache_hit()
    test_failover()
    test_all_fail()
    test_auth_required()
    test_auth_disabled()
    test_gateway_paused()
    test_health_check()
    test_sse_stream()
    test_ip_rate_limit()
    test_management_endpoints()
    test_no_available_key()
    test_local_models()
    test_log_written()
    test_quota_recorded()
    print(f"\n全部通过: {PASS} 项断言")
