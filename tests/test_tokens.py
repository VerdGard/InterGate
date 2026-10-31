"""多租户 Token / JWT / 密码哈希 / 共享状态 测试。"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from crypto.aes import decrypt_plaintext
from db.database import get_db
from services.token_manager import TokenManager


@pytest.fixture
def tm():
    db = get_db()
    for row in db.list_tokens():
        db.delete_token(row["id"])
    return TokenManager(db)


def test_add_and_resolve(tm):
    t = tm.add("租户A", plain_token="tok-abc", daily_quota_usd=5.0,
               max_requests_per_minute=10, models=["gpt-4o"])
    plain = decrypt_plaintext(t.token)
    got = tm.resolve(plain)
    assert got is not None and got.id == t.id
    # 禁用的不能解析
    tm.update(t, enabled=False)
    assert tm.resolve(plain) is None


def test_quota_and_usage(tm):
    t = tm.add("租户B", plain_token="tok-b", daily_quota_usd=1.0)
    assert tm.check_quota(t, 0.5) is None
    tm.record_usage(t, 0.6)
    t2 = tm.get(t.id)
    assert t2.today_used_usd == pytest.approx(0.6)
    assert tm.check_quota(t2, 0.5) == "quota_exhausted"


def test_delete_and_crud(tm):
    t = tm.add("租户C", plain_token="tok-c")
    plain = decrypt_plaintext(t.token)
    assert tm.delete(t.id) is True
    assert tm.resolve(plain) is None


def test_reload_index(tm):
    t = tm.add("租户D", plain_token="tok-d")
    plain = decrypt_plaintext(t.token)
    tm2 = TokenManager(get_db())   # 模拟重启
    assert tm2.resolve(plain).id == t.id
    tm2.delete(t.id)


def test_password_hash_migration():
    from services.secret import hash_password, verify_password, is_hashed
    h = hash_password("secret123")
    assert is_hashed(h)
    ok, migrate = verify_password("secret123", h)
    assert ok and not migrate
    ok2, migrate2 = verify_password("wrong", h)
    assert not ok2
    # 旧明文
    ok3, migrate3 = verify_password("plain", "plain")
    assert ok3 and migrate3


def test_jwt():
    from services.jwt import create_token, verify_token
    tok = create_token("s", {"sub": "a", "models": ["gpt-4o"]}, ttl_seconds=100)
    assert verify_token("s", tok)["sub"] == "a"
    assert verify_token("wrong", tok) is None


def test_shared_state():
    from services import shared_state
    c = shared_state.SharedCounter(window_sec=60)
    assert c.add("k") >= 1
    assert c.add("k") >= 2
    cc = shared_state.SharedCache(ttl_seconds=30)
    k = cc.make_key("GET", "/x", b"b")
    cc.put(k, 200, {"h": "1"}, b"body")
    got = cc.get(k)
    assert got and got[0] == 200 and got[1]["h"] == "1"
    assert cc.stats()["entries"] >= 1


# ---------------- 端到端网关转发 ----------------
def test_tenant_gateway_flow(tmp_path, monkeypatch):
    import json as _json
    from fastapi.testclient import TestClient
    from config.settings import UserSettings
    from db.database import Database
    from gateway import GatewayApp
    from providers.upstream import UpstreamResult

    class FakeUp:
        async def forward(self, method, url, headers, body):
            return UpstreamResult(200, {"content-type": "application/json"},
                                  _json.dumps({
                                      "id": "1", "model": "gpt-4o",
                                      "choices": [{"message": {"content": "ok"}}],
                                      "usage": {"prompt_tokens": 10,
                                                "completion_tokens": 5}}).encode(),
                                  usage={"prompt_tokens": 10, "completion_tokens": 5})
        async def open_stream(self, method, url, headers, body):
            raise AssertionError("should not stream")
        async def aclose(self):
            pass
        async def get_json(self, url, headers=None):
            return {"data": [{"id": "gpt-4o"}]}

    db = Database(str(tmp_path / "t.db"))
    s = UserSettings()
    s.tokens_enabled = True   # 租户 Token 功能需显式开启
    gw = GatewayApp(s, db)
    gw.upstream = FakeUp()
    gw.key_manager.add_key("custom", "sk-1", name="k1", base_url="https://x/v1")
    t = gw.tokens.add("租户E", plain_token="tenant-e", daily_quota_usd=0.01)
    from crypto.aes import decrypt_plaintext
    plain = decrypt_plaintext(t.token)
    c = TestClient(gw.app)
    r = c.post("/v1/chat/completions",
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
               headers={"Authorization": "Bearer " + plain})
    assert r.status_code == 200, r.text
    # 用量应已累计到租户
    t2 = gw.tokens.get(t.id)
    assert t2.requests_today >= 1
    # 关闭租户后拒绝
    gw.tokens.update(t, enabled=False)
    r2 = c.post("/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer " + plain})
    assert r2.status_code == 401
    gw.tokens.delete(t.id)
