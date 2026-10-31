"""Key 管理器测试:CRUD/加密/失败/恢复/冷却。"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_km_")

import time  # noqa: E402

from config import constants as C  # noqa: E402
from crypto.aes import decrypt_plaintext, encrypt_plaintext  # noqa: E402
from db.database import Database  # noqa: E402
from models.api_key import ApiKey, KeyStatus  # noqa: E402
from services.key_manager import KeyManager  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


def _make_km():
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], f"km_{PASS}.db"))
    return KeyManager(db), db


def test_add_and_get():
    print("添加与获取")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-test-12345", name="test1")
    check("返回有 ID", k.id)
    check("返回加密 Key", k.encrypted_key != "sk-test-12345")
    check("名称正确", k.name == "test1")
    check("状态 ACTIVE", k.status == KeyStatus.ACTIVE)

    got = km.get(k.id)
    check("get 返回同一对象", got is not None and got.id == k.id)


def test_decrypt():
    print("解密")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-decrypt-me", name="dec")
    plain = km.decrypt(k)
    check("解密还原", plain == "sk-decrypt-me")

    # 空加密 Key
    k2 = ApiKey(id="empty", provider="openai", encrypted_key="", name="empty")
    check("空 Key 解密返回空", km.decrypt(k2) == "")


def test_list_all_and_active():
    print("列表查询")
    km, _ = _make_km()
    km.add_key("openai", "sk-1", name="a", priority=10)
    km.add_key("openai", "sk-2", name="b", priority=50)
    km.add_key("anthropic", "sk-3", name="c", priority=30)

    all_keys = km.list_all()
    check("3 个 Key", len(all_keys) == 3)
    check("按 provider+priority 排序", all_keys[0].provider == "anthropic")

    active_openai = km.list_active(provider="openai")
    check("openai 2 个 active", len(active_openai) == 2)


def test_update_key():
    print("更新 Key")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-original", name="orig")
    k.name = "updated"
    k.priority = 5
    km.update_key(k)
    got = km.get(k.id)
    check("名称已更新", got.name == "updated")
    check("优先级已更新", got.priority == 5)

    # 更新密钥
    km.update_key(k, plain_key="sk-new-secret")
    got = km.get(k.id)
    check("密钥已加密更新", decrypt_plaintext(got.encrypted_key) == "sk-new-secret")


def test_delete_key():
    print("删除 Key")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-del", name="del")
    check("删除前存在", km.get(k.id) is not None)
    result = km.delete_key(k.id)
    check("删除返回 True", result is True)
    check("删除后不存在", km.get(k.id) is None)
    check("删除不存在的返回 False", km.delete_key("nonexistent") is False)


def test_record_success():
    print("记录成功")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-s", name="s")
    km.record_failure(k.id, "upstream")
    km.record_failure(k.id, "upstream")
    # 两次失败后记录成功应重置 failure_count
    km.record_success(k.id, latency_ms=100)
    got = km.get(k.id)
    check("failure_count 重置", got.failure_count == 0)
    check("status ACTIVE", got.status == KeyStatus.ACTIVE)
    check("cooldown 清除", got.cooldown_until is None)


def test_record_failure_upstream():
    print("记录上游失败(未达阈值)")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-f", name="f")
    km.record_failure(k.id, "upstream")
    got = km.get(k.id)
    check("1 次失败不冷却", got.status == KeyStatus.ACTIVE)
    check("failure_count=1", got.failure_count == 1)


def test_record_failure_threshold():
    print("记录失败达阈值冷却")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-th", name="th")
    for _ in range(C.MAX_FAILURE_THRESHOLD):
        km.record_failure(k.id, "upstream")
    got = km.get(k.id)
    check("达阈值后 ERROR", got.status == KeyStatus.ERROR)
    check("有冷却时间", got.cooldown_until is not None)


def test_record_failure_auth():
    print("记录认证失败")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-auth", name="auth")
    km.record_failure(k.id, "auth")
    got = km.get(k.id)
    check("1 次 auth 即 ERROR", got.status == KeyStatus.ERROR)
    check("有冷却时间", got.cooldown_until is not None)


def test_record_failure_quota():
    print("记录额度耗尽")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-q", name="q")
    km.record_failure(k.id, "quota")
    got = km.get(k.id)
    check("quota 即 EXHAUSTED", got.status == KeyStatus.EXHAUSTED)
    check("长时间冷却", got.cooldown_until is not None)


def test_cooldown_excluded():
    print("冷却期排除")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-c", name="c")
    km.record_failure(k.id, "auth")
    active = km.list_active(provider="openai", exclude_cooldown=True)
    check("冷却中不出现", k.id not in [a.id for a in active])

    # 不排除冷却的可列出
    all_with_cooldown = km.list_active(provider="openai", exclude_cooldown=False)
    check("不排除时可列出", k.id in [a.id for a in all_with_cooldown])


def test_auto_recover():
    print("自动恢复")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-r", name="r")
    km.record_failure(k.id, "upstream")
    km.record_failure(k.id, "upstream")
    km.record_failure(k.id, "upstream")
    check("3 次后 ERROR", km.get(k.id).status == KeyStatus.ERROR)

    # 模拟冷却过期: 手动清除 cooldown_until
    k2 = km.get(k.id)
    k2.cooldown_until = 1  # 过期时间戳
    # list_active 应自动恢复
    active = km.list_active(provider="openai")
    check("冷却过期自动恢复", k.id in [a.id for a in active])
    check("恢复后 ACTIVE", km.get(k.id).status == KeyStatus.ACTIVE)


def test_set_status():
    print("手动设置状态")
    km, _ = _make_km()
    k = km.add_key("openai", "sk-ss", name="ss")
    km.set_status(k.id, KeyStatus.INACTIVE)
    check("设为 INACTIVE", km.get(k.id).status == KeyStatus.INACTIVE)
    km.set_status(k.id, KeyStatus.ACTIVE)
    check("恢复 ACTIVE", km.get(k.id).status == KeyStatus.ACTIVE)
    check("恢复后 cooldown 清除", km.get(k.id).cooldown_until is None)


def test_persistence():
    print("持久化")
    db = Database(os.path.join(os.environ["INTERGATE_DATA_DIR"], "persist.db"))
    km1 = KeyManager(db)
    k = km1.add_key("openai", "sk-persist", name="persist")
    # 新实例从 DB 加载
    km2 = KeyManager(db)
    loaded = km2.get(k.id)
    check("新实例可读取", loaded is not None)
    check("密钥一致", decrypt_plaintext(loaded.encrypted_key) == "sk-persist")


if __name__ == "__main__":
    test_add_and_get()
    test_decrypt()
    test_list_all_and_active()
    test_update_key()
    test_delete_key()
    test_record_success()
    test_record_failure_upstream()
    test_record_failure_threshold()
    test_record_failure_auth()
    test_record_failure_quota()
    test_cooldown_excluded()
    test_auto_recover()
    test_set_status()
    test_persistence()
    print(f"\n全部通过: {PASS} 项断言")
