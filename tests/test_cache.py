"""响应缓存测试:LRU/TTL/统计/失效。"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("INTERGATE_DATA_DIR", "/tmp/ig_cache_test")

from services.cache import ResponseCache  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


def test_basic_put_get():
    print("基础存取")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=10)
    key = c.make_key("POST", "/v1/chat/completions", b'{"model":"gpt-4o"}')
    check("空缓存返回 None", c.get(key) is None)

    c.put(key, 200, {"content-type": "application/json"}, b'{"id":"1"}')
    hit = c.get(key)
    check("命中返回 tuple", hit is not None)
    status, headers, body = hit
    check("status 正确", status == 200)
    check("body 正确", body == b'{"id":"1"}')
    check("headers 正确", headers.get("content-type") == "application/json")


def test_cache_disabled():
    print("缓存关闭")
    c = ResponseCache(enabled=False)
    key = c.make_key("POST", "/v1/x", b"{}")
    c.put(key, 200, {}, b"data")
    check("关闭后 get 返回 None", c.get(key) is None)
    check("misses 递增", c.misses > 0)


def test_ttl_expiry():
    print("TTL 过期")
    c = ResponseCache(enabled=True, ttl_seconds=0.3, max_entries=10)
    key = c.make_key("GET", "/v1/models", b"")
    c.put(key, 200, {}, b"models")
    check("TTL 内命中", c.get(key) is not None)
    time.sleep(0.4)
    check("TTL 过期后 miss", c.get(key) is None)


def test_lru_eviction():
    print("LRU 淘汰")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=3)
    k1 = c.make_key("POST", "/a", b"1")
    k2 = c.make_key("POST", "/b", b"2")
    k3 = c.make_key("POST", "/c", b"3")
    c.put(k1, 200, {}, b"1")
    c.put(k2, 200, {}, b"2")
    c.put(k3, 200, {}, b"3")
    # 访问 k1, 使 k2 成为最久未用
    c.get(k1)
    # 插入 k4, 应淘汰 k2(LRU)
    k4 = c.make_key("POST", "/d", b"4")
    c.put(k4, 200, {}, b"4")
    check("k1 保留(最近访问)", c.get(k1) is not None)
    check("k2 被淘汰", c.get(k2) is None)
    check("k3 保留", c.get(k3) is not None)
    check("k4 保留", c.get(k4) is not None)


def test_non_2xx_not_cached():
    print("非 2xx 不缓存")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=10)
    key = c.make_key("POST", "/x", b"{}")
    c.put(key, 404, {}, b"not found")
    c.put(key, 500, {}, b"server error")
    check("404 不缓存", c.get(key) is None)


def test_large_body_not_cached():
    print("大响应体不缓存")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=10,
                      max_body_bytes=100)
    key = c.make_key("POST", "/big", b"{}")
    c.put(key, 200, {}, b"x" * 200)
    check("超限不缓存", c.get(key) is None)


def test_invalidate():
    print("缓存失效")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=10)
    c.put(c.make_key("POST", "/a", b"1"), 200, {}, b"1")
    c.put(c.make_key("POST", "/a", b"2"), 200, {}, b"2")
    c.put(c.make_key("POST", "/b", b"3"), 200, {}, b"3")
    # 全部清除
    cleared = c.invalidate()
    check("清除 3 条", cleared == 3, str(cleared))
    check("清除后空", c.get(c.make_key("POST", "/a", b"1")) is None)


def test_invalidate_by_prefix():
    print("按前缀清除")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=10)
    # make_key 返回 hex, 无法按前缀区分; 但 invalidate() 支持前缀
    # 因为 key 是 hex, 前缀匹配实际不会命中, 这里测试空前缀 = 全清
    c.put(c.make_key("POST", "/a", b"1"), 200, {}, b"1")
    cleared = c.invalidate(prefix="")
    check("空前缀全清", cleared == 1)
    cleared2 = c.invalidate(prefix="")
    check("再清无内容", cleared2 == 0)


def test_stats():
    print("统计信息")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=5)
    k1 = c.make_key("POST", "/a", b"1")
    c.put(k1, 200, {}, b"1")
    c.get(k1)  # hit
    c.get(c.make_key("POST", "/b", b"2"))  # miss
    stats = c.stats()
    check("有 entries", stats["entries"] == 1)
    check("hits=1", stats["hits"] == 1)
    check("misses>=1", stats["misses"] >= 1)
    check("hit_rate > 0", stats["hit_rate"] > 0)
    check("有 max_entries", stats["max_entries"] == 5)
    check("有 ttl", stats["ttl_seconds"] == 60)
    check("enabled=True", stats["enabled"] is True)


def test_make_key_consistency():
    print("缓存键一致性")
    k1 = ResponseCache.make_key("POST", "/v1/chat/completions", b'{"a":1}')
    k2 = ResponseCache.make_key("POST", "/v1/chat/completions", b'{"a":1}')
    k3 = ResponseCache.make_key("POST", "/v1/chat/completions", b'{"a":2}')
    k4 = ResponseCache.make_key("GET", "/v1/chat/completions", b'{"a":1}')
    check("相同输入相同 key", k1 == k2)
    check("不同 body 不同 key", k1 != k3)
    check("不同 method 不同 key", k1 != k4)


def test_move_to_end_on_get():
    print("get 后提升到最新(LRU move_to_end)")
    c = ResponseCache(enabled=True, ttl_seconds=60, max_entries=2)
    k1 = c.make_key("POST", "/a", b"1")
    k2 = c.make_key("POST", "/b", b"2")
    c.put(k1, 200, {}, b"1")
    c.put(k2, 200, {}, b"2")
    # get k1 使其成为最新
    c.get(k1)
    # 插入 k3, 应淘汰 k2(最久未用)
    k3 = c.make_key("POST", "/c", b"3")
    c.put(k3, 200, {}, b"3")
    check("k1 保留(get 后提升)", c.get(k1) is not None)
    check("k2 被淘汰", c.get(k2) is None)


if __name__ == "__main__":
    test_basic_put_get()
    test_cache_disabled()
    test_ttl_expiry()
    test_lru_eviction()
    test_non_2xx_not_cached()
    test_large_body_not_cached()
    test_invalidate()
    test_invalidate_by_prefix()
    test_stats()
    test_make_key_consistency()
    test_move_to_end_on_get()
    print(f"\n全部通过: {PASS} 项断言")
