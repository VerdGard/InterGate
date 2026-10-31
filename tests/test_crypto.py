"""加密模块测试:AES-256-GCM。"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["INTERGATE_DATA_DIR"] = tempfile.mkdtemp(prefix="ig_crypto_")

from crypto.aes import decrypt_plaintext, encrypt_plaintext, ensure_master_key  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS
    assert cond, f"[FAIL] {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


def test_encrypt_decrypt():
    print("加密解密")
    plain = "sk-test-abc-123-def-456"
    blob = encrypt_plaintext(plain)
    check("密文与明文不同", blob != plain)
    check("可解密还原", decrypt_plaintext(blob) == plain)


def test_empty_input():
    print("空值安全")
    check("加密空值返回空", encrypt_plaintext("") == "")
    check("解密空值返回空", decrypt_plaintext("") == "")


def test_unicode():
    print("Unicode 加密")
    plain = "密钥-🔑-unicode-test"
    blob = encrypt_plaintext(plain)
    check("Unicode 可解密", decrypt_plaintext(blob) == plain)


def test_each_encryption_unique():
    print("每次加密不同密文(nonce 随机)")
    plain = "sk-same-input"
    blob1 = encrypt_plaintext(plain)
    blob2 = encrypt_plaintext(plain)
    check("两次加密密文不同", blob1 != blob2)
    check("两次解密一致", decrypt_plaintext(blob1) == plain == decrypt_plaintext(blob2))


def test_master_key_persists():
    print("主密钥持久化")
    key1 = ensure_master_key()
    # 再次调用应返回同一个
    key2 = ensure_master_key()
    check("主密钥一致", key1 == key2)
    check("长度 32", len(key1) == 32)


def test_tamper_detection():
    print("篡改检测")
    plain = "sk-tamper-test"
    blob = encrypt_plaintext(plain)
    # 篡改密文(翻转一位)
    import base64
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode()
    try:
        decrypt_plaintext(tampered)
        check("篡改后应抛异常", False, "未抛异常")
    except Exception:
        check("篡改后抛异常", True)


def test_long_input():
    print("长输入")
    plain = "x" * 10000
    blob = encrypt_plaintext(plain)
    check("长输入可解密", decrypt_plaintext(blob) == plain)


if __name__ == "__main__":
    test_encrypt_decrypt()
    test_empty_input()
    test_unicode()
    test_each_encryption_unique()
    test_master_key_persists()
    test_tamper_detection()
    test_long_input()
    print(f"\n全部通过: {PASS} 项断言")
