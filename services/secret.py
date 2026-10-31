"""敏感字段安全工具:密码加盐哈希 + 落盘字段 AES 加密。

- hash_password / verify_password: 管理台密码用 PBKDF2-SHA256 加盐哈希存储,
  避免明文落盘; 兼容迁移旧明文。
- encrypt_field / decrypt_field: 网关 Key、附加网关密钥、Webhook Secret 等
  敏感字段在落盘(SQLite)时用 AES-256-GCM 加密, 运行时内存保留明文供热路径比对。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from crypto import aes

_PBKDF2_ITERATIONS = 260_000
_HASH_PREFIX = "$pbkdf2$"
_ENC_PREFIX = "enc$"

# ---------------------------------------------------------------- 密码哈希
def hash_password(password: str) -> str:
    """对密码做 PBKDF2-SHA256 加盐哈希, 返回存储格式 $pbkdf2$iter$salt$hash。"""
    if not password:
        return ""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return _HASH_PREFIX + str(_PBKDF2_ITERATIONS) + "$" + \
        base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def is_hashed(stored: str) -> bool:
    """判断 stored 是否为 PBKDF2 哈希格式(而非旧明文)。"""
    return bool(stored) and stored.startswith(_HASH_PREFIX)


def verify_password(password: str, stored: str):
    """校验密码。返回 (ok, needs_migrate)。"""
    if not stored:
        # 未设置密码 -> 免密(仅本机)
        return True, False
    if not is_hashed(stored):
        # 旧明文: 直接比对; 成功后可迁移为哈希
        return hmac.compare_digest(password, stored), True
    try:
        _prefix, _algo, iters_s, salt_s, hash_s = stored.split("$", 4)
        iters = int(iters_s)
        salt = base64.b64decode(salt_s)
        expected = base64.b64decode(hash_s)
    except Exception:
        return False, False
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(dk, expected), False


# ---------------------------------------------------------------- 字段落盘加密
def encrypt_field(plain: str | None) -> str:
    """落盘前加密。空值原样返回。旧明文(非 enc$ 前缀)保持不动以便迁移。"""
    if not plain:
        return ""
    if plain.startswith(_ENC_PREFIX):
        return plain
    return _ENC_PREFIX + aes.encrypt_plaintext(plain)


def decrypt_field(stored: str | None) -> str:
    """读取时解密。返回明文。空值/旧明文原样返回。"""
    if not stored:
        return ""
    if stored.startswith(_ENC_PREFIX):
        try:
            return aes.decrypt_plaintext(stored[len(_ENC_PREFIX):])
        except Exception:
            return ""
    return stored
