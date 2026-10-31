"""API Key 本地加密:AES-256-GCM,主密钥存于 data/.master_key(权限 0600)。

设计说明:
- 首次启动生成随机 32 字节主密钥并落盘(仅本用户可读)。
- 所有 API Key 明文仅在创建时加密、转发时临时解密,存储与日志不保留明文。
"""
from __future__ import annotations

import base64
import os
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_FILE = "data/.master_key"
_lock = threading.Lock()
_cached_key: bytes | None = None


def _data_dir() -> str:
    """相对项目根目录的 data 目录。"""
    base = os.environ.get("INTERGATE_DATA_DIR")
    if base:
        return base
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def ensure_master_key() -> bytes:
    global _cached_key
    with _lock:
        if _cached_key is not None:
            return _cached_key
        path = os.path.join(_data_dir(), ".master_key")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as f:
                _cached_key = f.read().strip()
        else:
            _cached_key = os.urandom(32)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(_cached_key)
        if len(_cached_key) not in (16, 24, 32):
            raise ValueError("master key 长度必须为 16/24/32 字节")
        return _cached_key


def encrypt_plaintext(plain: str) -> str:
    """加密,返回 base64(nonce + ciphertext + tag)。"""
    if not plain:
        return ""
    key = ensure_master_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_plaintext(blob: str) -> str:
    """解密 encrypt_plaintext 的输出。"""
    if not blob:
        return ""
    key = ensure_master_key()
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
