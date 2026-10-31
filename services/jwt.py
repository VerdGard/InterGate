"""极简 JWT(HS256) 签发与校验, 无第三方依赖。

用于可选的网关鉴权: 外部系统可用密钥签发短期 JWT 作为访问凭证,
替代长期静态 Bearer Key, 便于轮换。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(secret: str, msg: bytes) -> str:
    return _b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())


def create_token(secret: str, payload: Dict[str, Any],
                 ttl_seconds: int = 3600) -> str:
    """签发 HS256 JWT。payload 需含 sub 等, 自动注入 exp。"""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = dict(payload)
    body["iat"] = int(time.time())
    body["exp"] = int(time.time()) + ttl_seconds
    payload_b64 = _b64url(json.dumps(body, ensure_ascii=False).encode())
    signing_input = f"{header}.{payload_b64}".encode()
    return f"{header}.{payload_b64}.{_sign(secret, signing_input)}"


def verify_token(secret: str, token: str,
                 leeway: int = 30) -> Optional[Dict[str, Any]]:
    """校验并返回 payload; 非法/过期返回 None。"""
    try:
        header_b64, payload_b64, sig = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        if not hmac.compare_digest(_sign(secret, signing_input), sig):
            return None
        payload = json.loads(_unb64url(payload_b64))
    except Exception:
        return None
    now = time.time()
    if payload.get("exp") and now > int(payload["exp"]) + leeway:
        return None
    if payload.get("nbf") and now < int(payload["nbf"]) - leeway:
        return None
    return payload
