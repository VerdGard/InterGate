"""InterGate Web 管理 API(FastAPI,端口 51235)。"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from config import constants as C
from config.pricing import estimate_cost
from config.settings import UserSettings
from db.database import Database, get_db
from gateway import GatewayApp
from models.api_key import KeyStatus

WEB_DIR = Path(__file__).parent / "web"

log = logging.getLogger("intergate.webapp")

# 登录失败限速: ip -> [失败时间戳]
_login_attempts: Dict[str, List[float]] = {}
_LOGIN_MAX_FAILURES = 5
_LOGIN_WINDOW_SECONDS = 60.0

# 敏感字段脱敏: 保留首尾各 4 字符, 中间固定 4 个圆点。
# 掩码值同时用于"前端未修改则原样回传"的判定(_is_mask)。
_MASK_DOTS = "••••"
_PWD_MASK = "••••••"


def _mask(value: str) -> str:
    """脱敏: 仅当长度足够时才保留首尾各 4 字符。

    短密钥(<=12)整体打码, 否则 "jwt-SECRET"(10 字符)会露出 8/10。
    """
    if not value:
        return ""
    if len(value) <= 12:
        return _MASK_DOTS
    return value[:4] + _MASK_DOTS + value[-4:]


def _is_mask(value: str) -> bool:
    """判断是否为 _mask 生成的脱敏值(而非用户真正输入的密钥)。"""
    return bool(value) and _MASK_DOTS in value


def _safe_decrypt(value: str) -> str:
    """尝试把本机密文解成明文; 不是密文(或解不开)则原样返回。"""
    if not value:
        return ""
    from services.secret import decrypt_field
    from crypto.aes import decrypt_plaintext
    raw = str(value)
    if raw.startswith("enc$"):
        return decrypt_field(raw)
    # 旧版导出的租户 Token 是不带前缀的裸密文: 能解开就说明是密文
    try:
        return decrypt_plaintext(raw)
    except Exception:
        return raw


EXPORT_FORMAT_V2 = "intergate-config/2"


def _plain_from_export(value: Any, legacy_cipher: bool = False) -> str:
    """从导入文件取明文密钥。返回空串表示"无法还原, 应跳过"。

    legacy_cipher=True(旧版导出)时, 该字段确定是密文: 只做解密,
    解不开(换机导致主密钥不同)一律跳过, 绝不能把密文当明文写库。
    """
    v = str(value or "").strip()
    if not v:
        return ""
    if v.startswith("enc$"):
        from services.secret import decrypt_field
        return decrypt_field(v)
    if legacy_cipher:
        try:
            from crypto.aes import decrypt_plaintext
            return decrypt_plaintext(v)
        except Exception:
            return ""
    return v          # 新版导出: 字段本身即明文


def _provider_defaults() -> Dict[str, str]:
    return dict(C.PROVIDER_BASE_URLS)


def _detect_ips() -> Dict[str, Any]:
    """探测本机回环地址与局域网 IPv4 地址列表。

    优先用 UDP connect 拿默认路由出口 IP(在 Termux/Android WiFi 下可靠,
    即使无外网也能拿到局域网地址),再尝试解析主机名与 `ip -4 addr` 兜底。
    回环地址固定为 127.0.0.1。
    """
    lan: List[str] = []
    seen: set = set()

    def _add(ip: str) -> None:
        ip = (ip or "").strip()
        if not ip:
            return
        # 去掉 CIDR 后缀(如 192.168.1.167/24)
        ip = ip.split("/")[0]
        if ip.startswith("127.") or ip == "::1":
            return
        if ip not in seen:
            seen.add(ip)
            lan.append(ip)

    # 1) UDP 默认路由出口 IP(不实际发包,仅触发路由选择)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            _add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass

    # 2) 主机名解析
    try:
        import socket
        for info in socket.getaddrinfo(socket.gethostname(), None):
            _add(info[4][0])
    except Exception:
        pass

    # 3) `ip -4 addr` 兜底(部分环境可用)
    try:
        import re
        import subprocess
        out = subprocess.run(["ip", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=3)
        for m in re.finditer(r"inet\s+(\S+)", out.stdout):
            _add(m.group(1))
    except Exception:
        pass

    return {"loopback": "127.0.0.1", "lan": sorted(set(lan))}


class WebApp:
    def __init__(self, gateway: GatewayApp, db: Optional[Database] = None):
        self.gateway = gateway
        self.db = db or gateway.db
        self.settings = gateway.settings
        _pricing_reload(self.db)
        self.app = FastAPI(title="InterGate Web Console", version=C.APP_VERSION,
                           docs_url=None)
        self._routes()

    # ---------------- 路由 ----------------
    def _routes(self) -> None:
        a = self.app

        @a.middleware("http")
        async def auth_middleware(request: Request, call_next):
            if self._is_public(request.url.path):
                return await call_next(request)
            if not self._authorized(request):
                return JSONResponse({"error": "未授权"}, status_code=401)
            return await call_next(request)

        @a.get("/")
        async def index():
            return FileResponse(WEB_DIR / "index.html")

        @a.get("/manifest.json")
        async def manifest():
            return FileResponse(WEB_DIR / "manifest.json",
                                media_type="application/manifest+json")

        @a.get("/sw.js")
        async def sw_js():
            return FileResponse(WEB_DIR / "sw.js", media_type="application/javascript")

        @a.get("/{filename}")
        async def static_file(filename: str):
            # 静态资源(图标等); 不在 web/ 目录则返回 404
            target = (WEB_DIR / filename).resolve()
            if WEB_DIR.resolve() not in target.parents and target != WEB_DIR.resolve():
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            if target.is_file():
                return FileResponse(target)
            return JSONResponse({"detail": "Not Found"}, status_code=404)

        @a.post("/api/login")
        async def login(body: Dict[str, Any], request: Request):
            from services.secret import verify_password, hash_password
            pwd = self.settings.web_password
            ip = request.client.host if request.client else "unknown"
            self._check_login_attempts(ip)
            if not pwd:
                return {"token": self._make_token("local")}
            ok, needs_migrate = verify_password(body.get("password") or "", pwd)
            if ok:
                # 旧明文密码首次登录成功 -> 迁移为 PBKDF2 哈希并落盘
                if needs_migrate:
                    self.settings.web_password = hash_password(body.get("password"))
                    try:
                        self.db.set_setting("user_settings",
                                            self.settings.to_persist_dict())
                    except Exception:
                        pass
                self._clear_login_attempts(ip)
                return {"token": self._make_token("admin")}
            self._record_login_attempt(ip)
            raise HTTPException(401, "密码错误")

        @a.get("/api/status")
        async def status():
            s = self.settings
            return {
                "app": C.APP_NAME,
                "version": C.APP_VERSION,
                "slogan": C.APP_SLOGAN,
                "gateway_enabled": s.gateway_enabled,
                "gateway_host": s.host,
                "gateway_port": s.port,
                "web_port": s.web_port,
                "ips": _detect_ips(),
                "load_balance_strategy": s.load_balance_strategy,
                "uptime": _uptime(),
                "stats": self.gateway._stats_body(),
            }

        @a.get("/api/keys")
        async def list_keys():
            return [k.to_dict() for k in self.gateway.key_manager.list_all()]

        @a.post("/api/keys")
        async def add_key(body: Dict[str, Any]):
            provider = (body.get("provider") or "custom").strip().lower()
            plain = (body.get("api_key") or body.get("key") or "").strip()
            if not plain:
                raise HTTPException(400, "API Key 不能为空")
            if provider not in C.PROVIDER_BASE_URLS:
                raise HTTPException(400, f"未知提供商: {provider}")
            k = self.gateway.key_manager.add_key(
                provider=provider,
                plain_key=plain,
                name=(body.get("name") or "").strip(),
                base_url=(body.get("base_url") or "").strip() or None,
                grp="",
                priority=int(body.get("priority", 100)),
                weight=int(body.get("weight", 1)),
                daily_quota=int(body.get("daily_quota", 1_000_000)),
                max_requests_per_minute=int(body.get("max_requests_per_minute", 60)),
                note=(body.get("note") or "").strip(),
                provider_id=(body.get("provider_id") or "").strip(),
            )
            return k.to_dict()

        @a.put("/api/keys/{key_id}")
        async def update_key(key_id: str, body: Dict[str, Any]):
            k = self.gateway.key_manager.get(key_id)
            if not k:
                raise HTTPException(404, "Key 不存在")
            plain = (body.get("api_key") or "").strip() or None
            for field in ("name", "note"):
                if field in body:
                    setattr(k, field, body[field] or "")
            # 仅当请求显式携带 base_url 时才更新, 避免 {status} 等局部更新清空
            if "base_url" in body:
                k.base_url = (body.get("base_url") or "") or None
            for field in ("priority", "weight", "max_requests_per_minute", "daily_quota"):
                if field in body:
                    setattr(k, field, int(body[field]))
            if body.get("status") in (KeyStatus.ACTIVE, KeyStatus.INACTIVE,
                                      KeyStatus.EXHAUSTED, KeyStatus.ERROR):
                self.gateway.key_manager.set_status(k.id, body["status"])
                # 停用/异常 Key 的模型立即从模型列表移除, 与 Key 管理页一致
                if body["status"] != KeyStatus.ACTIVE:
                    self.gateway.syncer.remove_by_key(k.id)
                else:
                    # 重新启用 Key: 后台同步拉回其模型, 立即生效
                    async def _resync():
                        try:
                            await self.gateway.syncer.sync(
                                self.gateway.key_manager.list_all())
                        except Exception:
                            pass
                    asyncio.create_task(_resync())
            self.gateway.key_manager.update_key(k, plain)
            return k.to_dict()

        @a.delete("/api/keys/{key_id}")
        async def delete_key(key_id: str):
            self.gateway.key_manager.delete_key(key_id)
            # 已删除 Key 的模型立即从模型列表移除
            self.gateway.syncer.remove_by_key(key_id)
            return {"ok": True}

        @a.get("/api/keys/{key_id}/secret")
        async def get_key_secret(key_id: str):
            """返回解密后的明文密钥(仅编辑回显用, 管理台已鉴权)。"""
            k = self.gateway.key_manager.get(key_id)
            if not k:
                raise HTTPException(404, "Key 不存在")
            return {"key_id": key_id, "key": self.gateway.key_manager.decrypt(k)}

        @a.post("/api/keys/{key_id}/test")
        async def test_key(key_id: str):
            result = await self.gateway.key_manager.test_key(
                key_id, client=self.gateway.upstream)
            if not result["ok"]:
                raise HTTPException(400, result.get("message") or "测试失败")
            return result

        @a.post("/api/keys/test-all")
        async def test_all():
            # 并发测试全部 Key(串行在 Key 多时很慢), 复用共享上游连接池
            keys = self.gateway.key_manager.list_all()

            async def _one(k):
                r = await self.gateway.key_manager.test_key(
                    k.id, client=self.gateway.upstream)
                return {"id": k.id, "name": k.name, **r}

            results = await asyncio.gather(*(_one(k) for k in keys))
            return {"results": list(results)}

        @a.get("/api/logs")
        async def logs(limit: int = Query(200, le=1000), offset: int = Query(0, ge=0),
                       provider: str = "", status: Optional[int] = None,
                       key_id: str = "", model: str = "",
                       ts_from: Optional[int] = None, ts_to: Optional[int] = None,
                       before_ts: Optional[int] = None):
            """请求日志。提供 before_ts 时走游标分页(加载更早日志), 否则走 OFFSET。"""
            rows, total = self.db.query_logs(
                limit=limit, offset=offset, provider=provider,
                status=status, key_id=key_id, model=model,
                ts_from=ts_from, ts_to=ts_to, before_ts=before_ts, total=True)
            next_cursor = rows[-1]["ts"] if (rows and before_ts is not None) else None
            return {"logs": rows, "count": len(rows), "total": total,
                    "offset": offset, "limit": limit,
                    "next_cursor": next_cursor,
                    "has_more": next_cursor is not None}

        @a.delete("/api/logs")
        async def clear_logs():
            n = self.db.clear_logs()
            return {"ok": True, "deleted": n}

        @a.get("/api/stats")
        async def stats(days: int = Query(7, ge=1, le=30)):
            import datetime as _dt
            end = _dt.date.today()
            start = end - _dt.timedelta(days=days - 1)

            # 价格预估: 以 stats_daily 已落库费用为主(请求时实时估算写入),
            # 与 request_logs 是否被清理无关
            _rows = self.db.stats_range(start.isoformat(), end.isoformat())
            total_usd = round(sum(r["cost_usd"] or 0 for r in _rows), 6)
            today_usd = round(sum(r["cost_usd"] or 0 for r in _rows
                                  if r["date"] == end.isoformat()), 6)

            # 按模型拆分明细: 优先 request_logs(含 model 字段); 日志被清理时
            # 降级为 stats_daily 聚合条目, 保证图表非空且费用不丢失
            models = []
            for r in self.db.token_usage_by_model(days):
                cost, pin, pout = estimate_cost(
                    r["model"], r["prompt_tokens"], r["completion_tokens"])
                models.append({**r, "cost_usd": round(cost, 6),
                               "input_price": pin, "output_price": pout})
            if not models and total_usd > 0:
                tok = sum((r["prompt_tokens"] or 0) + (r["completion_tokens"] or 0)
                          for r in _rows)
                models.append({
                    "model": "全部模型", "prompt_tokens": tok,
                    "completion_tokens": 0, "cost_usd": total_usd,
                    "input_price": 0, "output_price": 0,
                })

            return {"summary": self.gateway.quota.summary(days),
                    "cache": self.gateway.cache.stats(),
                    "rate_limiter": self.gateway.rate_limiter.stats(),
                    "alerts": self.gateway.quota.recent_alerts(),
                    "pricing": {"total_usd": total_usd,
                                "today_usd": today_usd,
                                "models": models}}

        @a.get("/api/models")
        async def models():
            return {"models": self.gateway.syncer.all(),
                    "last_sync": self.gateway.syncer.last_sync}

        @a.put("/api/models/{model_id}")
        async def toggle_model(model_id: str, body: Dict[str, Any]):
            """切换模型开关:关闭后不再暴露给网关。"""
            enabled = bool(body.get("enabled", True))
            self.gateway.syncer.set_enabled(model_id, enabled)
            return {"model_id": model_id, "enabled": enabled,
                    "models_count": len(self.gateway.syncer.all_enabled())}

        @a.post("/api/sync")
        async def sync():
            keys = self.gateway.key_manager.list_all()
            result = await self.gateway.syncer.sync(keys)
            return result

        @a.get("/api/routes")
        async def get_routes():
            return {"routes": self.gateway.db.get_routes()}

        @a.put("/api/routes/{model}")
        async def put_route(model: str, body: Dict[str, Any]):
            key_ids = body.get("key_ids") or []
            self.gateway.db.set_route(
                model, [str(x) for x in key_ids],
                enabled=bool(body.get("enabled", True)),
                note=str(body.get("note", "")))
            return {"ok": True, "model": model}

        @a.delete("/api/routes/{model}")
        async def delete_route(model: str):
            self.gateway.db.delete_route(model)
            return {"ok": True, "model": model}

        @a.get("/api/settings")
        async def get_settings():
            """返回设置。

            敏感字段(网关 Key / JWT 密钥 / Webhook Secret / Telegram Token /
            管理台密码)一律脱敏返回, 避免明文出现在响应体、浏览器缓存与前端
            localStorage。需要明文时走 /api/settings/secret/{field}。
            """
            d = self.settings.to_dict()
            for f in UserSettings.SENSITIVE_FIELDS:
                if d.get(f):
                    d[f] = _mask(str(d[f]))
            if d.get("web_password"):
                d["web_password"] = "••••••"
            return d

        @a.get("/api/settings/secret/{field}")
        async def get_settings_secret(field: str):
            """返回单个敏感字段的明文(仪表盘复制网关 Key 用; 已鉴权)。"""
            if field not in UserSettings.SENSITIVE_FIELDS:
                raise HTTPException(400, f"不支持查看字段: {field}")
            return {"field": field, "value": str(getattr(self.settings, field, "") or "")}

        @a.put("/api/settings")
        async def put_settings(body: Dict[str, Any]):
            # 只更新提交的字段,其余保持现状
            current = self.settings.to_dict()
            body = {k: v for k, v in body.items() if k in current}
            # 前端持有的是脱敏值: 原样回传(未修改)时不能把掩码写进配置
            for f in UserSettings.SENSITIVE_FIELDS:
                if f in body and _is_mask(str(body[f])):
                    body.pop(f)
            if "web_password" in body and str(body["web_password"]) == _PWD_MASK:
                # 回传的是掩码 -> 不修改; 提交空串仍表示"清除密码"(保留原有行为)
                body.pop("web_password")
            current.update(body)
            # 数值字段类型校验(前端可能提交字符串)
            int_fields = ("port", "web_port", "max_concurrent",
                          "cache_ttl_seconds", "cache_max_entries",
                          "ip_rate_limit_per_minute", "global_rpm_limit",
                          "token_rate_limit_per_minute",
                          "sync_interval_minutes", "log_retention_days",
                          "max_log_entries")
            float_fields = ("quota_warn_threshold", "burst_multiplier")
            for f in int_fields:
                if f in current and not isinstance(current[f], bool):
                    try:
                        current[f] = int(current[f])
                    except (TypeError, ValueError):
                        raise HTTPException(400, f"字段 {f} 格式非法")
            for f in float_fields:
                if f in current and not isinstance(current[f], bool):
                    try:
                        current[f] = float(current[f])
                    except (TypeError, ValueError):
                        raise HTTPException(400, f"字段 {f} 格式非法")
            for f in ("port", "web_port"):
                if f in current and not (1 <= int(current[f]) <= 65535):
                    raise HTTPException(400, "端口必须为 1-65535")
            old_port = self.settings.port
            old_settings_snapshot = self.settings.to_dict()
            new = UserSettings.from_dict(current)
            # 密码: 前端回传的若非哈希则视为新明文, 统一哈希(旧明文迁移)
            from services.secret import is_hashed as _is_hash, hash_password as _hpass
            if current.get("web_password") and not _is_hash(str(current["web_password"])):
                new.web_password = _hpass(str(current["web_password"]))
            self.settings.__dict__.update(new.__dict__)
            # 落盘: 敏感字段 AES 加密, 内存保留明文供热路径
            self.db.set_setting("user_settings", new.to_persist_dict())
            # 检测哪些字段变更需要重启才能生效
            from config.settings import RESTART_FIELDS
            changed_fields = {}
            for field in RESTART_FIELDS:
                old_val = old_settings_snapshot.get(field)
                new_val = current.get(field)
                if old_val != new_val:
                    changed_fields[field] = {"old": old_val, "new": new_val}
            return {"ok": True,
                    "port_changed": old_port != new.port,
                    "needs_restart": bool(changed_fields),
                    "restart_fields": changed_fields,
                    "settings": self.settings.to_dict()}

        @a.post("/api/gateway/toggle")
        async def toggle_gateway(body: Dict[str, Any]):
            self.settings.gateway_enabled = bool(body.get("enabled", True))
            # 必须走 to_persist_dict: 内存中的敏感字段是明文, 直接 to_dict 会明文落盘
            self.db.set_setting("user_settings", self.settings.to_persist_dict())
            return {"gateway_enabled": self.settings.gateway_enabled}

        @a.post("/api/restart")
        async def restart_service():
            """请求重启服务(修改端口等需重启的字段后调用)。

            通过向自身进程发送 SIGTERM,由 run.sh 的 nohup 机制
            或进程管理器重新拉起。若不在 nohup 环境下则仅返回提示。
            """
            import os, signal, threading
            def _delayed_restart():
                import time
                time.sleep(0.5)
                os.kill(os.getpid(), signal.SIGTERM)
            threading.Thread(target=_delayed_restart, daemon=True).start()
            return {"ok": True, "message": "服务将在 0.5 秒后重启"}

        @a.get("/api/gateway-keys")
        async def get_gateway_keys():
            from services.secret import decrypt_field
            keys = self.db.get_setting("gateway_keys", []) or []
            # 解密后脱敏: 不返回完整密钥(仅前4后4), 但返回稳定 id 供前端回传定位
            masked = []
            for idx, k in enumerate(keys):
                kk = dict(k)
                raw = str(decrypt_field(kk.get("key", "")))
                kk["id"] = str(kk.get("id") or f"gk{idx}")
                kk["key_masked"] = (raw[:4] + "••••" + raw[-4:]) if len(raw) > 8 else "••••"
                kk.pop("key", None)
                kk.pop("key_masked_input", None)
                masked.append(kk)
            return {"keys": masked}

        @a.put("/api/gateway-keys")
        async def put_gateway_keys(body: Dict[str, Any]):
            """保存附加网关密钥。

            前端只持有脱敏后的 key_masked, 因此条目分为两类:
            - 带 key(新建或用户重新输入): 用新明文
            - 只带 id/key_masked(仅改开关/权限): 沿用数据库中的旧密文,
              绝不能当成空密钥写回, 否则一次"启用/停用"就会清空所有密钥。
            """
            keys = body.get("keys") or []
            from services.secret import encrypt_field, decrypt_field
            existing = self.db.get_setting("gateway_keys", []) or []
            old_by_id: Dict[str, str] = {}
            old_by_masked: Dict[str, str] = {}
            for idx, k in enumerate(existing):
                kid = str(k.get("id") or f"gk{idx}")
                enc = str(k.get("key", ""))
                old_by_id[kid] = enc
                raw = str(decrypt_field(enc))
                old_by_masked[(raw[:4] + "••••" + raw[-4:]) if len(raw) > 8 else "••••"] = enc
            clean = []
            for k in keys:
                new_plain = str(k.get("key", "")).strip()
                kid = str(k.get("id") or "").strip()
                enc = ""
                if new_plain:
                    enc = encrypt_field(new_plain)
                elif kid and kid in old_by_id:
                    enc = old_by_id[kid]
                elif k.get("key_masked"):
                    enc = old_by_masked.get(str(k["key_masked"]), "")
                if not enc:
                    continue      # 既无新明文也找不到旧密文: 跳过而不是写入空值
                clean.append({
                    "id": kid or f"gk{len(clean)}",
                    "key": enc,
                    "name": str(k.get("name", "")).strip(),
                    "permission": k.get("permission", "full"),
                    "models": [str(m) for m in (k.get("models") or [])],
                    "enabled": bool(k.get("enabled", True)),
                    "note": str(k.get("note", "")),
                })
            self.db.set_setting("gateway_keys", clean)
            try:
                self.gateway.invalidate_gateway_keys()  # 即时刷新鉴权缓存
            except Exception:
                pass
            return {"ok": True, "count": len(clean)}

        @a.get("/api/tokens")
        async def list_tokens():
            if not self.settings.tokens_enabled:
                return {"tokens": [], "disabled": True}
            return {"tokens": [t.to_dict() for t in self.gateway.tokens.list_all()],
                    "enabled": True}

        @a.post("/api/tokens")
        async def add_token(body: Dict[str, Any]):
            if not self.settings.tokens_enabled:
                raise HTTPException(403, "租户 Token 功能未开启")
            from models.api_token import TokenStatus
            try:
                t = self.gateway.tokens.add(
                    name=str(body.get("name") or "租户"),
                    plain_token=str(body.get("token") or "").strip(),
                    enabled=bool(body.get("enabled", True)),
                    daily_quota_usd=float(body.get("daily_quota_usd") or 0),
                    max_requests_per_minute=int(body.get("max_requests_per_minute") or 0),
                    models=[str(m) for m in (body.get("models") or [])],
                    provider=str(body.get("provider") or ""),
                    note=str(body.get("note") or ""),
                )
            except ValueError as ve:
                raise HTTPException(400, str(ve))
            return {"ok": True, "token": t.to_dict(),
                    "plain": getattr(t, "_plain", None)}

        @a.put("/api/tokens/{token_id}")
        async def update_token(token_id: str, body: Dict[str, Any]):
            if not self.settings.tokens_enabled:
                raise HTTPException(403, "租户 Token 功能未开启")
            t = self.gateway.tokens.get(token_id)
            if not t:
                raise HTTPException(404, "Token 不存在")
            try:
                t = self.gateway.tokens.update(
                    t,
                    plain_token=(str(body["token"]).strip() if body.get("token") else None),
                    enabled=body.get("enabled"),
                    daily_quota_usd=(float(body["daily_quota_usd"])
                                     if "daily_quota_usd" in body else None),
                    max_requests_per_minute=(int(body["max_requests_per_minute"])
                                             if "max_requests_per_minute" in body else None),
                    models=[str(m) for m in body["models"]] if "models" in body else None,
                    provider=body.get("provider"),
                    note=body.get("note"),
                    reset_usage=bool(body.get("reset_usage")),
                )
            except ValueError as ve:
                raise HTTPException(400, str(ve))
            return {"ok": True, "token": t.to_dict(),
                    "plain": getattr(t, "_plain", None)}

        @a.delete("/api/tokens/{token_id}")
        async def delete_token(token_id: str):
            if not self.settings.tokens_enabled:
                raise HTTPException(403, "租户 Token 功能未开启")
            ok = self.gateway.tokens.delete(token_id)
            if not ok:
                raise HTTPException(404, "Token 不存在")
            return {"ok": True}

        @a.get("/api/trend")
        async def usage_trend(period: str = Query("7d"),
                              days: int = Query(0, ge=0, le=90)):
            """用量趋势, 支持三档 period: 24h(按小时) / 7d / 30d(按日)。

            兼容旧参数 days(>0 时按日返回 days 天)。缺失桶补 0。
            """
            import datetime as _dt

            # 24 小时: 按小时聚合(基于 request_logs)
            if period == "24h" and days == 0:
                rows = self.db.hourly_trend(24)
                by_bucket = {int(r["bucket"]): r for r in rows}
                now_bucket = int(time.time() // 3600)
                start_bucket = now_bucket - 23
                series = []
                for b in range(start_bucket, now_bucket + 1):
                    r = by_bucket.get(b)
                    pt = int(r["prompt_tokens"]) if r else 0
                    ct = int(r["completion_tokens"]) if r else 0
                    lt = _dt.datetime.fromtimestamp(b * 3600)
                    series.append({
                        "date": lt.strftime("%Y-%m-%d %H:00"),
                        "label": lt.strftime("%H:00"),
                        "requests": int(r["requests"]) if r else 0,
                        "errors": int(r["errors"]) if r else 0,
                        "tokens": pt + ct,
                        "cost_usd": 0.0,   # 小时级不做费用估算(费用按日更准)
                    })
                return {"period": "24h", "series": series}

            # 按日: 7d / 30d(或兼容旧 days 参数)
            n_days = days if days > 0 else (30 if period == "30d" else 7)
            end = _dt.date.today()
            start = end - _dt.timedelta(days=n_days - 1)
            rows = self.db.stats_range(start.isoformat(), end.isoformat())
            daily: Dict[str, Dict[str, float]] = {}
            for r in rows:
                agg = daily.setdefault(r["date"], {
                    "requests": 0, "errors": 0,
                    "prompt_tokens": 0, "completion_tokens": 0,
                    "cost_usd": 0.0,
                })
                agg["requests"] += r["requests"]
                agg["errors"] += r["errors"]
                agg["prompt_tokens"] += r["prompt_tokens"]
                agg["completion_tokens"] += r["completion_tokens"]
                agg["cost_usd"] += r["cost_usd"]
            series = []
            cur = start
            while cur <= end:
                d = cur.isoformat()
                agg = daily.get(d, {"requests": 0, "errors": 0,
                                    "prompt_tokens": 0, "completion_tokens": 0,
                                    "cost_usd": 0.0})
                series.append({
                    "date": d,
                    "label": cur.strftime("%m-%d"),
                    "requests": int(agg["requests"]),
                    "errors": int(agg["errors"]),
                    "tokens": int(agg["prompt_tokens"] + agg["completion_tokens"]),
                    "cost_usd": round(agg["cost_usd"], 6),
                })
                cur += _dt.timedelta(days=1)
            return {"period": period, "days": n_days, "series": series}

        @a.post("/api/cache/clear")
        async def clear_cache():
            """清空网关响应缓存, 返回清除的条目数。"""
            cleared = self.gateway.cache.invalidate()
            return {"ok": True, "cleared": cleared,
                    "cache": self.gateway.cache.stats()}

        @a.get("/api/health")
        async def health_check():
            """网关健康 + 各 Key 上游连通性实时探测。"""
            from services.health import HealthProbe
            keys = self.gateway.key_manager.list_all()
            probe = HealthProbe()
            try:
                results = await probe.probe_all(keys)
            finally:
                await probe.aclose()
            return {"status": "ok",
                    "time": int(__import__("time").time() * 1000),
                    "summary": HealthProbe.summary(results),
                    "results": results}

        @a.get("/api/health/patrol")
        async def health_patrol_status():
            patrol = getattr(self.gateway, "patrol", None)
            if patrol is None:
                return {"running": False, "last_run": None,
                        "summary": {}, "interval": self.settings.health_patrol_interval}
            return {"running": True, "last_run": patrol.last_run,
                    "interval": self.settings.health_patrol_interval,
                    "summary": patrol.last_summary,
                    "results": patrol.last_results}

        @a.post("/api/health/patrol")
        async def health_patrol_trigger():
            from services.patrol import HealthPatrol
            patrol = getattr(self.gateway, "patrol", None)
            if patrol is None:
                patrol = HealthPatrol(self.gateway, self.settings.health_patrol_interval)
                self.gateway.patrol = patrol
            res = await patrol.patrol_once()
            return {"ok": True, **res}

        # ---------------- 审计 ----------------
        @a.get("/api/audit")
        async def list_audit(limit: int = Query(100, le=500)):
            return {"logs": self.db.query_audit(limit)}

        @a.delete("/api/audit")
        async def clear_audit():
            n = self.db.clear_audit()
            return {"ok": True, "deleted": n}

        # ---------------- 告警 ----------------
        @a.get("/api/alerts")
        async def list_alerts(limit: int = Query(50, le=200)):
            """告警列表(含 id/acknowledged)。"""
            rows = self.db.query_alerts(limit=limit)
            alerts = [{"id": r["id"], "ts": r["ts"], "type": r["type"],
                       "key_id": r["key_id"], "provider": r["provider"],
                       "message": r["message"],
                       "acknowledged": bool(r["acknowledged"])}
                      for r in rows]
            return {"alerts": alerts}

        @a.post("/api/alerts/{alert_id}/ack")
        async def ack_alert(alert_id: int):
            self.db.acknowledge_alert(alert_id)
            return {"ok": True}

        @a.delete("/api/alerts")
        async def clear_alerts():
            n = self.db.clear_alerts()
            try:
                self.gateway.quota.alerts = []
            except Exception:
                pass
            return {"ok": True, "deleted": n}

        # ---------------- 费用导出(按 Key/模型) ----------------
        @a.get("/api/stats/cost-export")
        async def cost_export(period: str = Query("30d")):
            """导出近 N 天按 Key 分组的费用明细(CSV)。"""
            import datetime as _dt
            import io as _io
            import csv as _csv
            n_days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}.get(period, 30)
            end = _dt.date.today()
            start = end - _dt.timedelta(days=n_days - 1)
            rows = self.db.stats_range(start.isoformat(), end.isoformat())
            # 关联 Key 名称
            key_names = {k.id: k.name for k in self.gateway.key_manager.list_all()}
            buf = _io.StringIO()
            w = _csv.writer(buf)
            w.writerow(["date", "provider", "key_id", "key_name", "requests",
                        "errors", "prompt_tokens", "completion_tokens", "cost_usd"])
            total_cost = 0.0
            for r in rows:
                c = float(r["cost_usd"] or 0)
                total_cost += c
                w.writerow([r["date"], r["provider"], r["key_id"],
                            key_names.get(r["key_id"], ""), r["requests"],
                            r["errors"], r["prompt_tokens"],
                            r["completion_tokens"], round(c, 6)])
            csv_text = buf.getvalue()
            return Response(csv_text, media_type="text/csv",
                            headers={"Content-Disposition":
                                     f'attachment; filename="cost-{period}.csv"'})

        # ---------------- 配置导出 / 导入 ----------------
        @a.get("/api/settings/export")
        async def settings_export():
            """导出完整配置(设置 + Key + 价格覆盖 + 网关密钥 + 租户 Token)。

            导出文件必须可在**另一台机器**还原, 因此其中密钥为明文——AES 密文
            依赖本机 data/.master_key, 换机后无法解密。导出文件本身即敏感物,
            请妥善保管(响应头已标记 no-store)。
            """
            from services.secret import decrypt_field
            db = self.db
            keys = []
            for k in self.gateway.key_manager.list_all():
                d = k.to_dict()
                d.pop("key", None)                 # 去掉密文
                d["key"] = self.gateway.key_manager.decrypt(k)   # 明文
                keys.append(d)
            tokens = []
            for t in self.gateway.tokens.list_all():
                d = t.to_dict()
                d["token"] = _safe_decrypt(d.get("token", ""))
                tokens.append(d)
            gw_keys = []
            for idx, gk in enumerate(db.get_setting("gateway_keys", []) or []):
                g = dict(gk)
                g["id"] = str(g.get("id") or f"gk{idx}")
                g["key"] = decrypt_field(str(g.get("key", "")))
                gw_keys.append(g)
            data = {
                "format": "intergate-config/2",
                "app": C.APP_NAME, "version": C.APP_VERSION,
                "exported_at": int(__import__("time").time() * 1000),
                "settings": self.settings.to_dict(),   # 明文, 与导入侧对称
                "keys": keys,
                "gateway_keys": gw_keys,
                "pricing_overrides": __import__("config.pricing", fromlist=["get_overrides"]).get_overrides(),
                "tokens": tokens,
                "model_states": db.get_model_states(),
            }
            import json as _json
            return Response(_json.dumps(data, ensure_ascii=False),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     'attachment; filename="intergate-config.json"',
                                     "Cache-Control": "no-store"})

        @a.post("/api/settings/import")
        async def settings_import(body: Dict[str, Any]):
            """导入配置。

            兼容两种来源:
            - 本版本导出(format=intergate-config/2): 密钥均为明文
            - 旧版导出: keys/tokens 里是密文(依赖源机器的主密钥)
            旧版密文换机后无法解密, 这些条目会被跳过并在 skipped 中报告,
            绝不把密文当明文写入。
            """
            db = self.db
            legacy = body.get("format") != EXPORT_FORMAT_V2
            # 旧版导出里的 settings 也是 to_persist_dict 结果(敏感字段为密文),
            # from_persist_dict 会尝试解密; 换机解不开则得到空串, 属预期降级。
            n_keys, n_tokens, n_settings, skipped = 0, 0, 0, 0
            if body.get("settings"):
                s = UserSettings.from_persist_dict(body["settings"])
                try:
                    self.settings.__dict__.update(s.__dict__)
                except Exception:
                    pass
                db.set_setting("user_settings", s.to_persist_dict())
                n_settings += 1
            for k in (body.get("keys") or []):
                try:
                    plain = _plain_from_export(
                        k.get("key") or k.get("encrypted_key"),
                        legacy_cipher=legacy)
                    if not plain:
                        skipped += 1  # 解不出明文就不导入, 避免产生空 Key
                        continue
                    self.gateway.key_manager.add_key(
                        provider=str(k.get("provider") or "custom"),
                        plain_key=plain,
                        name=str(k.get("name") or ""),
                        base_url=k.get("base_url") or None,
                        grp=str(k.get("group") or k.get("grp") or ""),
                        priority=int(k.get("priority") or 100),
                        weight=int(k.get("weight") or 1),
                        daily_quota=int(k.get("daily_quota") or 1_000_000),
                        max_requests_per_minute=int(k.get("max_requests_per_minute") or 60),
                        note=str(k.get("note") or ""),
                    )
                    n_keys += 1
                except Exception:
                    continue
            for t in (body.get("tokens") or []):
                try:
                    tok_plain = _plain_from_export(t.get("token"),
                                                   legacy_cipher=legacy)
                    if not tok_plain:
                        skipped += 1
                        continue
                    self.gateway.tokens.add(
                        name=str(t.get("name") or "导入"),
                        plain_token=tok_plain,
                        daily_quota_usd=float(t.get("daily_quota_usd") or 0),
                        max_requests_per_minute=int(t.get("max_requests_per_minute") or 0),
                        models=[str(m) for m in (t.get("models") or [])],
                        provider=str(t.get("provider") or ""),
                        note=str(t.get("note") or ""),
                    )
                    n_tokens += 1
                except Exception:
                    continue
            # 附加网关密钥: 用导入文件覆盖(明文优先, 兼容旧版密文)
            if body.get("gateway_keys"):
                from services.secret import encrypt_field
                clean = []
                for idx, gk in enumerate(body["gateway_keys"]):
                    plain = _plain_from_export(gk.get("key"), legacy_cipher=legacy)
                    if not plain:
                        skipped += 1
                        continue
                    clean.append({
                        "id": str(gk.get("id") or f"gk{idx}"),
                        "key": encrypt_field(plain),
                        "name": str(gk.get("name", "")),
                        "permission": gk.get("permission", "full"),
                        "models": [str(m) for m in (gk.get("models") or [])],
                        "enabled": bool(gk.get("enabled", True)),
                        "note": str(gk.get("note", "")),
                    })
                if clean:
                    db.set_setting("gateway_keys", clean)
                    try:
                        self.gateway.invalidate_gateway_keys()
                    except Exception:
                        pass
            # 模型开关状态
            for mid, enabled in (body.get("model_states") or {}).items():
                try:
                    db.set_model_state(str(mid), bool(enabled))
                    self.gateway.syncer.set_enabled(str(mid), bool(enabled))
                except Exception:
                    continue
            # 价格覆盖
            if body.get("pricing_overrides"):
                try:
                    from config.pricing import set_overrides
                    rules = {str(k): (float(v[0]), float(v[1]))
                             for k, v in body["pricing_overrides"].items()
                             if isinstance(v, (list, tuple)) and len(v) >= 2}
                    set_overrides(rules)
                    db.set_setting("pricing_rules", rules)
                except Exception:
                    pass
            return {"ok": True, "settings": n_settings,
                    "keys": n_keys, "tokens": n_tokens,
                    "skipped": skipped, "legacy": legacy}

        @a.get("/api/providers")
        async def providers():
            return {"providers": [{"id": p, "default_base_url": u}
                                  for p, u in _provider_defaults().items()]}

        @a.post("/api/backup")
        async def make_backup():
            """创建数据库备份(含主密钥), 返回备份信息。"""
            import shutil, subprocess
            try:
                result = subprocess.run(
                    ["./run.sh", "backup"], capture_output=True, text=True, timeout=60)
                out = (result.stdout or "") + (result.stderr or "")
                files = []
                import glob, os
                for f in sorted(glob.glob("backups/intergate-*.tgz"))[-10:]:
                    files.append({"name": os.path.basename(f),
                                  "size": os.path.getsize(f)})
                return {"ok": result.returncode == 0,
                        "message": out.strip(), "files": files}
            except Exception as e:
                return {"ok": False, "error": str(e)}

        @a.get("/api/backup/download")
        async def download_backup(name: str = ""):
            import os
            if not name or ".." in name or "/" in name:
                return JSONResponse({"error": "非法文件名"}, status_code=400)
            path = os.path.join("backups", name)
            if not os.path.exists(path):
                return JSONResponse({"error": "备份不存在"}, status_code=404)
            from fastapi.responses import FileResponse
            return FileResponse(path, media_type="application/gzip",
                                filename=name)

        @a.get("/api/export/logs")
        async def export_logs():
            """导出全部请求日志为 CSV。"""
            import csv, io
            rows = self.db.query_logs(limit=100000)
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["ts", "path", "method", "status", "provider",
                        "key_id", "model", "latency_ms", "prompt_tokens",
                        "completion_tokens", "cached", "error"])
            for r in rows:
                w.writerow([r.get(k, "") for k in
                            ("ts", "path", "method", "status", "provider",
                             "key_id", "model", "latency_ms", "prompt_tokens",
                             "completion_tokens", "cached", "error")])
            from fastapi.responses import Response
            return Response(content=buf.getvalue(),
                            media_type="text/csv; charset=utf-8",
                            headers={"Content-Disposition":
                                     'attachment; filename="logs.csv"'})

        @a.get("/api/export/stats")
        async def export_stats():
            """导出近 30 日用量统计为 CSV。"""
            import csv, io, datetime as _dt
            today = _dt.date.today().isoformat()
            start = (_dt.date.today() - _dt.timedelta(days=30)).isoformat()
            rows = self.db.stats_range(start, today)
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["date", "provider", "key_id", "requests",
                        "errors", "prompt_tokens", "completion_tokens", "cost_usd"])
            for r in rows:
                w.writerow([r.get(k, "") for k in
                            ("date", "provider", "key_id", "requests",
                             "errors", "prompt_tokens", "completion_tokens", "cost_usd")])
            from fastapi.responses import Response
            return Response(content=buf.getvalue(),
                            media_type="text/csv; charset=utf-8",
                            headers={"Content-Disposition":
                                     'attachment; filename="stats.csv"'})

        @a.post("/api/webhook/test")
        async def test_webhook(body: Dict[str, Any]):
            from services.webhook import notify_webhook
            url = str(body.get("url", "")).strip()
            if not url:
                return {"ok": False, "error": "URL 为空"}
            ok = await notify_webhook(
                url, "InterGate 测试推送",
                "这是一条来自 InterGate 网关控制台的测试通知。",
                str(body.get("secret", "")))
            return {"ok": ok, "error": "" if ok else "推送失败(非 2xx 或网络错误)"}

        @a.post("/api/telegram/test")
        async def test_telegram(body: Dict[str, Any]):
            from services.notify import _send_telegram
            token = str(body.get("token") or "").strip()
            chat_id = str(body.get("chat_id") or "").strip()
            if not token or not chat_id:
                raise HTTPException(400, "缺少 token 或 chat_id")
            ok = await _send_telegram(token, chat_id, "InterGate 测试推送",
                                      "这是一条来自 InterGate 的测试消息 ✅")
            if not ok:
                raise HTTPException(502, "Telegram 推送失败, 请检查 Token 与 Chat ID")
            return {"ok": True}

        @a.get("/api/pricing")
        async def get_pricing():
            from config.pricing import MODEL_PRICES, DEFAULT_PRICE, get_overrides
            return {"rules": get_overrides(),
                    "builtin": MODEL_PRICES,
                    "default": DEFAULT_PRICE}

        @a.put("/api/pricing")
        async def put_pricing(body: Dict[str, Any]):
            from config.pricing import set_overrides
            rules = body.get("rules") or {}
            clean = {str(k): (float(v[0]), float(v[1]))
                     for k, v in rules.items()
                     if str(k).strip() and isinstance(v, (list, tuple)) and len(v) >= 2}
            set_overrides(clean)
            self.db.set_setting("pricing_rules", clean)
            return {"ok": True, "rules": clean}

    # ---------------- 鉴权 ----------------
    def _is_public(self, path: str) -> bool:
        if path == "/":
            return True
        if path.startswith("/api/login"):
            return True
        # /api/status 始终公开:登录页需要它判断是否要登录,且不含敏感数据
        if path.startswith("/api/status"):
            return True
        return False

    def _authorized(self, request: Request) -> bool:
        if not self.settings.web_password:
            # 未设置密码: 仅本机可访问, 避免局域网内任何人拿到明文 Key
            host = request.client.host if request.client else ""
            return host in ("127.0.0.1", "::1", "localhost")
        token = request.headers.get("authorization", "")
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        return self._verify_token(token)


    # ---------------- Token 与登录限速 ----------------
    def _make_token(self, role: str) -> str:
        """生成带过期时间的签名 token(小时粒度, 24 小时有效)。"""
        secret = self.settings.web_password or "intergate-local"
        hour = int(time.time()) // 3600
        payload = f"{role}:{hour}"
        sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"),
                       hashlib.sha256).hexdigest()[:24]
        return base64.urlsafe_b64encode(f"{payload}.{sig}".encode("utf-8")).decode("ascii")

    def _verify_token(self, token: str) -> bool:
        """校验 token 签名与 24 小时有效期。"""
        if not token:
            return False
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
            payload, sig = raw.rsplit(".", 1)
            role, hour_str = payload.rsplit(":", 1)
            if role not in ("admin", "local"):
                return False
            secret = self.settings.web_password or "intergate-local"
            expect = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"),
                              hashlib.sha256).hexdigest()[:24]
            if not hmac.compare_digest(sig, expect):
                return False
            age = int(time.time()) // 3600 - int(hour_str)
            return 0 <= age <= 24
        except Exception:
            return False

    def _check_login_attempts(self, ip: str) -> None:
        """检查该 IP 是否已被限速(不计数)。"""
        now = time.time()
        with _login_lock():
            lst = [t for t in _login_attempts.get(ip, [])
                   if now - t < _LOGIN_WINDOW_SECONDS]
            if len(lst) >= _LOGIN_MAX_FAILURES:
                raise HTTPException(429, "尝试次数过多, 请稍后再试")

    def _record_login_attempt(self, ip: str) -> None:
        """记录一次登录失败。"""
        now = time.time()
        with _login_lock():
            lst = [t for t in _login_attempts.get(ip, [])
                   if now - t < _LOGIN_WINDOW_SECONDS]
            lst.append(now)
            _login_attempts[ip] = lst

    def _clear_login_attempts(self, ip: str) -> None:
        with _login_lock():
            _login_attempts.pop(ip, None)


import threading as _threading
_login_lock_obj = _threading.Lock()


def _login_lock():
    """返回全局单例锁(修复原实现每次创建新锁的问题)。"""
    return _login_lock_obj


def _pricing_reload(db) -> None:
    """从数据库加载用户自定义价格覆盖。"""
    try:
        from config.pricing import set_overrides
        rules = db.get_setting("pricing_rules", {}) or {}
        set_overrides(rules)
    except Exception as e:
        log.warning("加载价格覆盖失败: %s", e)


def _uptime() -> float:
    import time
    return round(time.time() - _START_TS, 1)


_START_TS = time.time()


def create_web_app(gateway: GatewayApp, db: Optional[Database] = None) -> FastAPI:
    return WebApp(gateway, db).app
