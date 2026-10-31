"""告警通知分发: 支持通用 Webhook 与 Telegram Bot。

quota 触发告警时调用 send_alert, 按配置同时/分别推送到 webhook 与 Telegram。
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Optional

import httpx

log = logging.getLogger("intergate.notify")
TIMEOUT = 10.0
SIGNATURE_HEADER = "X-InterGate-Signature"


async def _send_webhook(url: str, title: str, content: str, secret: str = "") -> bool:
    if not url or not url.strip():
        return False
    payload = {"title": title, "content": content, "time": int(time.time())}
    try:
        body = json.dumps(payload, ensure_ascii=False)
    except Exception:
        return False
    headers = {"Content-Type": "application/json"}
    if secret:
        digest = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers[SIGNATURE_HEADER] = digest
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(url, content=body, headers=headers)
        return resp.is_success
    except Exception as e:
        log.warning("webhook 推送失败: %s", e)
        return False


async def _send_telegram(token: str, chat_id: str, title: str, content: str) -> bool:
    if not token or not chat_id:
        return False
    text = f"*{title}*\n\n{content}"[:4000]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id, "text": text,
                "parse_mode": "Markdown", "disable_web_page_preview": True,
            })
        return resp.is_success
    except Exception as e:
        log.warning("Telegram 推送失败: %s", e)
        return False


async def send_alert(webhook: Optional[tuple], telegram: Optional[tuple],
                     title: str, content: str) -> None:
    """webhook=(url, secret, enabled); telegram=(token, chat_id, enabled)。"""
    tasks = []
    if webhook and webhook[2] and webhook[0]:
        tasks.append(_send_webhook(webhook[0], title, content, webhook[1] or ""))
    if telegram and telegram[2] and telegram[0] and telegram[1]:
        tasks.append(_send_telegram(telegram[0], telegram[1], title, content))
    if tasks:
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            log.warning("通知分发异常: %s", e)


def send_alert_sync(webhook: Optional[tuple], telegram: Optional[tuple],
                    title: str, content: str) -> None:
    """同步上下文 fire-and-forget 分发。"""
    def _run():
        try:
            asyncio.run(send_alert(webhook, telegram, title, content))
        except Exception as e:
            log.warning("通知后台分发异常: %s", e)
    threading.Thread(target=_run, daemon=True).start()
