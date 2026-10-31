"""Webhook 推送模块:向外部 URL 异步 POST JSON 通知,可选 HMAC-SHA256 签名。"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

import httpx

log = logging.getLogger('intergate.webhook')

SIGNATURE_HEADER = 'X-InterGate-Signature'
TIMEOUT_SECONDS = 10.0


async def notify_webhook(url: str, title: str, content: str, secret: str = '') -> bool:
  """推送一条通知到 webhook URL。

  参数:
    url: 接收方地址(HTTP/HTTPS)。
    title: 通知标题。
    content: 通知正文。
    secret: 非空时按 HMAC-SHA256 对请求体签名,放入 X-InterGate-Signature 头。

  返回:
    True 表示推送成功(HTTP 2xx),否则 False;所有异常均被捕获并仅记警告日志。
  """
  if not url or not url.strip():
    log.warning('webhook URL 为空, 跳过推送')
    return False
  payload = {
    'title': title,
    'content': content,
    'time': int(time.time()),
  }
  try:
    # 先序列化固定请求体,签名与发送内容保持一致(避免 httpx 二次序列化导致签名不匹配)
    body = json.dumps(payload, ensure_ascii=False)
  except Exception as exc:
    log.warning('webhook json 序列化失败: %s', exc)
    return False
  headers = {'Content-Type': 'application/json'}
  if secret:
    digest = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()
    headers[SIGNATURE_HEADER] = digest
  try:
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
      resp = await client.post(url, content=body, headers=headers)
  except Exception as exc:
    log.warning('webhook 推送失败 url=%s: %s', url, exc)
    return False
  if not resp.is_success:
    log.warning('webhook 推送非 2xx 响应 url=%s status=%s', url, resp.status_code)
    return False
  return True


def notify_webhook_sync(url: str, title: str, content: str, secret: str = '') -> None:
  """同步上下文 fire-and-forget 推送(内部起守护线程跑 asyncio)。"""
  if not url:
    return
  import threading

  def _run():
    try:
      import asyncio
      asyncio.run(notify_webhook(url, title, content, secret))
    except Exception as exc:
      log.warning('webhook 后台推送异常: %s', exc)

  threading.Thread(target=_run, daemon=True).start()
