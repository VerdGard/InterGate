"""InterGate 入口:同时启动代理网关(51234) 与 Web 控制台(51235)。

多 Worker 模式(workers > 1):
  - 网关端口由 N 个 worker 进程并行服务, 提升并发吞吐
  - Web 控制台始终在主进程运行(管理状态)
  - 模型同步在主进程执行, 结果写入 SQLite 供各 worker 读取
  - 缓存/限流计数器/延迟统计为每进程独立(见各模块设计说明)
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

import uvicorn

from config.constants import APP_VERSION
from config.settings import UserSettings
from db.database import get_db
from gateway import GatewayApp
from webapp import WebApp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("intergate")


def load_settings() -> UserSettings:
    db = get_db()
    saved = db.get_setting("user_settings")
    env_pwd = os.environ.get("WEB_PASSWORD", "")
    if env_pwd and not (saved or {}).get("web_password"):
        # 首次启动且未设置管理台密码: 用环境变量作为初始密码
        from services.secret import hash_password
        base = dict(saved or {})
        base["web_password"] = hash_password(env_pwd)
        saved = base
    if saved:
        s = UserSettings.from_persist_dict(saved)   # 解密敏感字段, 内存保留明文
        db.set_setting("user_settings", s.to_persist_dict())
        return s
    s = UserSettings()
    db.set_setting("user_settings", s.to_persist_dict())
    return s


async def auto_sync_loop(gateway: GatewayApp) -> None:
    """自动同步模型列表:启动后立即同步一次,之后按 sync_interval_minutes 周期执行。

    共享 settings 对象,Web 控制台修改 sync_enabled/sync_interval_minutes 后实时生效。
    """
    while True:
        s = gateway.settings
        try:
            if s.sync_enabled:
                keys = gateway.key_manager.list_all()
                if keys:
                    result = await gateway.syncer.sync(keys)
                    log.info("自动同步模型: %d 个 (错误: %s)",
                             result.get("count", 0), result.get("error") or "无")
                else:
                    log.info("自动同步模型: 无可用 Key,跳过")
        except Exception as e:
            log.warning("自动同步模型失败: %s", e)
        # 开启时按配置间隔; 关闭时短轮询以便快速恢复
        interval = max(1, s.sync_interval_minutes) * 60 if s.sync_enabled else 30
        await asyncio.sleep(interval)


async def prune_loop(gateway: GatewayApp) -> None:
    """定时清理请求日志:按 log_retention_days / max_log_entries 裁剪, 防止表无限增长。

    共享 settings 对象, Web 控制台修改后下一轮生效。首次延迟 60 秒执行,
    避免启动瞬间与同步任务争抢 DB 锁; 之后每小时清理一次。
    """
    await asyncio.sleep(60)
    while True:
        s = gateway.settings
        try:
            n = gateway.db.prune_logs(
                retention_days=max(1, s.log_retention_days),
                max_entries=max(100, s.max_log_entries),
            )
            if n:
                log.info("清理过期请求日志: %d 条", n)
        except Exception as e:
            log.warning("清理请求日志失败: %s", e)
        try:
            from services.shared_state import cleanup_expired
            cleanup_expired()
        except Exception:
            pass
        await asyncio.sleep(3600)


def _run_gateway_worker(settings_dict: dict, port: int, host: str) -> None:
    """子进程入口:启动单个网关 worker。

    接收序列化的 settings dict, 重建实例。
    """
    settings = UserSettings.from_dict(settings_dict)
    db = get_db()
    gateway = GatewayApp(settings, db)

    # webhook / telegram 回调
    gateway.quota.webhook_provider = lambda: (
        settings.webhook_url, settings.webhook_secret, settings.webhook_enabled)
    gateway.quota.telegram_provider = lambda: (
        settings.telegram_bot_token, settings.telegram_chat_id,
        settings.telegram_enabled)

    config = uvicorn.Config(
        gateway.app, host=host, port=port,
        log_level="warning", access_log=False,
    )
    server = uvicorn.Server(config)
    try:
        asyncio.run(server.serve())
    finally:
        # worker 退出前冲刷该进程积压的批量写(日志/统计/Key 状态)
        try:
            db.flush_now()
        except Exception:
            pass


async def _run_single_process(settings: UserSettings) -> None:
    """单进程模式:网关 + Web + 同步任务都在一个 asyncio 事件循环。"""
    db = get_db()
    gateway = GatewayApp(settings, db)
    web = WebApp(gateway, db)

    gateway.quota.webhook_provider = lambda: (
        settings.webhook_url, settings.webhook_secret, settings.webhook_enabled)
    gateway.quota.telegram_provider = lambda: (
        settings.telegram_bot_token, settings.telegram_chat_id,
        settings.telegram_enabled)

    gw_cfg = uvicorn.Config(gateway.app, host=settings.host, port=settings.port,
                            log_level="warning", access_log=False)
    web_host = "127.0.0.1" if not settings.web_password else "0.0.0.0"
    web_cfg = uvicorn.Config(web.app, host=web_host, port=settings.web_port,
                             log_level="warning", access_log=False)

    log.info("=" * 56)
    log.info("  InterGate v%s · AI API 智能中转网关", APP_VERSION)
    log.info("  代理网关   -> http://%s:%s  (OpenAI 兼容 /v1)", settings.host, settings.port)
    log.info("  Web 控制台 -> http://%s:%s%s",
             web_host, settings.web_port,
             "  (未设置密码, 仅本机可访问)" if not settings.web_password else "")
    log.info("  负载均衡   -> %s", settings.load_balance_strategy)
    log.info("  自动同步   -> %s (间隔 %s 分钟)",
             "开" if settings.sync_enabled else "关", settings.sync_interval_minutes)
    log.info("=" * 56)

    servers = [uvicorn.Server(gw_cfg), uvicorn.Server(web_cfg)]
    sync_task = asyncio.create_task(auto_sync_loop(gateway))
    prune_task = asyncio.create_task(prune_loop(gateway))
    from services.patrol import HealthPatrol
    patrol = HealthPatrol(gateway, settings.health_patrol_interval)
    patrol_task = asyncio.create_task(patrol.run_loop())
    gateway.patrol = patrol
    try:
        await asyncio.gather(*(s.serve() for s in servers),
                             sync_task, prune_task, patrol_task,
                             return_exceptions=True)
    finally:
        # 优雅关闭: 关闭上游连接池 + 冲刷未落库的批量写
        sync_task.cancel()
        prune_task.cancel()
        patrol_task.cancel()
        try:
            await patrol.aclose()
        except Exception:
            pass
        try:
            await gateway.upstream.aclose()
        except Exception as e:
            log.warning("关闭上游连接池失败: %s", e)
        try:
            db.flush_now()
        except Exception as e:
            log.warning("冲刷数据库失败: %s", e)


async def _run_multi_worker(settings: UserSettings) -> None:
    """多进程模式:N 个网关 worker + 主进程 Web 控制台。

    主进程负责:
    - Web 控制台 (管理 Key/设置/日志)
    - 模型自动同步 (结果写 SQLite, 各 worker 启动时读取)
    - 告警 Webhook 回调

    各 worker 进程负责:
    - 网关请求转发 (各自独立的缓存/限流/负载均衡器实例)
    """
    import multiprocessing
    import signal

    db = get_db()
    gateway = GatewayApp(settings, db)
    web = WebApp(gateway, db)

    gateway.quota.webhook_provider = lambda: (
        settings.webhook_url, settings.webhook_secret, settings.webhook_enabled)
    gateway.quota.telegram_provider = lambda: (
        settings.telegram_bot_token, settings.telegram_chat_id,
        settings.telegram_enabled)

    log.info("=" * 56)
    log.info("  InterGate v%s · AI API 智能中转网关 (多 Worker)", APP_VERSION)
    log.info("  代理网关   -> http://%s:%s  (workers=%d)", settings.host, settings.port, settings.workers)
    log.info("  Web 控制台 -> http://%s:%s",
             "127.0.0.1" if not settings.web_password else "0.0.0.0", settings.web_port)
    log.info("  负载均衡   -> %s", settings.load_balance_strategy)
    log.info("  自动同步   -> %s (间隔 %s 分钟)",
             "开" if settings.sync_enabled else "关", settings.sync_interval_minutes)
    log.info("=" * 56)

    # 启动网关 worker 进程
    settings_dict = settings.to_dict()
    workers: list[multiprocessing.Process] = []
    for i in range(settings.workers):
        p = multiprocessing.Process(
            target=_run_gateway_worker,
            args=(settings_dict, settings.port, settings.host),
            name=f"intergate-gw-{i}",
            daemon=True,
        )
        p.start()
        workers.append(p)
        log.info("  网关 worker %d 已启动 (PID %d)", i, p.pid)

    # 主进程运行 Web 控制台 + 同步任务
    web_host = "127.0.0.1" if not settings.web_password else "0.0.0.0"
    web_cfg = uvicorn.Config(web.app, host=web_host, port=settings.web_port,
                             log_level="warning", access_log=False)
    web_server = uvicorn.Server(web_cfg)
    sync_task = asyncio.create_task(auto_sync_loop(gateway))
    prune_task = asyncio.create_task(prune_loop(gateway))
    from services.patrol import HealthPatrol
    patrol = HealthPatrol(gateway, settings.health_patrol_interval)
    patrol_task = asyncio.create_task(patrol.run_loop())
    gateway.patrol = patrol

    # 注册信号处理: 主进程收到终止信号时清理子进程
    def _shutdown_workers(*args):
        for p in workers:
            if p.is_alive():
                p.terminate()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown_workers)

    try:
        await asyncio.gather(web_server.serve(), sync_task, prune_task,
                             patrol_task, return_exceptions=True)
    finally:
        prune_task.cancel()
        patrol_task.cancel()
        try:
            await patrol.aclose()
        except Exception:
            pass
        for p in workers:
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)
        try:
            db.flush_now()
        except Exception as e:
            log.warning("冲刷数据库失败: %s", e)


def main() -> None:
    settings = load_settings()

    if settings.workers > 1:
        asyncio.run(_run_multi_worker(settings))
    else:
        asyncio.run(_run_single_process(settings))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterGate 已停止")
        sys.exit(0)
