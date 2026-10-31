#!/usr/bin/env bash
# InterGate 管理脚本(Termux / Linux 均可)
# 用法: ./run.sh [start|stop|restart|status|backup]   默认 start
cd "$(dirname "$0")"
PID_FILE="intergate.pid"
PORT=51234
WEB_PORT=51235

# ══════════════════════════════════════════════════════════════
# 输出美化 (仅在终端为 tty 时启用颜色, 重定向/日志时自动禁用)
# ══════════════════════════════════════════════════════════════
if [ -t 1 ]; then
  C_RESET=$'\033[0m';    C_BOLD=$'\033[1m';    C_DIM=$'\033[2m'
  C_RED=$'\033[31m';     C_GREEN=$'\033[32m';  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m';    C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
  C_WHITE=$'\033[37m';   C_BG_GREEN=$'\033[42m'; C_BG_RED=$'\033[41m'
  C_BG_YELLOW=$'\033[43m'; C_BG_CYAN=$'\033[46m'
else
  C_RESET=; C_BOLD=; C_DIM=; C_RED=; C_GREEN=; C_YELLOW=
  C_BLUE=; C_MAGENTA=; C_CYAN=; C_WHITE=; C_BG_GREEN=; C_BG_RED=
  C_BG_YELLOW=; C_BG_CYAN=
fi

say()  { printf '%b\n' "$*"; }
hr()   { say "${C_DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"; }
info() { say "  ${C_CYAN}▸${C_RESET} $*"; }
ok()   { say "  ${C_GREEN}✔${C_RESET} $*"; }
warn() { say "  ${C_YELLOW}⚠${C_RESET} $*"; }
err()  { say "  ${C_RED}✘${C_RESET} $*"; }

# ── ASCII 艺术字标题 (pyfiglet slant 风格) ────────────────────
banner() {
  [ -t 1 ] || return 0
  printf '%s\n' "${C_CYAN}" \
'    ____      __            ______      __' \
'   /  _/___  / /____  _____/ ____/___ _/ /____' \
'   / // __ \/ __/ _ \/ ___/ / __/ __ `/ __/ _ \' \
' _/ // / / / /_/  __/ /  / /_/ / /_/ / /_/  __/' \
'/___/_/ /_/\__/\___/_/   \____/\__,_/\__/\___/' \
"${C_RESET}"
}

# ── 端口占用检测: SO_REUSEADDR 避免 TIME_WAIT 误判 ──────────
ports_used() {
  python3 - "$PORT" "$WEB_PORT" <<'PY' 2>/dev/null
import socket, sys
def used(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", p)); return False
    except OSError:
        return True
    finally:
        s.close()
sys.exit(0 if (used(int(sys.argv[1])) or used(int(sys.argv[2]))) else 1)
PY
}

is_running() {
  # 1) PID 文件
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    return 0
  fi
  # 2) 端口被占用即视为已在运行
  if ports_used; then return 0; else return 1; fi
}

start() {
  if is_running; then
    say
    hr
    say "  ${C_BG_YELLOW}${C_BOLD}  ⚠  InterGate 已在运行  ${C_RESET}"
    hr
    warn "PID $(cat "$PID_FILE" 2>/dev/null || echo '?')"
    warn "如端口被其他程序占用, 请先 ./run.sh stop; 强制重启: ./run.sh restart"
    hr
    say
    return 0
  fi

  say
  banner
  say
  hr
  say "  ${C_BG_CYAN}${C_BOLD}  ◆  InterGate 启动中 ...  ${C_RESET}"
  hr
  nohup python3 main.py > intergate.log 2>&1 &
  echo $! > "$PID_FILE"
  sleep 4

  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    say
    hr
    say "  ${C_BG_GREEN}${C_BOLD}  ✔  InterGate 已启动  ${C_RESET}"
    hr
    ok "进程 PID  : ${C_BOLD}${C_YELLOW}${pid}${C_RESET}"
    ok "网关地址  : ${C_BOLD}${C_GREEN}http://127.0.0.1:${PORT}/v1${C_RESET}"
    ok "控制台    : ${C_BOLD}${C_GREEN}http://127.0.0.1:${WEB_PORT}${C_RESET}"
    hr
    say "  ${C_DIM}日志输出  : intergate.log${C_RESET}"
    say "  ${C_DIM}停止服务  : ./run.sh stop${C_RESET}"
    hr
    say
  else
    err "启动失败, 请查看 intergate.log"
    return 1
  fi
}

# 优雅停止单个 PID: 先 SIGTERM 让进程冲刷 DB/关闭连接, 超时再 SIGKILL
term_wait_kill() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null
  local i=0
  while [ $i -lt 10 ]; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 1; i=$((i+1))
  done
  # 超时兜底
  kill -9 "$pid" 2>/dev/null
}

stop() {
  say
  hr
  say "  ${C_BG_RED}${C_BOLD}  ■  InterGate 停止中 ...  ${C_RESET}"
  hr
  # 1) PID 文件精确停止(优雅关闭优先)
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    term_wait_kill "$(cat "$PID_FILE")"
    rm -f "$PID_FILE"
    ok "已停止 (PID 文件)"
  else
    # 2) 兜底: 按进程名清理
    local pids
    pids=$(pgrep -f "python3 .*main[.]py" 2>/dev/null)
    if [ -n "$pids" ]; then
      for pid in $pids; do term_wait_kill "$pid"; done
      rm -f "$PID_FILE"
      ok "已停止 (按进程名清理)"
    else
      rm -f "$PID_FILE"
      warn "未在运行"
    fi
  fi
  # 等待端口释放(最多 15 秒), 避免 restart 时 bind 失败
  local i=0
  while [ $i -lt 15 ]; do
    if ! ports_used; then break; fi
    sleep 1; i=$((i+1))
  done
  hr
  say
}

backup() {
  mkdir -p backups
  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  local out="backups/intergate-${ts}.tgz"
  # 用 SQLite 在线备份 API, 无需停止服务(自动处理锁)
  python3 - "$out" <<'PY'
import sqlite3, sys, os
src = "data/intergate.db"
dst = os.path.join("backups", os.path.basename(sys.argv[1]).replace(".tgz", ".db"))
conn = sqlite3.connect(src)
bak = sqlite3.connect(dst)
with bak:
    conn.backup(bak)
bak.close(); conn.close()
print("db backed up:", dst)
PY
  if [ -f data/.master_key ]; then
    tar -czf "$out" -C . backups/"$(basename "$out" .tgz).db" data/.master_key 2>/dev/null
  else
    tar -czf "$out" -C . backups/"$(basename "$out" .tgz).db" 2>/dev/null
  fi
  rm -f "backups/$(basename "$out" .tgz).db"
  say
  hr
  say "  ${C_BG_GREEN}${C_BOLD}  ✔  备份完成  ${C_RESET}"
  hr
  ok "备份文件  : ${C_BOLD}${C_GREEN}${out}${C_RESET}"
  ls -lh "$out" | awk '{print "  " $5 "  " $9}'
  hr
  say
}

case "${1:-start}" in
  start)  start ;;
  stop)   stop ;;
  restart) stop; start ;;
  status)
    say
    if is_running; then
      say "  ${C_GREEN}●${C_RESET} ${C_BOLD}InterGate 运行中${C_RESET}  ${C_DIM}(PID $(cat "$PID_FILE" 2>/dev/null || echo '?'))${C_RESET}"
      ok "网关   : http://127.0.0.1:${PORT}/v1"
      ok "控制台 : http://127.0.0.1:${WEB_PORT}"
    else
      say "  ${C_RED}○${C_RESET} ${C_BOLD}InterGate 未运行${C_RESET}"
    fi
    say ;;
  backup) backup ;;
  *) say "  ${C_YELLOW}用法: ./run.sh [start|stop|restart|status|backup]${C_RESET}"; exit 1 ;;
esac
