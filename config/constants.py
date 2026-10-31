"""全局常量(对齐 RelayGo / InterGate Android 版)"""

APP_NAME = "InterGate"
APP_VERSION = "1.1.3"
APP_SLOGAN = "AI 网关,随时就绪"

# 网关监听
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 51234
MAX_CONCURRENT_CONNECTIONS = 50
MAX_FAILURE_THRESHOLD = 3          # 连续失败阈值
COOLDOWN_SECONDS = 300             # 冷却秒数
UPSTREAM_TIMEOUT_SECONDS = 120
MAX_RETRY_KEYS = 3                 # 单请求最多切换 Key 数
MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024

# 接口路径
HEALTH_PATHS = ("/health", "/healthz", "/ping")
STATS_PATH = "/relay/stats"
VERSION_PATH = "/relay/version"
REPORT_PATH = "/relay/report"
CACHE_STATS_PATH = "/relay/cache"
METRICS_PATH = "/relay/metrics"
MODELS_PATH = "/v1/models"

# 客户端强制指定提供商 / key 的请求头
PROVIDER_HEADER = "x-relay-provider"
KEY_NAME_HEADER = "x-relay-key"
CACHE_HIT_HEADER = "x-relay-cache"
RETRY_AFTER_HEADER = "retry-after"

# 负载均衡策略
LOAD_BALANCE_STRATEGIES = (
    "round_robin", "weighted_round_robin", "priority",
    "least_connections", "response_time", "smart"
)

# 缓存
DEFAULT_CACHE_TTL_SECONDS = 300
DEFAULT_CACHE_MAX_ENTRIES = 500

# 限流(0 表示不限制)
DEFAULT_IP_RATE_LIMIT_PER_MINUTE = 0
DEFAULT_GLOBAL_RPM_LIMIT = 0
DEFAULT_TOKEN_RATE_LIMIT_PER_MINUTE = 0
DEFAULT_BURST_MULTIPLIER = 1.5

# 额度
DEFAULT_QUOTA_WARN_THRESHOLD = 0.9
QUOTA_EXHAUSTED_COOLDOWN_MS = 30 * 60 * 1000

# 自适应 TPM(AIMD)
TPM_AIMD_DOWN = 0.85
TPM_AIMD_UP = 0.02
TPM_WAIT_BUDGET_MS = 8000

# 日志
DEFAULT_LOG_RETENTION_DAYS = 7
DEFAULT_MAX_LOG_ENTRIES = 5000

# 提供商默认端点(opencode/azure/custom 需用户填写真实 Base URL)
PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "opencode": "",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com",
    "azure": "",
    "custom": "",
}

# Anthropic 必须的协议版本头(客户端未带时补默认值)
ANTHROPIC_VERSION = "2023-06-01"

# 接口路径 -> 提供商
PATH_TO_PROVIDER = {
    "/v1/chat/completions": "openai",
    "/v1/completions": "openai",
    "/v1/embeddings": "openai",
    "/v1/images/generations": "openai",
    "/v1/audio/transcriptions": "openai",
    "/v1/audio/speech": "openai",
    "/v1/models": "openai",
    "/v1/messages": "anthropic",
    "/v1beta": "google",
    "/openai/deployments": "azure",
}

# 模型名前缀 -> 提供商
MODEL_PREFIX_TO_PROVIDER = {
    "gpt-": "openai", "o1": "openai", "o3": "openai", "o4": "openai",
    "chatgpt": "openai", "text-embedding": "openai", "dall-e": "openai",
    "whisper": "openai", "tts-": "openai",
    "claude": "anthropic",
    "gemini": "google", "palm": "google", "chat-bison": "google",
    "text-bison": "google", "embedding-00": "google",
}

# 错误分类关键词
QUOTA_EXHAUSTED_KEYWORDS = (
    "free_quota_exhausted", "free quota", "insufficient_quota",
    "insufficient ledger balance", "insufficient_ledger_balance",
    "exceeded your current quota",
    "quota_exceeded", "quota exhausted", "billing_not_active",
    "billing not active", "billing_hard_limit", "credit_balance_too_low",
    "insufficient_credit", "insufficient credit", "out of credits",
    "not enough credit", "payment_required", "account_deactivated",
    "usage cap", "daily usage limit", "daily limit reached",
)



# 多 Worker 支持
DEFAULT_WORKERS = 1

# 上游连接池
DEFAULT_UPSTREAM_MAX_CONNECTIONS = 100
DEFAULT_UPSTREAM_MAX_KEEPALIVE = 20

# 告警持久化
MAX_PERSISTED_ALERTS = 200          # 数据库最多保存的告警条数
# 管理 Web 控制台默认端口
DEFAULT_WEB_PORT = 51235
