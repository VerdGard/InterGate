"""模型价格预估(单位:美元/百万 token)。

内置常见模型估算单价,按模型前缀匹配(最长前缀优先);
未匹配模型使用默认价。价格为公开参考价的近似值,仅用于仪表盘费用预估,
可自行调整或在设置页添加覆盖规则(数据库持久化)。
"""
from __future__ import annotations

from typing import Dict, Tuple

# 模型前缀 -> (输入价, 输出价) 美元/百万 token
# 匹配时按前缀长度降序,保证 gpt-4o-mini 优先于 gpt-4o 等精确命中
MODEL_PRICES: Dict[str, Tuple[float, float]] = {
    # ================= 国内模型 =================
    # DeepSeek 深度求索
    "deepseek-chat": (0.27, 1.10),
    "deepseek-reasoner": (0.55, 2.19),
    "deepseek-r1": (0.55, 2.19),
    "deepseek": (0.27, 1.10),
    # 智谱 GLM
    "glm-4.6": (0.60, 2.20),
    "glm-4.5": (0.60, 2.20),
    "glm-4-plus": (0.50, 2.00),
    "glm-4-air": (0.02, 0.02),
    "glm-4-flash": (0.01, 0.01),
    "glm-4-long": (0.01, 0.01),
    "glm": (0.30, 0.90),
    # 阿里通义千问
    "qwen-max": (2.80, 8.30),
    "qwen-plus": (0.10, 0.30),
    "qwen-turbo": (0.05, 0.10),
    "qwen-long": (0.01, 0.02),
    "qwen": (0.20, 0.60),
    # 月之暗面 Kimi
    "kimi-k2": (0.60, 2.50),
    "kimi": (0.60, 2.00),
    "moonshot": (0.60, 2.00),
    # 字节豆包
    "doubao-1.5": (0.20, 0.60),
    "doubao-seed": (0.20, 0.60),
    "doubao-pro": (0.15, 0.30),
    "doubao": (0.50, 2.00),
    # 讯飞星火
    "spark-max": (0.30, 0.60),
    "spark-pro": (0.15, 0.30),
    "spark-lite": (0.01, 0.01),
    "spark": (0.30, 0.60),
    # 百度文心一言
    "ernie-4": (4.00, 12.00),
    "ernie-3.5": (1.70, 1.70),
    "ernie-speed": (0.10, 0.10),
    "ernie": (1.70, 1.70),
    # 腾讯混元
    "hunyuan-turbo": (0.70, 2.80),
    "hunyuan-lite": (0.01, 0.01),
    "hunyuan": (0.70, 2.80),
    # 商汤日日新 SenseNova
    "sensenova": (1.00, 3.00),
    # MiniMax
    "minimax": (0.20, 0.60),
    # 阶跃星辰 Step
    "step": (0.40, 1.20),
    # 零一万物 Yi
    "yi": (0.40, 1.20),
    # 百川智能
    "baichuan": (0.50, 1.50),
    # 面壁智能 MiniCPM
    "minicpm": (0.10, 0.30),

    # ================= 国外模型 =================
    # OpenAI GPT 系列
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5-nano": (0.05, 0.40),
    "gpt-5": (1.25, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5": (0.50, 1.50),
    "gpt": (2.50, 10.00),
    # OpenAI o 系列推理模型
    "o1-mini": (3.00, 12.00),
    "o1": (15.00, 60.00),
    "o3-mini": (1.10, 4.40),
    "o3": (2.00, 8.00),
    "o4-mini": (1.10, 4.40),
    # Anthropic Claude
    "claude-3-opus": (15.00, 75.00),
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-haiku": (0.25, 1.25),
    "claude-opus": (15.00, 75.00),
    "claude-sonnet": (3.00, 15.00),
    "claude-haiku": (0.80, 4.00),
    "claude": (3.00, 15.00),
    # Google Gemini
    "gemini-3-pro": (2.00, 12.00),
    "gemini-3-flash": (0.50, 3.00),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini": (1.25, 5.00),
    # Meta Llama(托管 API 参考价)
    "llama-4-maverick": (0.23, 0.23),
    "llama-4-scout": (0.13, 0.13),
    "llama-3.3": (0.60, 0.60),
    "llama-3.1-405b": (3.50, 3.50),
    "llama-3.1-70b": (0.60, 0.60),
    "llama-3.1-8b": (0.05, 0.05),
    "llama": (0.60, 0.60),
    # xAI Grok
    "grok-3-mini": (0.30, 0.50),
    "grok-3": (3.00, 15.00),
    "grok-2": (2.00, 10.00),
    "grok": (3.00, 15.00),
    # Mistral
    "mistral-large": (2.00, 6.00),
    "mistral-medium": (2.50, 7.50),
    "mistral-small": (0.10, 0.30),
    "codestral": (0.30, 0.90),
    "ministral": (0.10, 0.10),
    "mistral": (0.60, 1.60),
    # Amazon Nova
    "nova-pro": (0.80, 3.20),
    "nova-lite": (0.06, 0.24),
    "nova-micro": (0.035, 0.14),
    "nova": (0.80, 3.20),
}
DEFAULT_PRICE: Tuple[float, float] = (1.00, 3.00)

# 按前缀长度降序预排序,保证最长前缀优先匹配
_PRICE_ITEMS = sorted(MODEL_PRICES.items(), key=lambda kv: len(kv[0]), reverse=True)

# 用户自定义覆盖(数据库可配置): prefix -> (输入价, 输出价)
_OVERRIDES: Dict[str, Tuple[float, float]] = {}
_OVERRIDE_ITEMS: list = []


def set_overrides(rules: Dict[str, Tuple[float, float]]) -> None:
    """设置用户自定义价格覆盖(来自数据库/设置页),优先级高于内置价格。"""
    global _OVERRIDES, _OVERRIDE_ITEMS
    _OVERRIDES = {
        str(k).strip().lower(): (float(v[0]), float(v[1]))
        for k, v in (rules or {}).items()
        if str(k).strip() and isinstance(v, (list, tuple)) and len(v) >= 2
    }
    _OVERRIDE_ITEMS = sorted(_OVERRIDES.items(),
                             key=lambda kv: len(kv[0]), reverse=True)


def get_overrides() -> Dict[str, Tuple[float, float]]:
    """返回当前用户自定义覆盖(深拷贝)。"""
    return dict(_OVERRIDES)


def price_for(model: str) -> Tuple[float, float]:
    """按模型前缀匹配单价(最长前缀优先),未匹配返回默认价。
    用户覆盖优先级高于内置价格。"""
    m = (model or "").lower()
    for prefix, p in _OVERRIDE_ITEMS:
        if m.startswith(prefix):
            return p
    for prefix, p in _PRICE_ITEMS:
        if m.startswith(prefix):
            return p
    return DEFAULT_PRICE


def estimate_cost(model: str, prompt_tokens: int,
                  completion_tokens: int) -> Tuple[float, float, float]:
    """估算费用(美元)。返回 (cost, input_price, output_price)。"""
    pin, pout = price_for(model)
    cost = (int(prompt_tokens) * pin + int(completion_tokens) * pout) / 1_000_000
    return round(cost, 6), pin, pout
