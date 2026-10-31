"""提供商识别与端点解析(对齐 Android 版 Environment)"""
from __future__ import annotations

from config import constants as C


def detect_provider_by_path(path: str) -> str:
    p = path.split("?")[0]
    if p.startswith("/v1/messages"):
        return "anthropic"
    if p.startswith("/v1beta") or ":generateContent" in p or ":streamGenerateContent" in p:
        return "google"
    if p.startswith("/openai/deployments"):
        return "azure"
    return "openai"


def detect_provider_by_model(model: str | None) -> str | None:
    if not model:
        return None
    m = model.lower()
    for prefix, provider in C.MODEL_PREFIX_TO_PROVIDER.items():
        if m.startswith(prefix):
            return provider
    return None


def detect_provider(path: str, model: str | None = None,
                    header_provider: str | None = None) -> str:
    """综合识别:请求头 > 模型名 > 请求路径。"""
    if header_provider and header_provider.strip():
        p = header_provider.strip().lower()
        if p in C.PROVIDER_BASE_URLS:
            return p
    by_path = detect_provider_by_path(path)
    if by_path != "openai":
        return by_path
    return detect_provider_by_model(model) or by_path


def candidate_providers(primary: str, path: str) -> list[str]:
    """候选提供商列表:主选 + OpenAI 兼容降级。"""
    out = [primary]
    openai_style = not path.startswith("/v1/messages") and \
        not path.startswith("/v1beta") and ":generateContent" not in path
    if openai_style:
        for p in ("custom", "openai", "azure"):
            if p != primary and p not in out:
                out.append(p)
    return out


def endpoint_kind(path: str) -> str:
    if "chat/completions" in path or "/messages" in path:
        return "chat"
    if "embeddings" in path or ":embedContent" in path:
        return "embedding"
    if "/images/" in path:
        return "image"
    if "/audio/transcriptions" in path:
        return "audio"
    if "/audio/speech" in path:
        return "tts"
    if "/completions" in path:
        return "completion"
    if ":generateContent" in path or ":streamGenerateContent" in path:
        return "chat"
    return "other"


def resolve_base_url(provider: str, key_base_url: str | None,
                     default_base_url: str | None = None) -> str | None:
    """解析上游 Base URL:Key 自定义 > 提供商默认 > 全局默认。"""
    if key_base_url:
        return key_base_url.rstrip("/")
    if default_base_url:
        return default_base_url.rstrip("/")
    base = C.PROVIDER_BASE_URLS.get(provider, "")
    return base.rstrip("/") if base else None
