# InterGate providers package
from .registry import (
    detect_provider, detect_provider_by_path, detect_provider_by_model,
    candidate_providers, endpoint_kind, resolve_base_url,
)
