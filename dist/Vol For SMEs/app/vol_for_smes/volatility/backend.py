from __future__ import annotations

DEFAULT_VOLATILITY_BACKEND = "volatility3"
BACKEND_LABEL = "Windows (Volatility 3)"


def backend_label(_backend: str | None = None) -> str:
    return BACKEND_LABEL
