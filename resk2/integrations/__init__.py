"""Optional integrations.

Submodules are imported lazily: importing ``resk2.integrations`` must not
require Starlette/OpenAI/resklogits, only the module you actually use.
"""

from __future__ import annotations

__all__ = ["ReskMiddleware", "OpenAIWrapper", "ReskLogitsIntegration"]

_MODULE_BY_NAME = {
    "ReskMiddleware": "fastapi",
    "OpenAIWrapper": "resk_openai",
    "ReskLogitsIntegration": "resk_logits",
}


def __getattr__(name: str):
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from importlib import import_module

    module = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *__all__])
