"""Compatibility shims for other LLM security libraries."""

from .llm_guard import (
    BanTopics,
    Jailbreak,
    PromptInjection,
    Sensitive,
    Toxicity,
    scan_output,
    scan_prompt,
)

__all__ = [
    "PromptInjection",
    "Jailbreak",
    "Sensitive",
    "BanTopics",
    "Toxicity",
    "scan_prompt",
    "scan_output",
]
