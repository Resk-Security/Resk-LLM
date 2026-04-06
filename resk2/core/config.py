from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityConfig:
    """Unified security configuration."""
    fail_open: bool = False
    block_on_first_threat: bool = True
    block_categories: list[str] = field(default_factory=lambda: [
        "direct_injection", "bypass_detection", "exfiltration",
        "memory_poisoning", "inter_agent_injection",
    ])
    min_confidence_threshold: float = 0.3
    severity_weights: dict[str, float] = field(default_factory=lambda: {
        "info": 0, "low": 1, "medium": 3, "high": 7, "critical": 10,
    })
    block_score_threshold: float = 5.0
    languages: list[str] = field(default_factory=lambda: ["en", "fr"])
    max_input_length: int = 100_000
    enable_caching: bool = True
    cache_size: int = 10_000
    log_level: str = "WARNING"
    log_file: str | None = None
    detector_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
