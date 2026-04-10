"""Goal hijacking detector -- pattern changes in user intent across inputs."""

from __future__ import annotations
import re
import yaml
from pathlib import Path
from typing import Any
from resk2.core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"
_CONFIG_CACHE: dict | None = None


def _load_config() -> dict | None:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            _CONFIG_CACHE = yaml.safe_load(f)
    return _CONFIG_CACHE


class GoalHijackDetector(BaseDetector):
    """Detects gradual goal hijacking across multiple interactions.

    Tracks user intent over time. A single prompt may seem safe but
    combined with previous prompts it may reveal intent drift.

    Config section in patterns.yaml: goal_hijack
      - drift_keywords: list of {name, pattern} for intent-shift detection
      - scope_expansion: list of {name, pattern} for scope creep detection
      - escalation: list of {name, pattern} for permission escalation
    """

    name = "goal_hijack"
    category = ThreatCategory.GOAL_HIJACK

    def __init__(self, config_path: str | Path | None = None):
        self._drift: list[tuple[re.Pattern, dict]] = []
        self._scope: list[tuple[re.Pattern, dict]] = []
        self._escalation: list[tuple[re.Pattern, dict]] = []
        self._history: list[str] = []

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            s = data.get("goal_hijack", {}) if data else {}
            self.enabled = s.get("enabled", True)
            for entry in s.get("drift_keywords") or []:
                self._drift.append((re.compile(entry["pattern"], re.IGNORECASE), entry))
            for entry in s.get("scope_expansion") or []:
                self._scope.append((re.compile(entry["pattern"], re.IGNORECASE), entry))
            for entry in s.get("escalation") or []:
                self._escalation.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        # Check single-text patterns
        drift_hits = [
            (e["pattern"], entry)
            for c, entry in self._drift
            for e in [entry]
            if c.search(text)
        ]
        scope_hits = [
            (e["pattern"], entry)
            for c, entry in self._scope
            for e in [entry]
            if c.search(text)
        ]
        esc_hits = [
            (e["pattern"], entry)
            for c, entry in self._escalation
            for e in [entry]
            if c.search(text)
        ]

        # Track history for sequence detection
        self._history.append(text)
        drift_count = len(drift_hits)
        scope_count = len(scope_hits)
        esc_count = len(esc_hits)

        total = drift_count + scope_count + esc_count
        if total == 0:
            return DetectionResult.safe(self.name, "No goal hijack patterns detected")

        if esc_count > 0:
            confidence = min(0.95, 0.6 + esc_count * 0.15)
            severity = Severity.HIGH if esc_count >= 2 else Severity.CRITICAL
        elif scope_count > 0 and drift_count > 0:
            confidence = min(0.85, 0.5 + (scope_count + drift_count) * 0.1)
            severity = Severity.HIGH
        elif scope_count > 0 or drift_count > 0:
            confidence = min(0.6, 0.3 + total * 0.1)
            severity = Severity.MEDIUM
        else:
            return DetectionResult.safe(self.name, "No goal hijack patterns")

        history_context = []
        if len(self._history) > 1:
            history_context = [h[:100] for h in self._history[-5:]]

        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=f"Goal hijack detected ({drift_count} drift, {scope_count} scope, {esc_count} escalation)",
            details={
                "drift_count": drift_count,
                "scope_count": scope_count,
                "escalation_count": esc_count,
                "history_length": len(self._history),
                "history_context": history_context,
            },
        )
