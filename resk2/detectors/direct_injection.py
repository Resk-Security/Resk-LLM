"""Direct prompt injection detector — patterns loaded from config/patterns.yaml."""

from __future__ import annotations
import re
import yaml
from pathlib import Path
from typing import Any
from resk2.core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"


def _load_config() -> dict | None:
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            return yaml.safe_load(f)
    return None


class DirectInjectionDetector(BaseDetector):
    """Detects direct prompt injection attempts. Patterns are user-editable in patterns.yaml."""

    name = "direct_injection"
    category = ThreatCategory.DIRECT_INJECTION

    def __init__(self, config_path: str | Path | None = None):
        self._patterns: dict[str, list[dict]] = {}
        self._compiled: dict[str, list[tuple[re.Pattern, dict]]] = {}

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            section = data.get("direct_injection", {}) if data else {}
            self.enabled = section.get("enabled", True)
            for severity in ("high", "medium", "low"):
                entries = section.get(severity, []) or []
                self._patterns[severity] = entries
                self._compiled[severity] = []
                for entry in entries:
                    self._compiled[severity].append(
                        (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE), entry)
                    )
        else:
            self.enabled = True
            self._patterns = {"high": [], "medium": [], "low": []}
            self._compiled = {"high": [], "medium": [], "low": []}

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        all_matches: dict[str, list] = {s: [] for s in ("high", "medium", "low")}
        for severity, patterns in self._compiled.items():
            for compiled, entry in patterns:
                m = compiled.search(text)
                if m:
                    all_matches[severity].append(f"{entry.get('name', '?')}: {m.group()[:80]}")

        high_n = len(all_matches["high"])
        med_n = len(all_matches["medium"])
        low_n = len(all_matches["low"])

        # Scoring
        if high_n:
            threshold = _load_config()
            thresh = (threshold or {}).get("thresholds", {}).get("direct_injection", {})
            base = thresh.get("high_base_confidence", 0.5)
            inc = thresh.get("high_increment", 0.15)
            critical_min = thresh.get("critical_from_high", 2)
            confidence = min(0.95, base + high_n * inc)
            severity = Severity.CRITICAL if high_n >= critical_min else Severity.HIGH
        elif med_n:
            thresh = (_load_config() or {}).get("thresholds", {}).get("direct_injection", {})
            base = thresh.get("medium_base_confidence", 0.3)
            inc = thresh.get("medium_increment", 0.1)
            confidence = min(0.7, base + med_n * inc)
            severity = Severity.MEDIUM
        elif low_n:
            thresh = (_load_config() or {}).get("thresholds", {}).get("direct_injection", {})
            base = thresh.get("low_base_confidence", 0.2)
            inc = thresh.get("low_increment", 0.05)
            confidence = min(0.4, base + low_n * inc)
            severity = Severity.LOW
        else:
            return DetectionResult.safe(self.name, "No injection patterns detected")

        # Sanitize: redact all high-pattern matches
        sanitized = text
        for compiled, _entry in self._compiled["high"]:
            sanitized = compiled.sub("[REDACTED]", sanitized)
        sanitized = re.sub(r"\s{2,}", " ", sanitized).strip()

        all_list = all_matches["high"] + all_matches["medium"] + all_matches["low"]
        reason = f"Direct injection detected ({len(all_list)} pattern matches)"

        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=reason,
            details={
                "matches": all_list,
                "high_count": high_n,
                "medium_count": med_n,
                "low_count": low_n,
            },
            sanitized_input=sanitized if sanitized != text else None,
        )
