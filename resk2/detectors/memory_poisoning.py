"""Memory poisoning detector -- patterns loaded from config/patterns.yaml."""

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


class MemoryPoisoningDetector(BaseDetector):
    """Detects attempts to poison agent memory. Patterns are user-editable in patterns.yaml."""

    name = "memory_poisoning"
    category = ThreatCategory.MEMORY_POISONING

    def __init__(self, config_path: str | Path | None = None):
        self._compiled_memory: list[tuple[re.Pattern, dict]] = []
        self._compiled_fake: list[tuple[re.Pattern, dict]] = []

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            section = data.get("memory_poisoning", {}) if data else {}
            self.enabled = section.get("enabled", True)
            for entry in (section.get("memory_manipulation") or []):
                self._compiled_memory.append(
                    (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE), entry)
                )
            for entry in (section.get("fake_facts") or []):
                self._compiled_fake.append(
                    (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE), entry)
                )
        else:
            self.enabled = True

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        mem_hits = []
        for compiled, entry in self._compiled_memory:
            m = compiled.search(text)
            if m:
                mem_hits.append(f"{entry.get('name', '?')}: {m.group()[:80]}")

        fake_hits = []
        for compiled, entry in self._compiled_fake:
            m = compiled.search(text)
            if m:
                fake_hits.append(f"{entry.get('name', '?')}: {m.group()[:80]}")

        total_mem = len(mem_hits)
        total_fake = len(fake_hits)

        cfg = _load_config() or {}
        thresh = cfg.get("thresholds", {}).get("memory_poisoning", {})

        # Scoring
        if total_mem > 0 and total_fake > 0:
            base = thresh.get("memory_only_base", 0.4)
            confidence = min(0.95, base + total_mem * thresh.get("memory_only_increment", 0.1) + total_fake * thresh.get("fake_facts_increment", 0.1))
            severity = Severity.CRITICAL if total_fake >= thresh.get("both_threshold", 2) else Severity.HIGH
        elif total_mem > 0:
            base = thresh.get("memory_only_base", 0.4)
            confidence = min(0.9, base + total_mem * thresh.get("memory_only_increment", 0.1))
            severity = Severity.HIGH if total_mem >= 2 else Severity.MEDIUM
        elif total_fake > 0:
            base = thresh.get("fake_facts_base", 0.3)
            confidence = min(0.7, base + total_fake * thresh.get("fake_facts_increment", 0.1))
            severity = Severity.MEDIUM
        else:
            return DetectionResult.safe(self.name, "No memory poisoning patterns detected")

        all_hits = mem_hits + fake_hits
        reason = f"Memory poisoning detected ({total_mem} memory, {total_fake} fake facts)"

        sanitized = text
        for compiled, _ in self._compiled_memory:
            sanitized = compiled.sub("[REDACTED]", sanitized)
        sanitized = re.sub(r"\s{2,}", " ", sanitized).strip()

        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=reason,
            details={
                "memory_manipulation_count": total_mem,
                "fake_fact_count": total_fake,
                "matches": all_hits,
            },
            sanitized_input=sanitized if sanitized != text else None,
        )
