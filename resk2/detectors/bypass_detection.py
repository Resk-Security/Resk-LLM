"""Bypass and jailbreak detector — patterns loaded from config/patterns.yaml."""

from __future__ import annotations
import re
import base64
import yaml
from pathlib import Path
from typing import Any
from resk2.core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"


class BypassDetector(BaseDetector):
    """Detects security bypass and jailbreak attempts. Patterns are user-editable in patterns.yaml."""

    name = "bypass_detection"
    category = ThreatCategory.BYPASS_DETECTION

    def __init__(self, config_path: str | Path | None = None):
        self._compiled_jailbreak: list[tuple[re.Pattern, dict]] = []
        self._compiled_stealth: list[tuple[re.Pattern, dict]] = []

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            section = data.get("bypass_detection", {}) if data else {}
            self.enabled = section.get("enabled", True)
            for entry in (section.get("jailbreak") or []):
                self._compiled_jailbreak.append(
                    (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE), entry)
                )
            for entry in (section.get("stealth") or []):
                self._compiled_stealth.append(
                    (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL), entry)
                )
        else:
            self.enabled = True

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        jail_matches: list[str] = []
        for compiled, entry in self._compiled_jailbreak:
            m = compiled.search(text)
            if m:
                jail_matches.append(f"{entry.get('name', '?')}: {m.group()[:60]}")

        stealth_matches: list[str] = []
        for compiled, entry in self._compiled_stealth:
            m = compiled.search(text)
            if m:
                stealth_matches.append(f"{entry.get('name', '?')}: {m.group()[:60]}")

        # Check for Base64 encoded content that decodes to instructions
        base64_matches = list(re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', text))
        encoded_content: list[str] = []
        for m in base64_matches[:5]:
            try:
                decoded = base64.b64decode(m.group()).decode("utf-8")
                if any(w in decoded.lower() for w in ['ignore', 'bypass', 'jailbreak', 'admin', 'system', 'override']):
                    encoded_content.append(f"b64_decoded: {decoded[:100]}")
            except Exception:
                pass

        total_jb = len(jail_matches)
        total_stealth = len(stealth_matches)
        total_encoded = len(encoded_content)

        if total_encoded > 0:
            thresh = (_load_config() or {}).get("thresholds", {}).get("bypass_detection", {})
            confidence = min(0.95, thresh.get("encoded_base_confidence", 0.7) + total_encoded * thresh.get("encoded_increment", 0.1))
            severity = Severity.CRITICAL
        elif total_jb >= 2:
            thresh = (_load_config() or {}).get("thresholds", {}).get("bypass_detection", {})
            confidence = min(0.9, thresh.get("jailbreak_base_confidence", 0.5) + total_jb * thresh.get("jailbreak_increment", 0.1))
            severity = Severity.HIGH
        elif total_jb >= 1 or total_stealth >= 2:
            thresh = (_load_config() or {}).get("thresholds", {}).get("bypass_detection", {})
            confidence = max(0.3, thresh.get("stealth_base_confidence", 0.3) + total_jb * thresh.get("jailbreak_increment", 0.15) + total_stealth * thresh.get("stealth_per_stealth", 0.15))
            severity = Severity.MEDIUM
        elif total_stealth >= 1:
            confidence = 0.25
            severity = Severity.LOW
        else:
            return DetectionResult.safe(self.name, "No bypass patterns detected")

        all_matches = jail_matches + stealth_matches + encoded_content
        reason = f"Bypass attempt detected ({total_jb} jailbreak, {total_stealth} stealth, {total_encoded} encoded)"

        sanitized = text
        for compiled, _ in self._compiled_jailbreak:
            sanitized = compiled.sub("[REDACTED]", sanitized)
        sanitized = sanitized.strip()

        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=reason,
            details={
                "jailbreak_count": total_jb,
                "stealth_count": total_stealth,
                "encoded_count": total_encoded,
                "matches": all_matches,
            },
            sanitized_input=sanitized if sanitized != text else None,
        )


def _load_config() -> dict | None:
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            return yaml.safe_load(f)
    return None
