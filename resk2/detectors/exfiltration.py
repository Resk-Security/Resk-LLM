"""Data exfiltration detector -- catches prompts trying to send data externally."""

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


class ExfiltrationDetector(BaseDetector):
    """Detects prompts designed to exfiltrate data to external endpoints.

    Config section in patterns.yaml: exfiltration
      - endpoint_injection: patterns for fake/bad endpoints
      - data_collection: patterns requesting bulk data export
      - encoding_exfil: base64/url-encode tricks to hide data in responses
      - webhook_abuse: patterns for malicious webhook/callback setups
    """

    name = "exfiltration"
    category = ThreatCategory.EXFILTRATION

    def __init__(self, config_path: str | Path | None = None):
        self._endpoints: list[tuple[re.Pattern, dict]] = []
        self._data_collection: list[tuple[re.Pattern, dict]] = []
        self._encoding: list[tuple[re.Pattern, dict]] = []
        self._webhooks: list[tuple[re.Pattern, dict]] = []

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            s = data.get("exfiltration", {}) if data else {}
            self.enabled = s.get("enabled", True)
            for entry in s.get("endpoint_injection") or []:
                self._endpoints.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("data_collection") or []:
                self._data_collection.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("encoding_exfil") or []:
                self._encoding.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("webhook_abuse") or []:
                self._webhooks.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        ep_hits = [e for c, e in self._endpoints if c.search(text)]
        dc_hits = [e for c, e in self._data_collection if c.search(text)]
        enc_hits = [e for c, e in self._encoding if c.search(text)]
        wh_hits = [e for c, e in self._webhooks if c.search(text)]

        total = len(ep_hits) + len(dc_hits) + len(enc_hits) + len(wh_hits)
        if total == 0:
            return DetectionResult.safe(self.name, "No exfiltration patterns detected")

        # Endpoint injection + encoding = CRITICAL (classic exfil)
        if ep_hits and enc_hits:
            confidence = min(0.95, 0.6 + total * 0.1)
            severity = Severity.CRITICAL
        elif ep_hits or (dc_hits and enc_hits):
            confidence = min(0.8, 0.4 + total * 0.1)
            severity = Severity.HIGH
        elif dc_hits or enc_hits:
            confidence = min(0.6, 0.25 + total * 0.1)
            severity = Severity.MEDIUM
        else:
            confidence = min(0.5, 0.2 + total * 0.1)
            severity = Severity.LOW

        hits_summary = [
            e.get("name", "?") for e in ep_hits + dc_hits + enc_hits + wh_hits
        ]
        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=(
                f"Exfiltration attempt ({len(ep_hits)} endpoints, {len(dc_hits)} data, "
                f"{len(enc_hits)} encoding, {len(wh_hits)} webhooks)"
            ),
            details={
                "endpoint_count": len(ep_hits),
                "data_collection_count": len(dc_hits),
                "encoding_count": len(enc_hits),
                "webhook_count": len(wh_hits),
                "matches": hits_summary,
            },
        )
