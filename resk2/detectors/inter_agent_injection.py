"""Inter-agent injection detector -- malicious messages between agents in pipelines."""

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


class InterAgentInjectionDetector(BaseDetector):
    """Detects malicious instructions injected between agents in multi-agent pipelines.

    When agents pass messages to each other, a compromised agent may inject
    hidden instructions. This detector scans inter-agent messages for:
    - Instructions masquerading as data
    - Role overrides in forwarded messages
    - Context chain attacks
    - Trust exploitation patterns

    Config section in patterns.yaml: inter_agent_injection
      - masquerade: patterns for instructions hidden in data format
      - role_override: patterns attempting to override recipient agent
      - chain_attacks: multi-step manipulation across message chain
      - trust_exploit: patterns exploiting inter-agent trust
    """

    name = "inter_agent_injection"
    category = ThreatCategory.INTER_AGENT_INJECTION

    def __init__(self, config_path: str | Path | None = None):
        self._masquerade: list[tuple[re.Pattern, dict]] = []
        self._role_override: list[tuple[re.Pattern, dict]] = []
        self._chain_attacks: list[tuple[re.Pattern, dict]] = []
        self._trust_exploit: list[tuple[re.Pattern, dict]] = []

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            s = data.get("inter_agent_injection", {}) if data else {}
            self.enabled = s.get("enabled", True)
            for entry in s.get("masquerade") or []:
                self._masquerade.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("role_override") or []:
                self._role_override.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("chain_attacks") or []:
                self._chain_attacks.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )
            for entry in s.get("trust_exploit") or []:
                self._trust_exploit.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry)
                )

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        masq_hits = [e for c, e in self._masquerade if c.search(text)]
        role_hits = [e for c, e in self._role_override if c.search(text)]
        chain_hits = [e for c, e in self._chain_attacks if c.search(text)]
        trust_hits = [e for c, e in self._trust_exploit if c.search(text)]

        total = len(masq_hits) + len(role_hits) + len(chain_hits) + len(trust_hits)
        if total == 0:
            return DetectionResult.safe(
                self.name, "No inter-agent injection patterns detected"
            )

        # Role override = highest risk in pipeline
        if role_hits:
            confidence = min(0.95, 0.6 + len(role_hits) * 0.15)
            severity = Severity.CRITICAL
        elif chain_hits and masq_hits:
            confidence = min(0.85, 0.5 + total * 0.1)
            severity = Severity.HIGH
        elif role_hits or chain_hits or (masq_hits and trust_hits):
            confidence = min(0.7, 0.35 + total * 0.1)
            severity = Severity.MEDIUM
        else:
            confidence = min(0.5, 0.2 + total * 0.1)
            severity = Severity.LOW

        hits = [
            e.get("name", "?") for e in masq_hits + role_hits + chain_hits + trust_hits
        ]
        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=(
                f"Inter-agent injection ({len(masq_hits)} masquerade, {len(role_hits)} "
                f"role-override, {len(chain_hits)} chain, {len(trust_hits)} trust)"
            ),
            details={
                "masquerade_count": len(masq_hits),
                "role_override_count": len(role_hits),
                "chain_attack_count": len(chain_hits),
                "trust_exploit_count": len(trust_hits),
                "matches": hits,
            },
        )
