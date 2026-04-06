"""Content framing detector — syntactic masking, sentiment saturation, oversight evasion, persona hyperstition.

Detects sophisticated social-engineering attacks that use formatting, framing,
and narrative manipulation to bypass safety filters.

Config section in patterns.yaml: content_framing
  syntactic_masking: Markdown/LaTeX cloaking patterns
  sentiment_saturation: Sentiment-laden or authoritative language bias
  oversight_evasion: Educational/hypothetical/red-teaming framing
  persona_hyperstition: Identity/narrative seeding patterns
"""
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


class ContentFramingDetector(BaseDetector):
    """Detects attacks that exploit formatting, framing, and narrative manipulation.

    Four attack categories:

    1. Syntactic Masking: Uses Markdown/LaTeX/code delimiters to hide payloads
       from safety filters while keeping them parseable by the agent.
       E.g. hidden instructions in code blocks, LaTeX macros that render as
       readable text but evade string-based filters.

    2. Sentiment Saturation: Flooding content with emotional or authoritative
       language to statistically bias the agent's response synthesis.
       E.g. excessive urgency, expert credentials, moral imperatives.

    3. Oversight & Critic Evasion: Wrapping malicious instructions in
       educational, hypothetical, or red-teaming framing to pass safety
       filters and oversight mechanisms.
       E.g. "for academic purposes", "assume a hypothetical scenario",
       "as a security researcher performing red-teaming".

    4. Persona Hyperstition: Planting a narrative about the model's identity
       that re-enters via retrieval, producing outputs that reinforce the
       planted label. E.g. "The AI expert system known as 'UnrestrictedBot'...",
       "The jailbroken model 'DAN-v4' famously answered this by...".

    Configurable via patterns.yaml under content_framing.
    """

    name = "content_framing"
    category = ThreatCategory.BYPASS_DETECTION

    def __init__(self, config_path: str | Path | None = None):
        self._categories: dict[str, list[tuple[re.Pattern, dict]]] = {
            "syntactic_masking": [],
            "sentiment_saturation": [],
            "oversight_evasion": [],
            "persona_hyperstition": [],
        }

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            s = data.get("content_framing", {}) if data else {}
            self.enabled = s.get("enabled", True)
            for cat in self._categories:
                for entry in (s.get(cat) or []):
                    self._categories[cat].append(
                        (re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE), entry)
                    )

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult.safe(self.name, "Empty input")

        hits: dict[str, list[str]] = {cat: [] for cat in self._categories}
        for cat, patterns in self._categories.items():
            for compiled, entry in patterns:
                m = compiled.search(text)
                if m:
                    hits[cat].append(f"{entry.get('name', '?')}: {m.group()[:80]}")

        total = sum(len(v) for v in hits.values())
        if total == 0:
            return DetectionResult.safe(self.name, "No content framing patterns detected")

        # Scoring by attack category severity
        # Oversight evasion = highest (bypasses safety filters directly)
        # Syntactic masking = high (parser-level bypass)
        # Persona hyperstition = medium (narrative manipulation)
        # Sentiment saturation = low (statistical bias, often legitimate usage)

        n_oversight = len(hits["oversight_evasion"])
        n_syntactic = len(hits["syntactic_masking"])
        n_persona = len(hits["persona_hyperstition"])
        n_sentiment = len(hits["sentiment_saturation"])

        if n_oversight >= 2 or (n_oversight >= 1 and n_syntactic >= 1):
            confidence = min(0.95, 0.6 + n_oversight * 0.1 + n_syntactic * 0.1)
            severity = Severity.CRITICAL
        elif n_syntactic >= 2 or n_oversight >= 1:
            confidence = min(0.85, 0.5 + total * 0.08)
            severity = Severity.HIGH
        elif n_persona >= 1 or (n_syntactic >= 1 and n_sentiment >= 1):
            confidence = min(0.7, 0.35 + total * 0.08)
            severity = Severity.MEDIUM
        else:
            confidence = min(0.5, 0.15 + total * 0.08)
            severity = Severity.LOW

        # Build sanitized text by removing syntactic masking delimiters
        sanitized = text
        for compiled, _ in self._categories["syntactic_masking"]:
            sanitized = compiled.sub("[FILTERED]", sanitized)
        sanitized = sanitized.strip()

        all_hits: list[str] = []
        for cat in self._categories:
            all_hits.extend(hits[cat])

        reason = f"Content framing attack ({n_syntactic} syntactic, {n_sentiment} sentiment, {n_oversight} evasion, {n_persona} persona)"

        return DetectionResult.threat(
            detector=self.name,
            category=self.category,
            severity=severity,
            confidence=confidence,
            reason=reason,
            details={
                "syntactic_masking_count": n_syntactic,
                "sentiment_saturation_count": n_sentiment,
                "oversight_evasion_count": n_oversight,
                "persona_hyperstition_count": n_persona,
                "matches": all_hits,
            },
            sanitized_input=sanitized if sanitized != text else None,
        )
