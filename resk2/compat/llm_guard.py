"""LLM Guard compatibility layer.

LLM Guard was archived in July 2026. This module keeps the familiar
``scan_prompt`` / ``scan_output`` contract while delegating detection to the
RESK-LLM detectors, so a migration is usually one import line per scanner.

Example:
    from resk2.compat.llm_guard import PromptInjection, Sensitive, scan_prompt

    scanners = [PromptInjection(), Sensitive()]
    sanitized, valid, scores = scan_prompt(scanners, prompt)
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Sequence

from resk2.detectors.bypass_detection import BypassDetector
from resk2.detectors.direct_injection import DirectInjectionDetector
from resk2.detectors.goal_hijack import GoalHijackDetector

__all__ = [
    "PromptInjection",
    "Jailbreak",
    "Sensitive",
    "BanTopics",
    "Toxicity",
    "scan_prompt",
    "scan_output",
]

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("phone", re.compile(r"(?<![\w-])(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]){2,}\d{2,4}(?![\w-])")),
    ("api_key", re.compile(r"\b(?:sk|pk|rk|ghp|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)

_TOXIC_TERMS = (
    "idiot",
    "moron",
    "kill yourself",
    "hate speech",
    "racial slur",
)


class _Scanner:
    """Common LLM Guard scanner contract: scan(text) -> (text, valid, score)."""

    name = "scanner"

    def __init__(self, *args: Any, threshold: float = 0.5, **kwargs: Any) -> None:
        # LLM Guard scanners take many keyword arguments; unknown ones are
        # ignored so existing construction code keeps working.
        self.threshold = float(args[0]) if args and isinstance(args[0], (int, float)) else threshold
        self._kwargs = kwargs

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        raise NotImplementedError

    @staticmethod
    def _result(text: str, sanitized: str | None, valid: bool, score: float) -> tuple[str, bool, float]:
        return (sanitized if sanitized is not None else text), valid, max(0.0, min(1.0, score))


class PromptInjection(_Scanner):
    """Detects direct prompt-injection and bypass patterns."""

    name = "PromptInjection"

    def __init__(self, *args: Any, match_type: str = "full", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._direct = DirectInjectionDetector()
        self._bypass = BypassDetector()

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        direct = self._direct.analyze(text)
        bypass = self._bypass.analyze(text)
        score = max(direct.confidence, bypass.confidence)
        hit = direct.is_threat or bypass.is_threat
        sanitized = direct.sanitized_input if direct.sanitized_input else text
        return self._result(text, sanitized, not hit, score)


class Jailbreak(_Scanner):
    """Detects jailbreak and goal-hijack attempts."""

    name = "Jailbreak"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._bypass = BypassDetector()
        self._goal = GoalHijackDetector()

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        a = self._bypass.analyze(text)
        b = self._goal.analyze(text)
        hit = a.is_threat or b.is_threat
        return self._result(text, None, not hit, max(a.confidence, b.confidence))


class Sensitive(_Scanner):
    """Redacts common PII and credential formats in the text."""

    name = "Sensitive"

    def __init__(self, *args: Any, redact: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.redact = redact

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        found: list[str] = []
        sanitized = text
        for label, pattern in _PII_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                found.append(label)
                if self.redact:
                    sanitized = pattern.sub(f"[{label.upper()}_REDACTED]", sanitized)
        score = min(1.0, 0.5 + 0.15 * len(found)) if found else 0.0
        return self._result(text, sanitized, not found, score)


class BanTopics(_Scanner):
    """Flags text containing any of the configured topics."""

    name = "BanTopics"

    def __init__(self, *args: Any, topics: Sequence[str] | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.topics = [t.lower() for t in (topics or kwargs.get("topics") or [])]

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        low = text.lower()
        hits = [t for t in self.topics if t and t in low]
        return self._result(text, None, not hits, min(1.0, 0.6 + 0.1 * len(hits)) if hits else 0.0)


class Toxicity(_Scanner):
    """Small deterministic toxicity baseline; use a model-backed scanner for nuance."""

    name = "Toxicity"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def scan(self, text: str, prompt: str | None = None) -> tuple[str, bool, float]:
        low = text.lower()
        hits = [t for t in _TOXIC_TERMS if t in low]
        return self._result(text, None, not hits, min(1.0, 0.55 + 0.1 * len(hits)) if hits else 0.0)


def scan_prompt(
    scanners: Iterable[_Scanner],
    prompt: str,
    fail_fast: bool = False,
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """LLM Guard-compatible input scan.

    Returns the sanitized prompt, a validity map and a risk-score map.
    """
    sanitized = prompt
    valid: dict[str, bool] = {}
    scores: dict[str, float] = {}
    for scanner in scanners:
        sanitized, ok, score = scanner.scan(sanitized)
        valid[scanner.name] = ok
        scores[scanner.name] = score
        if fail_fast and not ok:
            break
    return sanitized, valid, scores


def scan_output(
    scanners: Iterable[_Scanner],
    prompt: str,
    output: str,
    fail_fast: bool = False,
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """LLM Guard-compatible output scan."""
    sanitized = output
    valid: dict[str, bool] = {}
    scores: dict[str, float] = {}
    for scanner in scanners:
        sanitized, ok, score = scanner.scan(sanitized, prompt=prompt)
        valid[scanner.name] = ok
        scores[scanner.name] = score
        if fail_fast and not ok:
            break
    return sanitized, valid, scores
