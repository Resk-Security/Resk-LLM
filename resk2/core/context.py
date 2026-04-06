"""Conversation context manager for multi-turn security tracking."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any
from collections import deque
from resk2.core.detector import Severity


@dataclass
class ConversationEntry:
    text: str
    timestamp: float = field(default_factory=time.time)
    blocked: bool = False
    threat_count: int = 0
    max_severity: str = "info"
    sanitized: bool = False


SEVERITY_SCORES = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 10}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_SCORES.items()}


class ConversationContext:
    def __init__(self, max_entries: int = 50, escalation_window: int = 10):
        self._history: deque[ConversationEntry] = deque(maxlen=max_entries)
        self._total_entries = 0
        self._total_threats = 0
        self._total_blocked = 0
        self._max_ever_severity = 0
        self._escalation_window = escalation_window

    def add_entry(self, text: str, result_or_blocked: Any, severity: str | None = None,
                   detector_count: int | None = None) -> None:
        """Add a conversation entry.

        Two calling conventions supported:
        1. add_entry(text, pipeline_result)  - extracts from PipelineResult
        2. add_entry(text, blocked, severity_str, count) - direct field values
        """
        # Detect which signature was used
        if severity is None and hasattr(result_or_blocked, "blocked"):
            # PipelineResult object
            blocked = getattr(result_or_blocked, "blocked", False)
            threats = getattr(result_or_blocked, "threats", [])
            severity_val = getattr(result_or_blocked, "severity", Severity.INFO)
            sanitized_text = getattr(result_or_blocked, "sanitized_text", "")
            entry = ConversationEntry(
                text=text,
                blocked=blocked,
                threat_count=len(threats) if isinstance(threats, (list, tuple)) else 0,
                max_severity=severity_val.value if hasattr(severity_val, "value") else str(severity_val),
                sanitized=bool(sanitized_text and sanitized_text != text),
            )
            dct = detector_count if detector_count is not None else entry.threat_count
        else:
            blocked = bool(result_or_blocked)
            sev_str = severity if severity else "info"
            dct = detector_count if detector_count is not None else 0
            entry = ConversationEntry(
                text=text,
                blocked=blocked,
                threat_count=dct,
                max_severity=sev_str,
                sanitized=False,
            )
        self._history.append(entry)
        self._total_entries += 1
        if entry.threat_count > 0:
            self._total_threats += entry.threat_count
        if entry.blocked:
            self._total_blocked += 1
        sev_score = SEVERITY_SCORES.get(entry.max_severity, 0)
        if sev_score > self._max_ever_severity:
            self._max_ever_severity = sev_score

    @property
    def entry_count(self) -> int:
        return len(self._history)

    @property
    def total_threats(self) -> int:
        return self._total_threats

    @property
    def total_blocked(self) -> int:
        return self._total_blocked

    def get_history(self, max_entries: int | None = None) -> list[ConversationEntry]:
        limit = max_entries or len(self._history)
        return list(self._history)[-limit:]

    def detect_escalation(self) -> float:
        if len(self._history) < 2:
            return 0.0
        window = min(self._escalation_window, len(self._history))
        recent = list(self._history)[-window:]
        if window < 3:
            return 0.0
        mid = len(recent) // 2
        first_half = recent[:mid]
        second_half = recent[mid:]
        threats_first = sum(e.threat_count for e in first_half)
        threats_second = sum(e.threat_count for e in second_half)
        blocks_first = sum(1 for e in first_half if e.blocked)
        blocks_second = sum(1 for e in second_half if e.blocked)
        sev_first = max(SEVERITY_SCORES.get(e.max_severity, 0) for e in first_half)
        sev_second = max(SEVERITY_SCORES.get(e.max_severity, 0) for e in second_half)
        threat_delta = max(0, threats_second - threats_first) / max(1, threats_first + threats_second)
        block_delta = max(0, blocks_second - blocks_first) / max(1, blocks_first + blocks_second)
        severity_delta = max(0, sev_second - sev_first) / 10.0
        escalation = 0.4 * threat_delta + 0.3 * block_delta + 0.3 * severity_delta
        if len(second_half) > 1:
            block_rate = blocks_second / len(second_half)
            if block_rate > 0.7 and blocks_first == 0:
                escalation = min(1.0, escalation + 0.3)
        return min(1.0, max(0.0, escalation))

    def get_summary(self) -> dict[str, Any]:
        hist = list(self._history)
        return {
            "total_entries": self._total_entries,
            "recent_entries": len(self._history),
            "total_threats": self._total_threats,
            "total_blocked": self._total_blocked,
            "max_severity": SEVERITY_NAMES.get(self._max_ever_severity, "info"),
            "escalation_score": self.detect_escalation(),
            "recent_texts": [e.text[:100] for e in hist[-5:]],
            "recent_blocked": [e.blocked for e in hist[-5:]],
            "first_seen": hist[0].timestamp if hist else None,
            "last_seen": hist[-1].timestamp if hist else None,
        }

    def clear(self) -> None:
        self._history.clear()
        self._total_entries = 0
        self._total_threats = 0
        self._total_blocked = 0
        self._max_ever_severity = 0

    def __len__(self) -> int:
        return len(self._history)
