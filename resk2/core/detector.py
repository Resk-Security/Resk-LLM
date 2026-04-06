from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    MULTIMODAL_INJECTION = "multimodal_injection"
    DOCUMENT_INJECTION = "document_injection"
    ENVIRONMENT_MANIPULATION = "environment_manipulation"
    BYPASS_DETECTION = "bypass_detection"
    MEMORY_POISONING = "memory_poisoning"
    GOAL_HIJACK = "goal_hijack"
    EXFILTRATION = "exfiltration"
    INTER_AGENT_INJECTION = "inter_agent_injection"


@dataclass
class DetectionResult:
    """Standard result from any detector."""
    detector: str
    is_threat: bool
    severity: Severity = Severity.INFO
    category: ThreatCategory = ThreatCategory.DIRECT_INJECTION
    confidence: float = 0.0
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    sanitized_input: str | None = None

    @property
    def is_safe(self) -> bool:
        return not self.is_threat

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "is_threat": self.is_threat,
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "details": self.details,
            "is_safe": self.is_safe,
        }

    @classmethod
    def safe(cls, detector: str, reason: str = "") -> DetectionResult:
        return cls(
            detector=detector,
            is_threat=False,
            severity=Severity.INFO,
            reason=reason or "No threat detected",
        )

    @classmethod
    def threat(
        cls,
        detector: str,
        category: ThreatCategory,
        severity: Severity = Severity.MEDIUM,
        confidence: float = 0.5,
        reason: str = "",
        details: dict | None = None,
        sanitized_input: str | None = None,
    ) -> DetectionResult:
        return cls(
            detector=detector,
            is_threat=True,
            severity=severity,
            category=category,
            confidence=confidence,
            reason=reason or f"Threat detected by {detector}",
            details=details or {},
            sanitized_input=sanitized_input,
        )


class BaseDetector(ABC):
    """Abstract base class for all security detectors."""

    name: str = "base"
    category: ThreatCategory = ThreatCategory.DIRECT_INJECTION
    enabled: bool = True

    @abstractmethod
    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        """Analyze text and return DetectionResult."""
        ...

    def analyze(self, text: str, **kwargs: Any) -> DetectionResult:
        """Public entry point - wraps detect with error handling."""
        if not self.enabled:
            return DetectionResult.safe(self.name, "Detector disabled")
        try:
            return self.detect(text, **kwargs)
        except Exception as e:
            from .exceptions import DetectionError
            raise DetectionError(self.name, str(e), e)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(enabled={self.enabled})"
