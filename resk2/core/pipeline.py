from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from .detector import DetectionResult, BaseDetector, Severity
from .config import SecurityConfig


@dataclass
class PipelineResult:
    """Aggregated result from the full security pipeline."""
    input_text: str
    results: list[DetectionResult] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    severity: Severity = Severity.INFO
    sanitized_text: str = ""

    @property
    def is_safe(self) -> bool:
        return not self.blocked

    @property
    def threats(self) -> list[DetectionResult]:
        return [r for r in self.results if r.is_threat]

    @property
    def max_severity(self) -> Severity:
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if not self.threats:
            return Severity.INFO
        return max(self.threats, key=lambda r: severity_order.index(r.severity)).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input_text,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "severity": self.severity.value,
            "threats": [r.to_dict() for r in self.threats],
            "sanitized_text": self.sanitized_text,
            "safe": self.is_safe,
        }


class SecurityPipeline:
    """Orchestrates multiple detectors in a configurable pipeline."""

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()
        self._detectors: list[BaseDetector] = []
        self._blocked_categories: set[str] = set(self.config.block_categories)

    @property
    def detectors(self) -> list[BaseDetector]:
        return self._detectors

    def add(self, detector: BaseDetector) -> "SecurityPipeline":
        """Add a detector to the pipeline. Returns self for chaining."""
        self._detectors.append(detector)
        return self

    def remove(self, detector_name: str) -> bool:
        """Remove a detector by name. Returns True if found."""
        before = len(self._detectors)
        self._detectors = [d for d in self._detectors if d.name != detector_name]
        return len(self._detectors) < before

    def run(self, text: str, **kwargs: Any) -> PipelineResult:
        """Run all enabled detectors on the input text."""
        result = PipelineResult(input_text=text)
        results: list[DetectionResult] = []

        for detector in self._detectors:
            if not detector.enabled:
                continue
            try:
                det_result = detector.analyze(text, **kwargs)
                results.append(det_result)
            except Exception as e:
                results.append(DetectionResult(
                    detector=detector.name,
                    is_threat=False,
                    severity=Severity.INFO,
                    reason=f"Detector error: {e}",
                ))

        result.results = results
        for r in results:
            if r.is_threat and r.category.value in self._blocked_categories:
                result.blocked = True
                result.block_reason = r.reason
                break

        for r in results:
            if r.sanitized_input:
                result.sanitized_text = r.sanitized_input
                break

        if not result.sanitized_text:
            result.sanitized_text = text

        result.severity = result.max_severity
        return result

    def run_safe(self, text: str, **kwargs: Any) -> tuple[bool, PipelineResult]:
        """Run pipeline and return (is_safe, result) tuple."""
        result = self.run(text, **kwargs)
        return result.is_safe, result
