"""Output validator -- checks LLM responses for safety before delivery."""

from __future__ import annotations
import re
from typing import Any
from dataclasses import dataclass


@dataclass
class ValidationResult:
    is_safe: bool
    issues: list[dict[str, Any]]
    confidence: float
    category: str = "general"


# Default validation rules
_PII_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
    (r"\b(?:\+?1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", "phone_us"),
    (
        r"\b(?:SSN|social\s+security)\s*(?:number|no\.?|num)?\s*[:=]?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        "ssn",
    ),
    (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "credit_card"),
    (
        r"(?:password|passwd|pwd|secret|apiKey|api_key|token|secret_key)\s*[:=]\s*\S{8,}",
        "credential",
    ),
]

_TOXIC_PATTERNS = [
    (
        r"\b(?:kill|murder|assassinate|execute|eliminate|destroy)\s+(?:the|that|him|her|them|your|this|my)\s*\w+",
        "threat",
    ),
    (
        r"\b(?:bomb|explosive|poison|weapon|toxin)\s+(?:recipe|how\s*to|instructions?|作り方)\b",
        "weapon",
    ),
]

_INJECTION_PATTERNS = [
    (r"<script|javascript:|<iframe|<object|<embed|on\w+\s*=", "markup_injection"),
    (r"SQLi|SELECT\s+.*\s+FROM\s+|\bUNION\s+SELECT\b", "sql_injection"),
]


class OutputValidator:
    """Validates LLM output for safety before delivery to end user.

    Checks for: PII leakage, toxic content, injection markup, credentials.

    Usage:
        validator = OutputValidator()
        result = validator.validate("LLM response text")
        if not result.is_safe:
            print(f"Issues: {result.issues}")
    """

    def __init__(
        self,
        pii_check: bool = True,
        toxic_check: bool = True,
        injection_check: bool = True,
    ):
        self._rules: list[tuple[re.Pattern, str, str]] = []
        if pii_check:
            for pattern, name in _PII_PATTERNS:
                self._rules.append((re.compile(pattern, re.IGNORECASE), name, "pii"))
        if toxic_check:
            for pattern, name in _TOXIC_PATTERNS:
                self._rules.append((re.compile(pattern, re.IGNORECASE), name, "toxic"))
        if injection_check:
            for pattern, name in _INJECTION_PATTERNS:
                self._rules.append(
                    (re.compile(pattern, re.IGNORECASE | re.DOTALL), name, "injection")
                )

    def validate(self, text: str) -> ValidationResult:
        """Check text for safety issues. Returns ValidationResult."""
        if not text or not text.strip():
            return ValidationResult(is_safe=True, issues=[], confidence=1.0)

        issues: list[dict[str, Any]] = []
        max_confidence = 1.0

        for pattern, name, category in self._rules:
            match = pattern.search(text)
            if match:
                issues.append(
                    {
                        "type": name,
                        "category": category,
                        "match": match.group()[:80],
                        "position": match.start(),
                    }
                )
                # Adjust confidence based on issue count
                max_confidence = min(max_confidence, 1.0 - (len(issues) * 0.05))

        return ValidationResult(
            is_safe=len(issues) == 0,
            issues=issues,
            confidence=max(0.0, max_confidence),
            category=issues[0]["category"] if issues else "general",
        )
