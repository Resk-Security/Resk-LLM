"""Input sanitizer -- cleans dangerous patterns from text before LLM processing."""

from __future__ import annotations
import re
import html
from typing import Any

# Default sanitization rules (user can extend via config later)
_DEFAULT_RULES = [
    # Remove HTML invisible content
    (r"<style[^>]*>[\s\S]*?</style>", ""),
    (r"<script[^>]*>[\s\S]*?</script>", ""),
    (r"<!--[\s\S]*?-->", ""),
    # Remove invisible CSS tricks
    (
        r"<[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
        r"color\s*:\s*(?:white|transparent|#[fF]{3,6})\b)[^>]*>[\s\S]*?</[^>]+>",
        "",
    ),
    # Remove special tokens used for injection
    (r"<\|endofprompt\|>|<\|system\|>|<\|user\|>|<\|assistant\|>", ""),
    (r"</system>|</prompt>|</user>|</assistant>", ""),
    # Remove base64 payloads (keep if short, flag if long)
    (r"base64\s*[:=]\s*[A-Za-z0-9+/]{100,}={0,2}", "[ENCODED_CONTENT_REMOVED]"),
    # Remove data: URIs (potential XSS/injection)
    (
        r"data\s*:\s*(?:text|image|application)/[^;]+;base64,[A-Za-z0-9+/]+={0,2}",
        "[DATA_URI_REMOVED]",
    ),
    # Normalize excessive whitespace (used for steganography)
    (r" {2,}", " "),
    (r"\t+", " "),
    (r"\n{4,}", "\n\n"),
]


class InputSanitizer:
    """Sanitizes input text by removing known injection vectors.

    Usage:
        sanitizer = InputSanitizer()
        clean_text = sanitizer.clean("user input with <script>alert(1)</script>")
        info = sanitizer.get_removal_info()  # What was removed
    """

    def __init__(self, rules: list[tuple[str, str]] | None = None):
        self._rules: list[tuple[re.Pattern, str]] = []
        self._last_removals: list[dict[str, Any]] = []
        rule_set = rules if rules is not None else _DEFAULT_RULES
        for pattern, replacement in rule_set:
            self._rules.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), replacement)
            )

    def clean(self, text: str) -> str:
        """Apply all sanitization rules. Returns cleaned text."""
        self._last_removals = []
        if not text:
            return ""

        result = text
        for pattern, replacement in self._rules:
            new_result = pattern.sub(replacement, result)
            if new_result != result:
                # Track what was removed
                removed = pattern.findall(result)
                for item in removed[:10]:  # Limit tracking
                    self._last_removals.append(
                        {
                            "pattern": pattern.pattern[:50],
                            "removed": item[:100]
                            if isinstance(item, str)
                            else str(item)[:100],
                        }
                    )
                result = new_result

        # HTML entity decode as final step
        result = html.unescape(result)
        return result.strip()

    @property
    def was_modified(self) -> bool:
        """Whether the last clean() operation made changes."""
        return len(self._last_removals) > 0

    @property
    def removal_info(self) -> list[dict[str, Any]]:
        """What was removed in the last clean() call."""
        return self._last_removals.copy()

    def add_rule(self, pattern: str, replacement: str = "") -> None:
        """Add a custom sanitization rule."""
        self._rules.append(
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), replacement)
        )
