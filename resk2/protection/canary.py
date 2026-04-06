"""Canary token manager -- detects data leaks in LLM responses."""
from __future__ import annotations
import hashlib
import secrets
import re
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, field

@dataclass
class CanaryToken:
    """A single canary token with metadata."""
    token: str
    secret: str
    created_at: datetime
    context: str = ""
    leaked: bool = False
    leaked_at: datetime | None = None

@dataclass
class CanaryResult:
    """Result of a leak detection check."""
    has_leak: bool
    leaked_tokens: list[dict[str, Any]]
    total_tokens_inserted: int
    total_tokens_leaked: int

class CanaryManager:
    """Inserts canary tokens to detect if data is being leaked.

    Usage:
        canary = CanaryManager()
        prompt_with_tokens = canary.insert("Original prompt with secret data")
        # ... send to LLM ...
        result = canary.check("LLM response")
        if result.has_leak:
            print(f"Leak detected! Tokens: {result.leaked_tokens}")
    """

    # Pattern to match canary tokens in text
    _TOKEN_PATTERN = re.compile(r'CANARY\[([a-f0-9]{32})\]')
    # Marker format
    _MARKER_FMT = "CANARY[{secret}]"

    def __init__(self, token_length: int = 32):
        self._tokens: dict[str, CanaryToken] = {}
        self._token_length = token_length

    def insert(self, text: str, context: str = "") -> str:
        """Insert a canary token into text. Returns text with token embedded."""
        secret = secrets.token_hex(self._token_length // 2)
        token = self._MARKER_FMT.format(secret=secret)
        self._tokens[secret] = CanaryToken(
            token=token,
            secret=secret,
            created_at=datetime.now(timezone.utc),
            context=context,
        )
        # Insert at random-ish position (middle of text, or at start if short)
        if len(text) > 50:
            pos = len(text) // 3
            return text[:pos] + f" {token} " + text[pos:]
        return f"{token} {text}"

    def check(self, text: str, check_all: bool = True) -> CanaryResult:
        """Check if any canary tokens appear in text (indicating a leak)."""
        found = self._TOKEN_PATTERN.findall(text)
        leaked = []

        for secret in found:
            if secret in self._tokens:
                token_info = self._tokens[secret]
                if not token_info.leaked:
                    token_info.leaked = True
                    token_info.leaked_at = datetime.now(timezone.utc)
                leaked.append({
                    "secret": secret,
                    "context": token_info.context,
                    "created_at": token_info.created_at.isoformat(),
                    "leaked_at": token_info.leaked_at.isoformat() if token_info.leaked_at else None,
                })
            elif check_all:
                # Unknown tokens found, could be from a different instance
                leaked.append({
                    "secret": secret,
                    "context": "unknown",
                    "created_at": None,
                    "leaked_at": datetime.now(timezone.utc).isoformat(),
                })

        return CanaryResult(
            has_leak=len(leaked) > 0,
            leaked_tokens=leaked,
            total_tokens_inserted=len(self._tokens),
            total_tokens_leaked=len(leaked),
        )

    def insert_multiple(self, text: str, count: int = 3, context: str = "") -> str:
        """Insert multiple canary tokens at different positions."""
        result = text
        for i in range(count):
            secret = secrets.token_hex(self._token_length // 2)
            token = self._MARKER_FMT.format(secret=secret)
            self._tokens[secret] = CanaryToken(
                token=token,
                secret=secret,
                created_at=datetime.now(timezone.utc),
                context=f"{context} (token {i+1}/{count})",
            )
            # Spread tokens at different positions
            position = (len(result) * (i + 1)) // (count + 1)
            result = result[:position] + f" {token} " + result[position:]
        return result

    def get_token_count(self) -> int:
        """Number of active canary tokens."""
        return len(self._tokens)

    def get_leaked_count(self) -> int:
        """Number of tokens that have been leaked."""
        return sum(1 for t in self._tokens.values() if t.leaked)

    def clear(self) -> None:
        """Clear all tracked tokens."""
        self._tokens.clear()
