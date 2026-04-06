"""Integration with resk-logits for GPU-accelerated logits processing."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"


class ReskLogitsIntegration:
    """Wraps resklogits ShadowBanProcessor for use with Resk-LLM v2.1.

    This is an OPTIONAL integration. If resklogits is not installed,
    no error is raised - the integration simply won't work.

    Usage:
        integration = ReskLogitsIntegration(tokenizer)
        if integration.available:
            processor = integration.get_processor()
            model.generate(..., logits_processor=[processor])

    Requires: pip install resklogits
    """

    def __init__(self, tokenizer=None, config_path: str | Path | None = None):
        self.available = False
        self._processor = None
        self._config_path = config_path
        self._tokenizer = tokenizer

        try:
            from resklogits import ShadowBanProcessor, MultiLevelShadowBanProcessor
            self._shadow_ban_cls = ShadowBanProcessor
            self._multi_level_cls = MultiLevelShadowBanProcessor
            self.available = True
            self._load_config()
        except ImportError:
            self.available = False

    def _load_config(self) -> None:
        cfg_path = Path(self._config_path) if self._config_path else _CONFIG_PATH
        if not cfg_path.exists() or not self.available:
            return
        with open(cfg_path) as f:
            data = yaml.safe_load(f)
        section = data.get("resk_logits_integration", {}) if data else {}
        if not section.get("enabled", True):
            return

        # Load banned phrases from local patterns
        phrases = section.get("banned_phrases", [])
        if not phrases:
            # Fall back to vector_similarity attack_patterns if available
            vs = data.get("vector_similarity", {})
            phrases = vs.get("attack_patterns", [])

        if not phrases or not self._tokenizer:
            return

        # Build processor
        device = section.get("device", "cpu")  # Default to CPU
        penalty = section.get("shadow_penalty", -15.0)

        # Multi-level or flat?
        levels = section.get("levels")
        if levels and isinstance(levels, dict):
            penalties = section.get("level_penalties", {})
            self._processor = self._multi_level_cls(
                tokenizer=self._tokenizer,
                banned_phrases_by_level=levels,
                penalties=penalties,
                device=device,
            )
        else:
            self._processor = self._shadow_ban_cls(
                tokenizer=self._tokenizer,
                banned_phrases=phrases,
                shadow_penalty=penalty,
                device=device,
            )

    def get_processor(self):
        """Returns the logits processor, or None if not available."""
        return self._processor
