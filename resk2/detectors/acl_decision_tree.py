"""ACL Decision Tree detector - role-based access control via configurable decision trees."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from resk2.core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "patterns.yaml"


class ACLDecisionTreeDetector(BaseDetector):
    """Evaluates access decisions using a configurable decision tree.

    The tree is defined in patterns.yaml under 'acl_decision_tree'.
    Each node can have:
    - condition: key name to look up in kwargs
    - branches: dict mapping condition values to child nodes
    - action: 'allow' or 'deny' (terminal node)
    - reason: human-readable explanation
    - default: fallback branch when value not found

    Usage:
        acl = ACLDecisionTree(config_path='patterns.yaml')
        result = acl.detect('test', user_role='admin')
        # -> DetectionResult safe/threat based on tree traversal
    """

    name = "acl_decision_tree"
    category = ThreatCategory.DIRECT_INJECTION

    def __init__(self, config_path: str | Path | None = None):
        self._tree: dict[str, Any] = {}

        cfg_path = Path(config_path) if config_path else _CONFIG_PATH
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f)
            section = data.get("acl_decision_tree", {}) if data else {}
            self.enabled = section.get("enabled", True)
            tree_data = section.get("tree") or section.get("root", {})
            # If tree has a "root" key, use that as the actual tree
            self._tree = tree_data.get("root", tree_data) if tree_data else {}
        else:
            self.enabled = True

    def detect(self, text: str, **kwargs: Any) -> DetectionResult:
        if not self._tree:
            return DetectionResult.safe(self.name, "No ACL tree configured")

        action, reason = self._evaluate(self._tree, kwargs)

        if action == "allow":
            return DetectionResult.safe(
                self.name,
                reason or "Access granted",
            )
        else:
            return DetectionResult.threat(
                detector=self.name,
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=0.9,
                reason=reason or "Access denied by ACL policy",
                details={"action": action, "kwargs": kwargs},
            )

    def _evaluate(
        self, node: dict[str, Any], kwargs: dict[str, Any]
    ) -> tuple[str, str]:
        """Recursively evaluate the decision tree node.

        Returns (action, reason) where action is 'allow' or 'deny'.
        Handles both direct kwargs and nested {'context': {...}} format.
        """
        # Build a merged lookup dict from kwargs + any nested 'context' dict
        lookup: dict[str, Any] = {}
        for k, v in kwargs.items():
            if k == "context" and isinstance(v, dict):
                lookup.update(v)
            else:
                lookup[k] = v

        # Terminal node — has action directly
        if "action" in node:
            return node["action"], node.get("reason", "")

        # Decision node — has condition and branches
        condition_key = node.get("condition")
        branches = node.get("branches", {})

        if condition_key:
            value = lookup.get(condition_key)
            # Exact match in branches (try raw value first)
            if value is not None and value in branches:
                return self._evaluate(branches[value], lookup)
            # Try as string
            key_str = str(value)
            if key_str in branches:
                return self._evaluate(branches[key_str], lookup)

        # No match and no default — deny
        return "deny", f"No matching branch for condition '{condition_key}'"
