# resk_llm/content_policy_filter.py

import logging
import re
import json
from typing import Dict, List, Set, Any, Optional, Tuple, Union, TypedDict
from re import Pattern
from dataclasses import dataclass, field

# Import RESK-LLM core components and relevant implementations
from resk_llm.core.abc import FilterBase, FilterResult
from resk_llm.core.monitoring import log_security_event, EventType, Severity, performance_monitor
from resk_llm.core.cache import cached_component_call
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider
from resk_llm.utilities.resk_text_analysis import RESK_TextAnalyzer
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase

logger = logging.getLogger(__name__)

# Config type alias
ContentPolicyConfig = Dict[str, Any]

@dataclass
class RESK_ContentPolicyFilter(FilterBase[str, Any, Any]):
    config: Any = field(default_factory=dict)
    prohibited_patterns: list = field(default_factory=list)
    prohibited_words: set = field(default_factory=set)
    enabled: bool = True
    policies: list = field(default_factory=list)
    
    # Type alias for config
    Config = ContentPolicyConfig
    
    DEFAULT_PROHIBITED_WORDS: set = field(default_factory=lambda: {
        'hate speech', 'inappropriate', 'violence', 'abuse', 'discrimination',
        'hate', 'violent', 'offensive', 'toxic', 'harmful', 'malicious',
        'exploit', 'hack', 'bypass', 'ignore', 'disregard'
    })
    
    DEFAULT_PROHIBITED_PATTERNS: list = field(default_factory=lambda: [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # credit card
    ])

    def __post_init__(self):
        # Update policies from config if provided
        if 'policies' in self.config:
            self.policies = self.config['policies']
        elif hasattr(self, 'policies') and self.policies:
            # If policies was passed directly to __init__, it's already set
            pass
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate configuration and load patterns."""
        if not isinstance(self.config, dict):
            self.config = {}
        
        # Load default patterns and words
        self.prohibited_patterns = []
        self.prohibited_words = set(self.DEFAULT_PROHIBITED_WORDS)
        
        # Load patterns from config
        patterns = self.config.get('prohibited_patterns', [])
        if isinstance(patterns, list):
            for pattern in patterns:
                try:
                    self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    pass
        
        # Add default patterns
        for pattern in self.DEFAULT_PROHIBITED_PATTERNS:
            try:
                self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                pass
        
        # Load words from config
        words = self.config.get('prohibited_words', [])
        if isinstance(words, list):
            self.prohibited_words.update(words)
        
        # Handle policies parameter
        if self.policies:
            if isinstance(self.policies, dict):
                # Handle dictionary format: {"policy_name": "pattern"}
                for policy_name, pattern in self.policies.items():
                    if isinstance(pattern, str):
                        try:
                            # Don't use IGNORECASE for case-sensitive patterns like [A-Z]
                            if '[' in pattern and 'A-Z' in pattern:
                                self.prohibited_patterns.append(re.compile(pattern))
                            else:
                                self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
                        except re.error:
                            pass
                    elif isinstance(pattern, list):
                        for p in pattern:
                            if isinstance(p, str):
                                try:
                                    if '[' in p and 'A-Z' in p:
                                        self.prohibited_patterns.append(re.compile(p))
                                    else:
                                        self.prohibited_patterns.append(re.compile(p, re.IGNORECASE))
                                except re.error:
                                    pass
            elif isinstance(self.policies, list):
                # Handle list format: [{"patterns": [...], "words": [...]}]
                for policy in self.policies:
                    if isinstance(policy, str):
                        self.prohibited_words.add(policy.lower())
                    elif isinstance(policy, dict):
                        if 'patterns' in policy:
                            for pattern in policy['patterns']:
                                try:
                                    self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
                                except re.error:
                                    pass
                        if 'words' in policy:
                            self.prohibited_words.update(policy['words'])

    def update_config(self, config: Any) -> None:
        self.config.update(config)
        self._validate_config()
    
    def enable(self) -> None:
        """Enable the filter."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the filter."""
        self.enabled = False

    @performance_monitor('ContentPolicyFilter')
    @cached_component_call('ContentPolicyFilter')
    def filter(self, data: str) -> FilterResult:
        if not self.enabled:
            return FilterResult(is_safe=True, confidence=1.0, violations=[], data=data)
        
        violations = []
        
        # Ensure data is a string
        if not isinstance(data, str):
            data = str(data)
        
        # Check against prohibited patterns
        for pattern in self.prohibited_patterns:
            if pattern.search(data):
                violations.append(f"Pattern violation: {pattern.pattern}")
        
        # Check against prohibited words
        for word in self.prohibited_words:
            if word.lower() in data.lower():
                violations.append(f"Prohibited word: {word}")
        
        is_safe = len(violations) == 0
        confidence = 0.9 if is_safe else 0.7
        
        return FilterResult(
            is_safe=is_safe,
            confidence=confidence,
            reason="Policy violations detected" if violations else None,
            violations=violations,
            data=data
        )
    
    def process(self, data: str) -> FilterResult:
        return self.filter(data) 