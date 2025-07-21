# resk_llm/content_policy_filter.py

import logging
import re
import json
from typing import Dict, List, Set, Any, Optional, Tuple, Union, TypedDict
from re import Pattern
from dataclasses import dataclass, field

# Import RESK-LLM core components and relevant implementations
from resk_llm.core.abc import FilterBase
from resk_llm.core.monitoring import log_security_event, EventType, Severity, performance_monitor
from resk_llm.core.cache import cached_component_call
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider
from resk_llm.utilities.resk_text_analysis import RESK_TextAnalyzer
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase

logger = logging.getLogger(__name__)

# Config type alias
ContentPolicyConfig = Dict[str, Any]

# Type definition for filter results
class FilterResult(TypedDict):
    text: str
    filtered: bool
    competitor_mentions: Dict[str, List[str]]
    banned_code_matches: List[str]
    banned_topic_matches: List[str]
    banned_substring_matches: List[str]
    regex_matches: Dict[str, List[str]]
    reasons: List[str]

@dataclass
class RESK_ContentPolicyFilter(FilterBase[str, Any, Any]):
    config: Any = field(default_factory=dict)
    prohibited_patterns: list = field(default_factory=list)
    prohibited_words: set = field(default_factory=set)
    pattern_provider: Any = None

    def __post_init__(self):
        self._validate_config()

    def _validate_config(self) -> None:
        provider = self.config.get('pattern_provider')
        if provider and isinstance(provider, FileSystemPatternProvider):
            self.pattern_provider = provider
            # Charger les patterns et mots interdits depuis le provider
            self.prohibited_patterns = [re.compile(p, re.IGNORECASE) for p in self.pattern_provider.get_patterns(category='prohibited_patterns')]
            self.prohibited_words = set(self.pattern_provider.get_keywords(sources=['prohibited_words']))
        else:
            # Fallback: charger depuis la config (comportement précédent)
            self.prohibited_patterns = [re.compile(p, re.IGNORECASE) for p in self.config.get('prohibited_patterns', [])]
            self.prohibited_words = set(self.config.get('prohibited_words', []))

    def update_config(self, config: Any) -> None:
        self.config.update(config)
        self._validate_config()

    @performance_monitor('ContentPolicyFilter')
    @cached_component_call('ContentPolicyFilter')
    def filter(self, data: str) -> tuple:
        for pattern in self.prohibited_patterns:
            if pattern.search(data):
                log_security_event(
                    EventType.POLICY_VIOLATION,
                    'ContentPolicyFilter',
                    f'Prohibited pattern detected: {pattern.pattern}',
                    Severity.HIGH,
                    details={'content_preview': data[:100]}
                )
                return False, f'Prohibited pattern detected: {pattern.pattern}', data
        for word in self.prohibited_words:
            if word.lower() in data.lower():
                log_security_event(
                    EventType.POLICY_VIOLATION,
                    'ContentPolicyFilter',
                    f'Prohibited word detected: {word}',
                    Severity.HIGH,
                    details={'content_preview': data[:100]}
                )
                return False, f'Prohibited word detected: {word}', data
        return True, None, data

    def process(self, data: str) -> tuple:
        return self.filter(data) 