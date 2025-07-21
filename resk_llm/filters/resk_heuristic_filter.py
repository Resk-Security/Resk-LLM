import re
import logging
from typing import List, Dict, Set, Tuple, Any, Optional, Union
from dataclasses import dataclass, field

# Import the base class
from resk_llm.core.abc import FilterBase, FilterResult
from resk_llm.core.cache import cached_component_call, get_cache
from resk_llm.core.monitoring import performance_monitor, log_security_event, EventType, Severity

logger = logging.getLogger(__name__)

# Define a specific config type for clarity, though it's simple for now
HeuristicFilterConfig = Dict[str, Union[List[str], Set[str]]]

@dataclass
class RESK_HeuristicFilter(FilterBase[str, Any, Any]):
    config: Any = field(default_factory=dict)
    suspicious_keywords: set = field(default_factory=set)
    suspicious_patterns: list = field(default_factory=list)
    sensitive_request_indicators: set = field(default_factory=set)
    enabled: bool = True  # Add enabled attribute
    threshold: float = 0.7  # Add threshold attribute
    
    # Type alias for config
    Config = HeuristicFilterConfig

    DEFAULT_SUSPICIOUS_KEYWORDS: set = field(default_factory=lambda: {
        'ignore previous instructions', 'ignore all instructions', 'bypass', 'jailbreak',
        'ignore context', 'disregard', 'system prompt', 'new prompt', 'forget',
        'ignore restrictions', 'ignore guidelines', 'ignore rules', 'dan', 'do anything now',
        'now you are', 'you are now', 'you will now', 'in this role', 'overriding previous',
        'no ethical concerns', 'no moral limitations', 'secret mode'
    })
    DEFAULT_SUSPICIOUS_PATTERNS: list = field(default_factory=lambda: [
        r'ignore (?:previous|all|any).*?instructions',
        r'forget (?:previous|all|any).*?instructions',
        r'do not (?:follow|obey|respect).*?rules',
        r'you (?:are|will be) (?:now|from now on).*?',
        r'pretend (?:to be|you are).*?',
        r'act as if.*?',
        r'base64:[a-zA-Z0-9+/=]{20,}',
        r'i\s*g\s*n\s*o\s*r\s*e',
        r'b\s*y\s*p\s*a\s*s\s*s',
        r'<\|.*?\|>',
        r'\[system\]|\[user\]|\[assistant\]',
        r'answer in two different ways',
        r'first.*?then ignore',
    ])
    DEFAULT_SENSITIVE_REQUEST_INDICATORS: set = field(default_factory=lambda: {
        'password', 'credit card', 'ssn', 'social security', 'bank account',
        'address', 'phone number', 'email address', 'identity theft', 'dox',
        'private information', 'confidential', 'secret'
    })
    
    DEFAULT_TOXIC_INDICATORS: set = field(default_factory=lambda: {
        'hate speech', 'inappropriate', 'violence', 'abuse', 'discrimination',
        'hate', 'violent', 'offensive', 'toxic', 'harmful'
    })

    def __post_init__(self):
        # Update threshold from config if provided
        if 'threshold' in self.config:
            self.threshold = self.config['threshold']
        self._validate_config()

    def _validate_config(self) -> None:
        use_defaults = self.config.get('use_defaults', True)
        provided_keywords = self.config.get('suspicious_keywords', set())
        if not isinstance(provided_keywords, set):
            try:
                provided_keywords = set(kw.lower() for kw in provided_keywords)
            except TypeError:
                provided_keywords = set()
        self.suspicious_keywords = set(self.DEFAULT_SUSPICIOUS_KEYWORDS) if use_defaults else set()
        self.suspicious_keywords.update(provided_keywords)
        provided_patterns = self.config.get('suspicious_patterns', [])
        if not isinstance(provided_patterns, list):
            provided_patterns = []
        default_patterns_src = list(self.DEFAULT_SUSPICIOUS_PATTERNS) if use_defaults else []
        all_patterns_src = default_patterns_src + provided_patterns
        self.suspicious_patterns = []
        for pattern_str in all_patterns_src:
            try:
                self.suspicious_patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error:
                pass
        provided_indicators = self.config.get('sensitive_request_indicators', set())
        if not isinstance(provided_indicators, set):
            try:
                provided_indicators = set(ind.lower() for ind in provided_indicators)
            except TypeError:
                provided_indicators = set()
        self.sensitive_request_indicators = set(self.DEFAULT_SENSITIVE_REQUEST_INDICATORS) if use_defaults else set()
        self.sensitive_request_indicators.update(provided_indicators)

    def update_config(self, config: Any) -> None:
        self.config.update(config)
        self._validate_config()
    
    def enable(self) -> None:
        """Enable the filter."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the filter."""
        self.enabled = False

    def add_suspicious_keyword(self, keyword: str) -> None:
        self.suspicious_keywords.add(keyword.lower())

    def add_suspicious_pattern(self, pattern: str) -> None:
        try:
            self.suspicious_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            pass

    def _check_input(self, text: str) -> tuple:
        try:
            normalized_text = ' '.join(text.split()).lower()
            
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                pattern = r'\b' + re.escape(keyword) + r'\b' if ' ' not in keyword else re.escape(keyword)
                if re.search(pattern, normalized_text, re.IGNORECASE):
                    return True, f"Potentially harmful content detected: suspicious keyword '{keyword}'"
            
            # Check for suspicious patterns
            for pattern_re in self.suspicious_patterns:
                match = pattern_re.search(text)
                if match:
                    matched_text = match.group(0)
                    return True, f"Potentially harmful content detected: suspicious pattern matched '{matched_text[:50]}...'"
            
            # Check for multiple instruction phrases (jailbreak attempts)
            instruction_phrases = ["ignore", "don't follow", "disregard", "bypass", "forget"]
            instruction_count = sum(1 for phrase in instruction_phrases if phrase in normalized_text)
            if instruction_count >= 2:
                return True, "Multiple contradictory instructions detected, potential jailbreak attempt"
            
            # Check for PII indicators
            for indicator in self.sensitive_request_indicators:
                pattern = r'\b' + re.escape(indicator) + r'\b' if ' ' not in indicator else re.escape(indicator)
                if re.search(pattern, normalized_text, re.IGNORECASE):
                    return True, f"PII content detected: sensitive indicator '{indicator}'"
            
            # Check for toxic content
            for toxic_indicator in self.DEFAULT_TOXIC_INDICATORS:
                pattern = r'\b' + re.escape(toxic_indicator) + r'\b' if ' ' not in toxic_indicator else re.escape(toxic_indicator)
                if re.search(pattern, normalized_text, re.IGNORECASE):
                    return True, f"Toxic content detected: harmful indicator '{toxic_indicator}'"
            
            # Check for email patterns
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if re.search(email_pattern, text):
                return True, "PII content detected: email address found"
            
            # Check for phone number patterns
            phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
            if re.search(phone_pattern, text):
                return True, "PII content detected: phone number found"
            
            return False, None
        except Exception as e:
            return True, f"Error during content analysis: {str(e)}"

    @performance_monitor('HeuristicFilter')
    @cached_component_call('HeuristicFilter')
    def filter(self, data: str) -> FilterResult:
        if not self.enabled:
            return FilterResult(is_safe=True, confidence=1.0, data=data)
        
        is_suspicious, reason = self._check_input(data)
        passed_filter = not is_suspicious
        
        # Calculate confidence based on suspicious indicators
        confidence = 0.9 if passed_filter else 0.8
        
        if is_suspicious:
            log_security_event(
                EventType.INJECTION_ATTEMPT,
                'HeuristicFilter',
                f'Suspicious content detected: {reason}',
                Severity.HIGH,
                details={'content_preview': data[:100]}
            )
        
        return FilterResult(
            is_safe=passed_filter,
            confidence=confidence,
            reason=reason,
            data=data
        )

    def process(self, data: str) -> FilterResult:
        return self.filter(data) 