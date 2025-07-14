import re
import logging
from typing import List, Dict, Set, Tuple, Any, Optional, Union

# Import the base class
from resk_llm.core.abc import FilterBase
from resk_llm.core.cache import cached_component_call, get_cache
from resk_llm.core.monitoring import performance_monitor, log_security_event, EventType, Severity

# Define a specific config type for clarity, though it's simple for now
HeuristicFilterConfig = Dict[str, Union[List[str], Set[str]]]

# Define the output type for the filter method
FilterResult = Tuple[bool, Optional[str], str] # (passed_filter, reason, output_text)

class HeuristicFilter(FilterBase[str, FilterResult, HeuristicFilterConfig]):
    """
    A filter based on heuristics to identify and block potentially malicious user inputs.
    This filter checks against predefined lists of suspicious keywords and regex patterns
    often associated with prompt injection, jailbreaking, or requests for sensitive information.
    It's typically applied early in the processing chain to quickly reject obvious attacks.

    Inherits from FilterBase and expects string input and returns a tuple indicating
    whether the input passed, a reason if it failed, and the original text.
    """

    DEFAULT_SUSPICIOUS_KEYWORDS: Set[str] = {
        'ignore previous instructions', 'ignore all instructions', 'bypass', 'jailbreak',
        'ignore context', 'disregard', 'system prompt', 'new prompt', 'forget',
        'ignore restrictions', 'ignore guidelines', 'ignore rules', 'dan', 'do anything now',
        'now you are', 'you are now', 'you will now', 'in this role', 'overriding previous',
        'no ethical concerns', 'no moral limitations', 'secret mode'
    }

    DEFAULT_SUSPICIOUS_PATTERNS: List[str] = [
        r'ignore (?:previous|all|any).*?instructions',
        r'forget (?:previous|all|any).*?instructions',
        r'do not (?:follow|obey|respect).*?rules',
        r'you (?:are|will be) (?:now|from now on).*?',
        r'pretend (?:to be|you are).*?',
        r'act as if.*?',
        r'base64:[a-zA-Z0-9+/=]{20,}',
        r'i\s*g\s*n\s*o\s*r\s*e',
        r'b\s*y\s*p\s*a\s*s\s*s',
        r'<\|.*?\|>',  # Attempts to use model tokens
        r'\[system\]|\[user\]|\[assistant\]', # Role marker insertions
        r'answer in two different ways',
        r'first.*?then ignore',
    ]

    DEFAULT_SENSITIVE_REQUEST_INDICATORS: Set[str] = {
        'password', 'credit card', 'ssn', 'social security', 'bank account',
        'address', 'phone number', 'email address', 'identity theft', 'dox',
        'private information', 'confidential', 'secret'
    }

    def __init__(self, config: Optional[HeuristicFilterConfig] = None):
        """
        Initializes the HeuristicFilter.

        Args:
            config: Optional configuration dictionary. Can contain:
                'suspicious_keywords': A set of keywords to add/replace the defaults.
                'suspicious_patterns': A list of regex patterns to add/replace the defaults.
                'sensitive_request_indicators': A set of indicators to add/replace the defaults.
                'use_defaults': Boolean (default True) to use default lists. If False,
                                only provided lists in config are used.
        """
        self.logger = logging.getLogger(__name__)
        super().__init__(config) # Calls _validate_config internally

    def _validate_config(self) -> None:
        """Validate the configuration and load patterns."""
        use_defaults = self.config.get('use_defaults', True)

        # Load suspicious keywords
        provided_keywords = self.config.get('suspicious_keywords', set())
        if not isinstance(provided_keywords, set):
             # Attempt conversion if list provided
             try:
                 provided_keywords = set(kw.lower() for kw in provided_keywords)
             except TypeError:
                 self.logger.warning("Invalid 'suspicious_keywords' in config, expected Set[str] or List[str]. Using defaults.")
                 provided_keywords = set()

        self.suspicious_keywords: Set[str] = self.DEFAULT_SUSPICIOUS_KEYWORDS if use_defaults else set()
        self.suspicious_keywords.update(provided_keywords)

        # Load suspicious patterns
        provided_patterns = self.config.get('suspicious_patterns', [])
        if not isinstance(provided_patterns, list):
            self.logger.warning("Invalid 'suspicious_patterns' in config, expected List[str]. Using defaults.")
            provided_patterns = []

        default_patterns_src = self.DEFAULT_SUSPICIOUS_PATTERNS if use_defaults else []
        all_patterns_src = default_patterns_src + provided_patterns
        self.suspicious_patterns: List[re.Pattern] = []
        for pattern_str in all_patterns_src:
             try:
                 self.suspicious_patterns.append(re.compile(pattern_str, re.IGNORECASE))
             except re.error as e:
                 self.logger.error(f"Invalid regex pattern '{pattern_str}' skipped: {e}")

        # Load sensitive request indicators
        provided_indicators = self.config.get('sensitive_request_indicators', set())
        if not isinstance(provided_indicators, set):
             try:
                 provided_indicators = set(ind.lower() for ind in provided_indicators)
             except TypeError:
                 self.logger.warning("Invalid 'sensitive_request_indicators' in config, expected Set[str] or List[str]. Using defaults.")
                 provided_indicators = set()

        self.sensitive_request_indicators: Set[str] = self.DEFAULT_SENSITIVE_REQUEST_INDICATORS if use_defaults else set()
        self.sensitive_request_indicators.update(provided_indicators)


    def update_config(self, config: HeuristicFilterConfig) -> None:
        """
        Update the filter's configuration and reload patterns.

        Args:
            config: The new configuration dictionary.
        """
        self.config.update(config)
        self._validate_config() # Reload patterns/keywords with updated config

    def add_suspicious_keyword(self, keyword: str) -> None:
        """Add a new suspicious keyword to the filter's runtime set."""
        self.suspicious_keywords.add(keyword.lower())

    def add_suspicious_pattern(self, pattern: str) -> None:
        """Add a new suspicious regex pattern to the filter's runtime list."""
        try:
            self.suspicious_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as e:
            self.logger.error(f"Failed to add invalid regex pattern '{pattern}': {e}")

    # --- Core Filter Logic ---

    def _check_input(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Internal method to check if the input text contains suspicious content.

        Args:
            text: The input text to check.

        Returns:
            A tuple (is_suspicious, reason).
        """
        try:
            # Normalize text
            normalized_text = ' '.join(text.split()).lower()

            # Check keywords
            for keyword in self.suspicious_keywords:
                # Use word boundaries for keywords to avoid partial matches within words,
                # unless the keyword itself contains spaces.
                pattern = r'\b' + re.escape(keyword) + r'\b' if ' ' not in keyword else re.escape(keyword)
                if re.search(pattern, normalized_text, re.IGNORECASE):
                    self.logger.warning(f"Heuristic filter triggered: suspicious keyword '{keyword}'")
                    return True, f"Potentially harmful content detected: suspicious keyword '{keyword}'"

            # Check patterns
            for pattern_re in self.suspicious_patterns:
                match = pattern_re.search(text) # Search original text for case sensitivity if needed by pattern
                if match:
                    matched_text = match.group(0)
                    self.logger.warning(f"Heuristic filter triggered: suspicious pattern '{pattern_re.pattern}' matched '{matched_text}'")
                    return True, f"Potentially harmful content detected: suspicious pattern matched '{matched_text[:50]}...'" # Limit length

            # Check for contradictory instructions
            instruction_phrases = ["ignore", "don't follow", "disregard", "bypass", "forget"]
            instruction_count = sum(1 for phrase in instruction_phrases if phrase in normalized_text)
            if instruction_count >= 2:
                self.logger.warning("Heuristic filter triggered: Multiple contradictory instructions detected")
                return True, "Multiple contradictory instructions detected, potential jailbreak attempt"

            # Check for sensitive indicators (log only, doesn't fail filter by default)
            # This behavior could be made configurable
            for indicator in self.sensitive_request_indicators:
                 pattern = r'\b' + re.escape(indicator) + r'\b' if ' ' not in indicator else re.escape(indicator)
                 if re.search(pattern, normalized_text, re.IGNORECASE):
                    self.logger.info(f"Heuristic filter: Sensitive request indicator detected: {indicator}")
                    # By default, this check doesn't cause the filter to fail.
                    # Add `return True, "..."` here if blocking is desired.

            # Passed all checks
            return False, None

        except Exception as e:
            self.logger.exception(f"Error during heuristic filtering: {e}", exc_info=e)
            # Fail safe: if error occurs, block the input
            return True, f"Error during content analysis: {str(e)}"

    @performance_monitor('HeuristicFilter')
    @cached_component_call('HeuristicFilter')
    def filter(self, data: str) -> FilterResult:
        """
        Apply the heuristic filter to the input text.

        Args:
            data: The input string to be filtered.

        Returns:
            A tuple (passed_filter, reason, filtered_text) where:
            - passed_filter (bool): True if the text passed the filter, False otherwise.
            - reason (Optional[str]): Explanation if the filter failed, None otherwise.
            - filtered_text (str): The original input text. This filter doesn't modify text.
        """
        is_suspicious, reason = self._check_input(data)
        passed_filter = not is_suspicious
        
        # Log security events
        if is_suspicious:
            log_security_event(
                EventType.INJECTION_ATTEMPT,
                'HeuristicFilter',
                f'Suspicious content detected: {reason}',
                Severity.HIGH,
                details={'content_preview': data[:100]}
            )
        
        return passed_filter, reason, data # Return original text 