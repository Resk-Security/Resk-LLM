# resk_llm/word_list_filter.py
# (Replaces tokenizer_protection.py functionality)

import logging
import re # Import re for word boundary checks
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field

# Import RESK-LLM core components
from resk_llm.core.abc import FilterBase, FilterResult
# Explicitly import the concrete provider we expect for now
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider

# Define config type
WordListFilterConfig = Dict[str, Any]

logger = logging.getLogger(__name__)

class RESK_WordListFilter(FilterBase[str, FilterResult, WordListFilterConfig]):
    """
    A filter that checks input text against lists of prohibited keywords.
    It retrieves these keywords from a configured PatternProvider.
    """

    def __init__(self, config: Optional[WordListFilterConfig] = None, word_lists: Optional[Dict[str, List[str]]] = None, case_sensitive: bool = False):
        """
        Initializes the WordListFilter.

        Args:
            config: Optional configuration dictionary. Expected keys:
                'pattern_provider': An instance of a PatternProviderBase (e.g., FileSystemPatternProvider). Required.
                'keyword_sources': Optional list of source names (categories) to fetch keywords from the provider.
                                   If None, uses all available keyword sources from the provider.
                'case_sensitive': Boolean (default False) for keyword matching.
                'word_lists': Optional dictionary of word lists to use directly.
            word_lists: Direct word lists parameter (for backward compatibility)
            case_sensitive: Direct case_sensitive parameter (for backward compatibility)
        """
        self.pattern_provider: Optional[FileSystemPatternProvider] = None
        self.prohibited_words: Set[str] = set()
        self.keyword_sources: Optional[List[str]] = None
        self.case_sensitive: bool = case_sensitive
        self.enabled: bool = True  # Add enabled attribute
        self.word_lists: Dict[str, List[str]] = {}  # Add word_lists attribute
        self.logger = logger
        
        # Handle word_lists parameter (both from config and direct parameter)
        if word_lists:
            self.word_lists = word_lists
            # Convert word lists to prohibited words
            for word_list in self.word_lists.values():
                if isinstance(word_list, list):
                    self.prohibited_words.update(word_list)
        elif config and 'word_lists' in config:
            self.word_lists = config['word_lists']
            # Convert word lists to prohibited words
            for word_list in self.word_lists.values():
                if isinstance(word_list, list):
                    self.prohibited_words.update(word_list)
        
        # Handle case_sensitive parameter
        if config and 'case_sensitive' in config:
            self.case_sensitive = config['case_sensitive']
        
        super().__init__(config) # Calls _validate_config

    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Note: Pattern provider is optional for backward compatibility.
        """
        if not isinstance(self.config, dict):
            self.config = {}
        
        # Initialize prohibited words and patterns
        self.prohibited_words = set()
        self.prohibited_patterns = []
        
        # Handle word_lists parameter (both from config and direct parameter)
        if hasattr(self, 'word_lists') and self.word_lists:
            # Convert word lists to prohibited words
            for word_list in self.word_lists.values():
                if isinstance(word_list, list):
                    self.prohibited_words.update(word_list)
        elif self.config and 'word_lists' in self.config:
            self.word_lists = self.config['word_lists']
            # Convert word lists to prohibited words
            for word_list in self.word_lists.values():
                if isinstance(word_list, list):
                    self.prohibited_words.update(word_list)
        
        # Handle pattern provider if available
        if self.config and 'pattern_provider' in self.config:
            provider = self.config['pattern_provider']
            if isinstance(provider, FileSystemPatternProvider):
                self.pattern_provider = provider
                # Load patterns and words from provider
                self.prohibited_patterns = [re.compile(p, re.IGNORECASE) for p in self.pattern_provider.get_patterns(category='prohibited_patterns')]
                additional_words = set(self.pattern_provider.get_keywords(sources=['prohibited_words']))
                self.prohibited_words.update(additional_words)
            else:
                self.logger.warning("Pattern provider is not a FileSystemPatternProvider instance")
        else:
            # Fallback: load from config (previous behavior)
            patterns = self.config.get('prohibited_patterns', [])
            if isinstance(patterns, list):
                for pattern in patterns:
                    try:
                        self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
                    except re.error:
                        pass
            
            words = self.config.get('prohibited_words', [])
            if isinstance(words, list):
                self.prohibited_words.update(words)
        
        # Load keyword sources if specified
        if self.config and 'keyword_sources' in self.config:
            self.keyword_sources = self.config['keyword_sources']
            if self.pattern_provider and self.keyword_sources:
                additional_words = set(self.pattern_provider.get_keywords(sources=self.keyword_sources))
                self.prohibited_words.update(additional_words)

    def _load_keywords(self) -> None:
        """Load (or reload) keywords from the configured pattern provider."""
        if not self.pattern_provider:
             self.prohibited_words = set()
             self.logger.warning("WordListFilter cannot load keywords: pattern_provider is not configured.")
             return

        try:
             # Use the get_keywords convenience method
             self.prohibited_words = self.pattern_provider.get_keywords(sources=self.keyword_sources)
             # Case sensitivity is handled during matching, store original case from provider
             # if self.case_sensitive:
             #    pass # Keep original case
             # else:
             #    # Store lowercase versions for case-insensitive matching - This is done during check now
             #    self.prohibited_words = {word.lower() for word in self.prohibited_words}
             self.logger.info(f"WordListFilter loaded {len(self.prohibited_words)} keywords "
                              f"from sources: {self.keyword_sources or 'all'}.")
        except Exception as e:
             self.logger.error(f"Error loading keywords from pattern provider: {e}", exc_info=True)
             self.prohibited_words = set() # Clear words on error

    def update_config(self, config: WordListFilterConfig) -> None:
        """Update filter configuration and reload keywords."""
        self.config.update(config)
        self._validate_config() # Re-validates and reloads keywords
    
    def enable(self) -> None:
        """Enable the filter."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the filter."""
        self.enabled = False
    
    def add_words(self, category: str, words: Union[str, List[str]]) -> None:
        """
        Add words to the filter.
        
        Args:
            category: Category of words (default: "prohibited")
            words: Word or list of words to add
        """
        if isinstance(words, str):
            self.logger.warning("add_words expects a list of strings, got string. Treating as single word.")
            self.prohibited_words.add(words)
        elif isinstance(words, list):
            self.prohibited_words.update(words)
        else:
            self.logger.warning("add_words expects a list of strings")
        
        # Update word_lists if it exists
        if hasattr(self, 'word_lists') and isinstance(self.word_lists, dict):
            if category not in self.word_lists:
                self.word_lists[category] = []
            if isinstance(words, str):
                self.word_lists[category].append(words)
            elif isinstance(words, list):
                self.word_lists[category].extend(words)
    
    def remove_words(self, category: str, words: List[str]) -> None:
        """
        Remove words from the filter.
        
        Args:
            category: Category of words (default: "prohibited")
            words: List of words to remove
        """
        if isinstance(words, list):
            for word in words:
                self.prohibited_words.discard(word)
        else:
            self.logger.warning("remove_words expects a list of strings")
        
        # Update word_lists if it exists
        if hasattr(self, 'word_lists') and isinstance(self.word_lists, dict):
            if category in self.word_lists and isinstance(self.word_lists[category], list):
                for word in words:
                    if word in self.word_lists[category]:
                        self.word_lists[category].remove(word)

    def filter(self, data: str) -> FilterResult:
        """
        Filter text against prohibited words.
        
        Args:
            data: Text to filter
            
        Returns:
            FilterResult with filtering results
        """
        if not self.enabled:
            return FilterResult(is_safe=True, confidence=1.0, violations=[], matched_words=[], data=data)
        
        violations = []
        found_words = []
        
        # Check against prohibited words
        for word in self.prohibited_words:
            if self.case_sensitive:
                if word in data:
                    found_words.append(word)
            else:
                # Case insensitive search - check both original and lowercase versions
                if word.lower() in data.lower():
                    # Find the actual matched word in the original text
                    import re
                    pattern = re.compile(re.escape(word), re.IGNORECASE)
                    matches = pattern.findall(data)
                    found_words.extend(matches)
        
        if found_words:
            violations = [f"Prohibited word found: {word}" for word in found_words]
        
        is_safe = len(violations) == 0
        confidence = 0.9 if is_safe else 0.6
        
        return FilterResult(
            is_safe=is_safe,
            confidence=confidence,
            reason="Prohibited words detected" if violations else None,
            violations=violations,
            matched_words=found_words,
            data=data
        )
    
    def process(self, data: str) -> FilterResult:
        return self.filter(data)

    def check_input(self, text: str) -> Optional[str]:
        """
        Check input text for forbidden words.
        
        Args:
            text: Text to check
            
        Returns:
            Warning message if forbidden words are found, None otherwise
        """
        passed, reason, _ = self.filter(text)
        return reason if not passed else None 