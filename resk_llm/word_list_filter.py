# resk_llm/word_list_filter.py
# (Replaces tokenizer_protection.py functionality)

import logging
import re # Import re for word boundary checks
from typing import Dict, List, Optional, Set, Tuple, Any

# Import RESK-LLM core components
from resk_llm.core.abc import FilterBase, PatternProviderBase # Import PatternProviderBase
# Explicitly import the concrete provider we expect for now
from resk_llm.pattern_provider import FileSystemPatternProvider

# Define config type
WordListFilterConfig = Dict[str, Any]

# Define filter output type
# (passed_filter, reason, original_text) - similar to HeuristicFilter
FilterResult = Tuple[bool, Optional[str], str]

logger = logging.getLogger(__name__)

class WordListFilter(FilterBase[str, FilterResult, WordListFilterConfig]):
    """
    A filter that checks input text against lists of prohibited keywords.
    It retrieves these keywords from a configured PatternProvider.
    """

    def __init__(self, config: Optional[WordListFilterConfig] = None):
        """
        Initializes the WordListFilter.

        Args:
            config: Optional configuration dictionary. Expected keys:
                'pattern_provider': An instance of a PatternProviderBase (e.g., FileSystemPatternProvider). Required.
                'keyword_sources': Optional list of source names (categories) to fetch keywords from the provider.
                                   If None, uses all available keyword sources from the provider.
                'case_sensitive': Boolean (default False) for keyword matching.
        """
        self.pattern_provider: Optional[FileSystemPatternProvider] = None
        self.prohibited_words: Set[str] = set()
        self.keyword_sources: Optional[List[str]] = None
        self.case_sensitive: bool = False
        self.logger = logger
        super().__init__(config) # Calls _validate_config

    def _validate_config(self) -> None:
        """Validate configuration and load keywords from the provider."""
        if not isinstance(self.config, dict):
            self.config = {}

        provider = self.config.get('pattern_provider')
        # Check if it's an instance of the ABC
        if not isinstance(provider, FileSystemPatternProvider):
            self.logger.error("WordListFilter requires a valid 'pattern_provider' (instance of FileSystemPatternProvider) in its config.")
            # Set provider to None, filter will be ineffective but won't crash
            self.pattern_provider = None
            self.prohibited_words = set()
            return # Cannot proceed without a provider
        else:
            self.pattern_provider = provider

        self.keyword_sources = self.config.get('keyword_sources')
        if self.keyword_sources is not None and not isinstance(self.keyword_sources, list):
             self.logger.warning("'keyword_sources' should be a list of strings. Ignoring.")
             self.keyword_sources = None

        self.case_sensitive = self.config.get('case_sensitive', False)

        # Load keywords
        self._load_keywords()

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

    def filter(self, data: str) -> FilterResult:
        """
        Apply the word list filter to the input text.

        Args:
            data: The input string to be filtered.

        Returns:
            A tuple (passed_filter, reason, filtered_text) where:
            - passed_filter (bool): True if the text passed (no prohibited words found), False otherwise.
            - reason (Optional[str]): Explanation ("Prohibited word detected: 'word'") if failed, None otherwise.
            - filtered_text (str): The original input text. This filter doesn't modify text.
        """
        if not isinstance(data, str):
            self.logger.debug("WordListFilter received non-string data, passing through.")
            return True, None, data

        if not self.prohibited_words:
            # Pass if no words loaded (e.g., provider error or empty lists)
            self.logger.debug("WordListFilter has no prohibited words loaded, passing through.")
            return True, None, data

        # Simple substring check might be too broad (e.g., 'ass' in 'class').
        # Use word boundary checks for more accuracy.
        for word in self.prohibited_words:
            # Escape potential regex characters in the word itself
            escaped_word = re.escape(word)
            # Compile pattern with word boundaries
            try:
                 # Case sensitivity handled by flags
                 flags = 0 if self.case_sensitive else re.IGNORECASE
                 pattern = re.compile(r'\b' + escaped_word + r'\b', flags)
                 match = pattern.search(data) # Search original data
                 if match:
                      matched_text = match.group(0) # The actual matched word from input
                      self.logger.warning(f"WordListFilter triggered: Prohibited word '{matched_text}' (pattern: {word}) found.")
                      return False, f"Prohibited word detected: '{matched_text}'", data
            except re.error as e:
                 # This should ideally not happen if words are simple strings, but handle defensively
                 self.logger.error(f"Regex error checking word '{word}': {e}")
                 continue # Skip this word if problematic

        # Passed all checks
        return True, None, data 