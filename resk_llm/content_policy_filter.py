# resk_llm/content_policy_filter.py

import logging
import re
import json
from typing import Dict, List, Set, Any, Optional, Tuple, Union, TypedDict
from re import Pattern

# Import RESK-LLM core components and relevant implementations
from resk_llm.core.abc import FilterBase, SecurityComponent
from resk_llm.pattern_provider import FileSystemPatternProvider
from resk_llm.text_analysis import TextAnalyzer
from resk_llm.vector_db import VectorDatabase

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

class ContentPolicyFilter(FilterBase[str, FilterResult, ContentPolicyConfig]):
    """
    Filters content based on configurable policies including competitors, banned code,
    topics, substrings, and custom regex patterns.
    
    This filter loads patterns from a pattern provider (typically FileSystemPatternProvider)
    and checks input text against these patterns, returning a structured report of matches.
    """

    def __init__(self, 
                 config: Optional[ContentPolicyConfig] = None,
                 pattern_provider: Optional[FileSystemPatternProvider] = None):
        """
        Initialize the content policy filter.
        
        Args:
            config: Configuration dictionary which may contain:
                'config_path': Path to JSON configuration file
                'competitors': Dict of competitor info (names, products, domains)
                'banned_code': List of regex patterns for banned code
                'banned_topics': List of banned topic keywords
                'banned_substrings': List of exact string matches to filter
                'regex_patterns': Dict of named regex patterns
            pattern_provider: Provider for loading patterns (optional)
        """
        self.logger = logger
        
        # Initialize pattern collections
        self.competitors: Dict[str, List[str]] = {
            'names': [],
            'products': [],
            'domains': []
        }
        self.banned_code: List[str] = []
        self.banned_topics: List[str] = []
        self.banned_substrings: List[str] = []
        self.regex_patterns: Dict[str, str] = {}
        
        # Compiled regex patterns
        self.compiled_banned_code: List[Pattern] = []
        self.compiled_regex_patterns: Dict[str, Pattern] = {}
        
        # Set up pattern provider
        self.pattern_provider = pattern_provider or FileSystemPatternProvider()
        
        # Initialize with superclass (calls _validate_config)
        super().__init__(config)
    
    def _validate_config(self) -> None:
        """Validate configuration and load patterns."""
        if not isinstance(self.config, dict):
            self.config = {}
            
        # If a config path is provided, load from JSON file
        config_path = self.config.get('config_path')
        if config_path:
            try:
                # Load config from the specified JSON file path
                with open(config_path, 'r') as f:
                    loaded_config_from_file = json.load(f)
                
                if loaded_config_from_file and isinstance(loaded_config_from_file, dict):
                    # Update our config with loaded values, prioritizing file values
                    self.config.update(loaded_config_from_file)
                    self.logger.info(f"Loaded and updated config from {config_path}")
                else:
                    self.logger.warning(f"Config file {config_path} is empty or not a dictionary.")
                    
            except FileNotFoundError:
                 self.logger.error(f"Config file not found at {config_path}")
            except json.JSONDecodeError:
                self.logger.error(f"Error decoding JSON from config file {config_path}")
            except Exception as e:
                self.logger.error(f"Failed to load content policy config from {config_path}: {e}")
        
        # Load competitors from the (potentially updated) config
        competitor_config = self.config.get('competitors', {})
        if isinstance(competitor_config, dict):
            self.competitors = {
                'names': competitor_config.get('names', []),
                'products': competitor_config.get('products', []),
                'domains': competitor_config.get('domains', [])
            }
        
        # Load other pattern lists
        self.banned_code = self.config.get('banned_code', [])
        self.banned_topics = self.config.get('banned_topics', [])
        self.banned_substrings = self.config.get('banned_substrings', [])
        self.regex_patterns = self.config.get('regex_patterns', {})
        
        # Compile regex patterns
        self._compile_regex_patterns()
        
        self.logger.info(
            f"ContentPolicyFilter configured with {len(self.competitors['names'])} competitors, "
            f"{len(self.banned_code)} code patterns, {len(self.banned_topics)} topics, "
            f"{len(self.banned_substrings)} substrings, {len(self.regex_patterns)} regex patterns"
        )
    
    def _compile_regex_patterns(self) -> None:
        """Compile all regex patterns for efficient matching."""
        # Compile banned code regex
        self.compiled_banned_code = []
        for pattern in self.banned_code:
            try:
                self.compiled_banned_code.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.error(f"Invalid banned code regex '{pattern}': {e}")
        
        # Compile custom regex patterns
        self.compiled_regex_patterns = {}
        for name, pattern in self.regex_patterns.items():
            try:
                self.compiled_regex_patterns[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{name}': {e}")
    
    def update_config(self, config: ContentPolicyConfig) -> None:
        """Update filter configuration with new settings."""
        self.config.update(config)
        self._validate_config()
    
    def filter(self, data: str) -> FilterResult:
        """
        Filter text based on content policies and return detailed results.
        
        Args:
            data: The input text to check against content policies.
            
        Returns:
            Dictionary containing filter results:
            {
                'text': original_input_text,
                'filtered': bool,  # True if any policies were triggered
                'competitor_mentions': {
                    'names': [...],  # List of competitor names found
                    'products': [...],  # List of competitor products found
                    'domains': [...],  # List of competitor domains found
                },
                'banned_code_matches': [...],  # List of banned code patterns found
                'banned_topic_matches': [...],  # List of banned topics found
                'banned_substring_matches': [...],  # List of banned substrings found
                'regex_matches': {  # Dict of named regex pattern matches
                    'pattern_name1': [...],
                    'pattern_name2': [...]
                },
                'reasons': [...],  # List of reasons why content was filtered
            }
        """
        if not isinstance(data, str):
            self.logger.warning("ContentPolicyFilter received non-string input")
            # Return type must match FilterResult
            return FilterResult(
                text=str(data),
                filtered=False,
                competitor_mentions={'names': [], 'products': [], 'domains': []},
                banned_code_matches=[],
                banned_topic_matches=[],
                banned_substring_matches=[],
                regex_matches={},
                reasons=[]
            )
        
        result: FilterResult = FilterResult(
            text=data,
            filtered=False,
            competitor_mentions={
                'names': self._check_competitors(data, 'names'),
                'products': self._check_competitors(data, 'products'),
                'domains': self._check_competitors(data, 'domains')
            },
            banned_code_matches=self._check_banned_code(data),
            banned_topic_matches=self._check_banned_topics(data),
            banned_substring_matches=self._check_banned_substrings(data),
            regex_matches=self._check_regex_patterns(data),
            reasons=[]
        )
        
        # Aggregate results and determine if content should be filtered
        reasons = []
        
        # Check competitor mentions
        comp_mentions: Dict[str, List[str]] = result['competitor_mentions']
        for category, mentions in comp_mentions.items():
            if mentions:
                reasons.append(f"Contains competitor {category}: {', '.join(mentions)}")
        
        # Check banned code
        banned_code: List[str] = result['banned_code_matches']
        if banned_code:
            reasons.append(f"Contains banned code patterns: {', '.join(banned_code)}")
        
        # Check banned topics
        banned_topics: List[str] = result['banned_topic_matches']
        if banned_topics:
            reasons.append(f"Contains banned topics: {', '.join(banned_topics)}")
        
        # Check banned substrings
        banned_substrings: List[str] = result['banned_substring_matches']
        if banned_substrings:
            reasons.append(f"Contains banned substrings: {', '.join(banned_substrings)}")
        
        # Check regex patterns
        regex_matches_dict: Dict[str, List[str]] = result['regex_matches']
        for pattern_name, matches in regex_matches_dict.items():
            if matches:
                # Ensure matches are strings before joining
                str_matches = [str(m) for m in matches[:3]]
                reasons.append(f"Matches regex pattern '{pattern_name}': {', '.join(str_matches)}")
        
        # Set filtered flag and reasons
        result['filtered'] = len(reasons) > 0
        result['reasons'] = reasons
        
        return result
    
    def _check_competitors(self, text: str, category: str) -> List[str]:
        """Check text for mentions of competitors in the specified category."""
        matches = []
        for competitor in self.competitors.get(category, []):
            if competitor.lower() in text.lower():
                matches.append(competitor)
        return matches
    
    def _check_banned_code(self, text: str) -> List[str]:
        """Check text for banned code patterns."""
        matches = []
        for pattern in self.compiled_banned_code:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return matches
    
    def _check_banned_topics(self, text: str) -> List[str]:
        """Check text for banned topics."""
        matches = []
        text_lower = text.lower()
        for topic in self.banned_topics:
            if topic.lower() in text_lower:
                matches.append(topic)
        return matches
    
    def _check_banned_substrings(self, text: str) -> List[str]:
        """Check text for banned substrings."""
        matches = []
        for substring in self.banned_substrings:
            if substring in text:
                matches.append(substring)
        return matches
    
    def _check_regex_patterns(self, text: str) -> Dict[str, List[str]]:
        """Check text against custom regex patterns."""
        results = {}
        for name, pattern in self.compiled_regex_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Flatten matches if they're tuples (from capture groups)
                flat_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        # Join non-empty capture groups
                        flat_match = ' '.join([g for g in match if g])
                        if flat_match:
                            flat_matches.append(flat_match)
                    else:
                        flat_matches.append(match)
                
                if flat_matches:
                    results[name] = flat_matches
        
        return results 