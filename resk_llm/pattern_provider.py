"""
Pattern Provider module for the RESK LLM security library.

This module provides access to security patterns (regex, keywords) loaded from JSON files
stored in specified directories. It can also load built-in default patterns for scanning 
inputs and outputs for potentially malicious content.
"""

import re
import json
import os
import logging
from typing import Dict, List, Any, Tuple, Set, Optional, Union, Pattern, Mapping, Sequence, MutableSequence, cast, TypedDict
from pathlib import Path

# Import RESK-LLM core components
from resk_llm.core.abc import SecurityComponent, PatternProviderBase

# Import default patterns/lists
try:
    from resk_llm.filtering_patterns.prohibited_words import RESK_WORDS_LIST
    from resk_llm.filtering_patterns.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG
    from resk_llm.filtering_patterns.prohibited_patterns_fr import RESK_PROHIBITED_PATTERNS_FR
    DEFAULTS_AVAILABLE = True
except ImportError:
    # Initialize as empty list to match expected type
    RESK_WORDS_LIST = list() # type: ignore[assignment] 
    # Initialize as empty lists
    RESK_PROHIBITED_PATTERNS_ENG = list() # type: ignore[assignment]
    RESK_PROHIBITED_PATTERNS_FR = list() # type: ignore[assignment]
    DEFAULTS_AVAILABLE = False
    logging.warning("Could not import default pattern lists from resk_llm.filtering_patterns.")

# Setup logger for this module
logger = logging.getLogger(__name__)

# Type definitions
PatternData = Dict[str, Any]  # Type for individual pattern entries
CategoryPatterns = Dict[str, List[PatternData]]  # Category -> List of patterns
CompiledPatternData = Dict[str, Any]  # Includes compiled regex object
CompiledCategoryPatterns = Dict[str, List[CompiledPatternData]]  # Category -> List of compiled patterns
# ProviderConfig = Dict[str, Any]  # Config for the provider - Replace with TypedDict

# Define the structure for pattern provider configuration
class PatternProviderConfig(TypedDict, total=False):
    patterns_base_dir: str
    categories_to_load: List[str]
    load_defaults: bool

# Ignore type-var error for TypedDict compatibility
class FileSystemPatternProvider(PatternProviderBase[PatternProviderConfig]): # type: ignore[type-var]
    """
    Provides access to security patterns (regex, keywords) loaded from JSON files
    stored in specified directories. It can also load built-in default patterns.

    Implements the PatternProviderBase ABC.
    """

    DEFAULT_PATTERNS_CONFIG = {
        "keywords": {
            "default_words": RESK_WORDS_LIST,  # Built-in list
        },
        "regex": {
            "default_regex_en": list(RESK_PROHIBITED_PATTERNS_ENG),  # Convert Set to List
            "default_regex_fr": list(RESK_PROHIBITED_PATTERNS_FR),  # Convert Set to List
        }
    }

    def __init__(self, config: Optional[PatternProviderConfig] = None):
        """
        Initialize the pattern provider.

        Args:
            config: Configuration dictionary. Expected keys:
                'patterns_base_dir': Path to the directory containing pattern category subdirectories.
                'categories_to_load': Optional list of specific category names to load.
                'load_defaults': Boolean (default True) to load built-in default patterns.
        """
        # Initialize logger FIRST
        self.logger = logger

        # Store raw patterns (keywords as sets, regex as strings)
        self.patterns: Dict[str, Dict[str, Union[Set[str], List[str]]]] = {"keywords": {}, "regex": {}}
        # Store compiled regex patterns
        self.compiled_regex: Dict[str, Dict[str, List[CompiledPatternData]]] = {"regex": {}}
        # Metadata about categories/sources
        self.sources: Dict[str, Dict[str, Any]] = {}
        self.validation_errors: List[Dict[str, Any]] = []
        
        # Initialize the base class with the provided config last
        # Cast empty dict if config is None to satisfy TypedDict requirement
        if config is None:
            config = cast(PatternProviderConfig, {})
        super().__init__(config)

    def _validate_config(self) -> None:
        """
        Validate configuration and load patterns.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")

        self.patterns_base_dir: Optional[str] = self.config.get('patterns_base_dir')
        self.categories_to_load: Optional[List[str]] = self.config.get('categories_to_load')
        self.load_defaults: bool = self.config.get('load_defaults', True)

        # Clear existing patterns before loading
        self.patterns = {"keywords": {}, "regex": {}}
        self.compiled_regex = {"regex": {}}
        self.sources = {}
        self.validation_errors = []

        if self.load_defaults and DEFAULTS_AVAILABLE:
            self._load_default_patterns()

        if self.patterns_base_dir:
            if not os.path.isdir(self.patterns_base_dir):
                self.logger.warning(f"Pattern directory not found: {self.patterns_base_dir}. Skipping file loading.")
            else:
                self._load_patterns_from_directory(self.patterns_base_dir, self.categories_to_load)

        self.logger.info(f"Pattern provider initialized. Loaded sources: {list(self.sources.keys())}")

    def update_config(self, config: PatternProviderConfig) -> None:
        """
        Update the configuration and reload patterns.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()  # Reload all patterns

    def _load_default_patterns(self) -> None:
        """
        Load built-in default word lists and regex patterns.
        """
        self.logger.debug("Loading default RESK-LLM patterns...")
        default_source_name = "resk_defaults"
        self.sources[default_source_name] = {"type": "builtin", "description": "Default RESK-LLM patterns"}

        # Load default keywords
        kw_conf = self.DEFAULT_PATTERNS_CONFIG.get("keywords", {})
        if default_source_name not in self.patterns["keywords"]:
            self.patterns["keywords"][default_source_name] = set()
        for name, word_list in kw_conf.items():
            # Fix: Check if word_list is a Set or List
            if isinstance(word_list, (set, list)):
                # Cast to Set[str] to satisfy mypy
                kw_set = cast(Set[str], self.patterns["keywords"][default_source_name])
                # Ignore potential mypy confusion with Union
                kw_set.update(w.lower() for w in word_list if isinstance(w, str)) # type: ignore[union-attr]
            else:
                self.logger.warning(f"Invalid default keyword list format for '{name}'. Expected set or list.")

        # Load default regex
        regex_conf = self.DEFAULT_PATTERNS_CONFIG.get("regex", {})
        if default_source_name not in self.patterns["regex"]:
            self.patterns["regex"][default_source_name] = []
            self.compiled_regex["regex"][default_source_name] = []
        for name, pattern_list in regex_conf.items():
            if isinstance(pattern_list, list):
                for pattern_str in pattern_list:
                    if isinstance(pattern_str, str):
                        # Store raw pattern string
                        # Cast to List[str] to satisfy mypy
                        regex_list = cast(List[str], self.patterns["regex"][default_source_name])
                        # Ignore potential mypy confusion with Union
                        regex_list.append(pattern_str) # type: ignore[union-attr]
                        # Compile and store with basic metadata
                        try:
                            compiled = re.compile(pattern_str, re.IGNORECASE)
                            # Store compiled pattern with metadata
                            compiled_entry = {
                                'pattern': pattern_str,  # Keep original string
                                'compiled': compiled,
                                'source': default_source_name,
                                'category': name,  # Use the sub-key as category hint
                                'flags': ['IGNORECASE']  # Record the flags used
                            }
                            self.compiled_regex["regex"][default_source_name].append(compiled_entry)
                        except re.error as e:
                            error_info = {
                                'pattern': pattern_str, 'source': default_source_name, 'category': name,
                                'error': f"Compilation error: {e}"}
                            self.validation_errors.append(error_info)
                            self.logger.error(f"Error compiling default regex pattern '{pattern_str}': {e}")
                    else:
                        self.logger.warning(f"Non-string item found in default regex list '{name}'.")
            else:
                self.logger.warning(f"Invalid default regex list format for '{name}'. Expected list.")
        self.logger.debug("Default patterns loaded.")

    def _load_patterns_from_directory(self, base_dir: str, categories: Optional[List[str]] = None) -> None:
        """
        Load patterns from category subdirectories containing JSON files.
        
        Args:
            base_dir: Base directory containing category subdirectories
            categories: Optional list of specific category subdirectories to load
        """
        self.logger.debug(f"Loading patterns from directory: {base_dir}")
        try:
            subdirs = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
            categories_to_process = categories if categories is not None else subdirs

            for category_name in categories_to_process:
                if category_name not in subdirs:
                    self.logger.warning(f"Specified category directory '{category_name}' not found in {base_dir}.")
                    continue

                category_dir = os.path.join(base_dir, category_name)
                json_files = [f for f in os.listdir(category_dir) if f.lower().endswith('.json')]

                if not json_files:
                    self.logger.debug(f"No JSON files found in category directory: {category_dir}")
                    continue

                # Load all json files in the category dir into that category
                for file_name in json_files:
                    file_path = os.path.join(category_dir, file_name)
                    source_name = f"{category_name}_{Path(file_name).stem}"  # Unique source name
                    self._load_patterns_from_file(file_path, source_name, category_name)

        except Exception as e:
            self.logger.error(f"Error scanning pattern directory {base_dir}: {e}", exc_info=True)

    def _load_patterns_from_file(self, file_path: str, source_name: str, category_hint: Optional[str] = None) -> None:
        """
        Load patterns from a single JSON file.
        
        Args:
            file_path: Path to the JSON file
            source_name: Unique identifier for this pattern source
            category_hint: Optional category to associate with patterns from this file
        """
        self.logger.debug(f"Loading patterns from file: {file_path} into source '{source_name}'")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, dict):
                self.logger.error(f"Invalid format in {file_path}: Expected a JSON object (dict).")
                return

            meta = data.get("metadata", {})
            description = meta.get("description", f"Patterns from {source_name}")
            pattern_type = meta.get("type", "regex").lower()  # Default to regex if type not specified

            self.sources[source_name] = {
                "type": "file", 
                "path": file_path, 
                "description": description, 
                "pattern_type": pattern_type
            }

            if pattern_type == "keywords":
                self._load_keywords_from_data(data.get("keywords", []), source_name)
            elif pattern_type == "regex":
                self._load_regex_from_data(data.get("patterns", []), source_name)
            else:
                self.logger.error(f"Unsupported pattern type '{pattern_type}' in {file_path}")
                self.validation_errors.append({
                    'source': source_name, 
                    'error': f"Unsupported pattern type '{pattern_type}'"
                })

        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON from {file_path}: {e}")
            self.validation_errors.append({
                'source': source_name, 
                'error': f"JSON Decode Error: {e}"
            })
        except Exception as e:
            self.logger.error(f"Error loading patterns from {file_path}: {e}", exc_info=True)
            self.validation_errors.append({
                'source': source_name, 
                'error': f"General Load Error: {e}"
            })

    def _load_keywords_from_data(self, keyword_list: Any, source_name: str) -> None:
        """
        Loads a list of keywords into the patterns structure.
        
        Args:
            keyword_list: List of keywords to load
            source_name: Source identifier for these keywords
        """
        if not isinstance(keyword_list, list):
            self.logger.error(f"Invalid keyword format in source '{source_name}': Expected a list.")
            self.validation_errors.append({
                'source': source_name, 
                'error': 'Expected a list of keywords.'
            })
            return

        if source_name not in self.patterns["keywords"]:
            self.patterns["keywords"][source_name] = set()

        valid_keywords = {str(kw).lower() for kw in keyword_list if isinstance(kw, (str, int, float))}
        # Cast to Set[str] to satisfy mypy
        kw_set = cast(Set[str], self.patterns["keywords"][source_name])
        # Ignore potential mypy confusion with Union
        kw_set.update(valid_keywords) # type: ignore[union-attr]
        invalid_count = len(keyword_list) - len(valid_keywords)
        if invalid_count > 0:
            self.logger.warning(f"{invalid_count} invalid keyword entries skipped in source '{source_name}'.")

    def _load_regex_from_data(self, pattern_data_list: Any, source_name: str) -> None:
        """
        Loads a list of regex patterns with metadata.
        
        Args:
            pattern_data_list: List of pattern data objects
            source_name: Source identifier for these patterns
        """
        if not isinstance(pattern_data_list, list):
            self.logger.error(f"Invalid regex pattern format in source '{source_name}': Expected a list of pattern objects.")
            self.validation_errors.append({
                'source': source_name, 
                'error': 'Expected a list of pattern objects.'
            })
            return

        # Ensure lists exist for this source
        if source_name not in self.patterns["regex"]:
            self.patterns["regex"][source_name] = []
        if source_name not in self.compiled_regex["regex"]:
             self.compiled_regex["regex"][source_name] = []

        for entry in pattern_data_list:
            if not isinstance(entry, dict):
                self.logger.warning(f"Skipping invalid regex entry (not a dict) in source '{source_name}'.")
                continue

            pattern_str = entry.get("pattern")
            if not pattern_str or not isinstance(pattern_str, str):
                self.logger.warning(f"Skipping regex entry with missing/invalid 'pattern' field in source '{source_name}'.")
                self.validation_errors.append({
                    'source': source_name, 
                    'entry': entry, 
                    'error': "Missing/invalid 'pattern' field."
                })
                continue

            flags_list = entry.get("flags", [])
            flags_int = self._parse_regex_flags(flags_list)

            # Store raw pattern string in patterns dict
            # Cast to List[str] to satisfy mypy
            regex_list = cast(List[str], self.patterns["regex"][source_name])
            # Ignore potential mypy confusion with Union
            regex_list.append(pattern_str) # type: ignore[union-attr]

            # Compile and store in compiled_regex dict
            try:
                compiled = re.compile(pattern_str, flags_int)
                # Store compiled pattern along with its metadata for potential use by filters
                compiled_entry_data = entry.copy()
                compiled_entry_data['compiled'] = compiled
                compiled_entry_data['source'] = source_name  # Add source info
                # Cast to List[CompiledPatternData] to satisfy mypy
                compiled_list = cast(List[CompiledPatternData], self.compiled_regex["regex"][source_name])
                compiled_list.append(compiled_entry_data)
            except re.error as e:
                error_info = {
                    'pattern': pattern_str, 
                    'source': source_name, 
                    'entry': entry, 
                    'error': f"Compilation error: {e}"
                }
                self.validation_errors.append(error_info)
                self.logger.error(f"Error compiling regex pattern '{pattern_str}' from source '{source_name}': {e}")

    def _parse_regex_flags(self, flag_names: Any) -> int:
        """
        Convert flag names (list of strings) to re module flag values.
        
        Args:
            flag_names: List of flag names to parse
            
        Returns:
            Integer representation of combined flags
        """
        if not isinstance(flag_names, list):
            return 0  # Default: no flags

        flags = 0
        flag_map = {
            'IGNORECASE': re.IGNORECASE, 'I': re.IGNORECASE,
            'MULTILINE': re.MULTILINE, 'M': re.MULTILINE,
            'DOTALL': re.DOTALL, 'S': re.DOTALL,
            'UNICODE': re.UNICODE, 'U': re.UNICODE,
            'VERBOSE': re.VERBOSE, 'X': re.VERBOSE,
            'ASCII': re.ASCII, 'A': re.ASCII
        }
        for name in flag_names:
            if isinstance(name, str):
                flag_val = flag_map.get(name.upper())
                if flag_val:
                    flags |= flag_val
                else:
                    self.logger.warning(f"Unknown regex flag name '{name}' ignored.")
        return flags

    # --- PatternProviderBase Implementation ---

    def load_patterns(self) -> None:
        """Reload patterns based on the current configuration."""
        self.logger.info("Reloading patterns...")
        self._validate_config()

    def get_patterns(self, category: Optional[str] = None, lang: Optional[str] = None) -> Dict[str, Union[Set[str], List[CompiledPatternData]]]:
        """
        Retrieve patterns, potentially filtered by category (source name) or language.

        Args:
            category: The source name or category hint to retrieve patterns for.
                      If None, returns all patterns aggregated.
            lang: Language code (e.g., 'en', 'fr') for filtering patterns.

        Returns:
            A dictionary containing 'keywords' (Set[str]) and 'regex' (List[CompiledPatternData]).
            Keywords are aggregated across all matching sources.
            Regex patterns are returned as a list of dictionaries, each containing the compiled
            pattern and its associated metadata.
        """
        result: Dict[str, Union[Set[str], List[CompiledPatternData]]] = {
            "keywords": set(),
            "regex": []
        }

        sources_to_include = [category] if category and category in self.sources else list(self.sources.keys())

        # Aggregate Keywords
        for source in sources_to_include:
            if source in self.patterns.get("keywords", {}):
                result["keywords"] = cast(Set[str], result["keywords"])
                # Ignore potential mypy confusion with Union
                result["keywords"].update(self.patterns["keywords"][source]) # type: ignore[union-attr]

        # Aggregate Regex (Compiled with Metadata)
        for source in sources_to_include:
            if source in self.compiled_regex.get("regex", {}):
                # Language filtering for defaults requires better mapping than source name check
                is_default_source = source == "resk_defaults"
                should_include = True
                
                if is_default_source and lang:
                    # Filter patterns within the default source based on lang hint in category
                    lang_suffix = f"_{lang.lower()}"
                    source_patterns = [p for p in self.compiled_regex["regex"][source] 
                                      if p.get('category', '').endswith(lang_suffix)]
                    result["regex"] = cast(List[CompiledPatternData], result["regex"])
                    # Ignore potential mypy confusion with Union
                    result["regex"].extend(source_patterns) # type: ignore[union-attr]
                    should_include = False  # Already handled this source for this lang
                elif is_default_source and not lang:
                    # Include all default patterns if no specific language requested
                    pass  # should_include remains True
                elif not is_default_source:
                    # Always include non-default sources if they match the category filter
                    pass  # should_include remains True
                else:  # Default source but lang mismatch
                    should_include = False

                if should_include:
                    result["regex"] = cast(List[CompiledPatternData], result["regex"])
                    # Ignore potential mypy confusion with Union
                    result["regex"].extend(self.compiled_regex["regex"][source]) # type: ignore[union-attr]

        return result

    def get_keywords(self, sources: Optional[List[str]] = None) -> Set[str]:
        """
        Convenience method to get only keywords from specified sources.
        
        Args:
            sources: Optional list of source names to retrieve keywords from
            
        Returns:
            Set of keywords from the specified sources
        """
        # Add type hint
        all_keywords: Set[str] = set()
        source_keys = sources if sources else self.patterns.get("keywords", {}).keys()
        for source in source_keys:
            if source in self.patterns.get("keywords", {}):
                # Ignore potential mypy confusion with Union
                all_keywords.update(self.patterns["keywords"][source]) # type: ignore[union-attr]
        return all_keywords

    def get_compiled_regex(self, sources: Optional[List[str]] = None) -> List[CompiledPatternData]:
        """
        Convenience method to get compiled regex patterns from specified sources.
        
        Args:
            sources: Optional list of source names to retrieve patterns from
            
        Returns:
            List of compiled pattern data from the specified sources
        """
        all_regex = []
        source_keys = sources if sources else self.compiled_regex.get("regex", {}).keys()
        for source in source_keys:
            if source in self.compiled_regex.get("regex", {}):
                all_regex.extend(self.compiled_regex["regex"][source])
        return all_regex

    def get_validation_errors(self) -> List[Dict[str, Any]]:
        """
        Return a list of validation errors encountered during loading.
        
        Returns:
            List of validation error dictionaries
        """
        return self.validation_errors 