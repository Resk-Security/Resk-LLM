import re
import json
import os
import logging
from typing import Dict, List, Any, Tuple, Set, Optional, Union, Pattern, Mapping, cast, Sequence, MutableSequence
from pathlib import Path

class RegexPatternManager:
    """
    Manages the ingestion, validation, storage, and usage of regular expression patterns
    for security filtering and content analysis.
    """
    
    def __init__(self, patterns_dir: Optional[str] = None):
        """
        Initialize the regex pattern manager.
        
        Args:
            patterns_dir: Optional directory path where pattern files are stored
        """
        self.logger = logging.getLogger(__name__)
        
        # Directory for pattern files
        self.patterns_dir = patterns_dir
        if patterns_dir and not os.path.exists(patterns_dir):
            os.makedirs(patterns_dir, exist_ok=True)
        
        # Dictionaries to store patterns by category
        self.patterns: Dict[str, List[Dict[str, Any]]] = {}
        
        # Compiled regular expressions
        self.compiled_patterns: Dict[str, List[Dict[str, Any]]] = {}
        
        # Category metadata
        self.categories: Dict[str, Dict[str, Any]] = {}
        
        # Pattern validation errors
        self.validation_errors: List[Dict[str, Any]] = []
        
        # Load any existing patterns from the directory
        if patterns_dir:
            self.load_all_categories(patterns_dir)
    
    def load_all_categories(self, directory: str) -> bool:
        """
        Load all pattern files from a directory.
        
        Args:
            directory: Directory path containing pattern JSON files
            
        Returns:
            True if patterns were loaded successfully, False otherwise
        """
        try:
            pattern_files = [f for f in os.listdir(directory) if f.endswith('.json')]
            
            success = True
            for file_name in pattern_files:
                file_path = os.path.join(directory, file_name)
                category = file_name.replace('.json', '')
                
                if not self.load_patterns_from_file(file_path, category):
                    success = False
            
            return success
        except Exception as e:
            self.logger.error(f"Error loading patterns from directory {directory}: {str(e)}")
            return False
    
    def load_patterns_from_file(self, file_path: str, category: str) -> bool:
        """
        Load patterns from a JSON file.
        
        Args:
            file_path: Path to the JSON file containing patterns
            category: Category name for the patterns
            
        Returns:
            True if patterns were loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"Pattern file not found: {file_path}")
                return False
                
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Initialize category if needed
            if category not in self.patterns:
                self.patterns[category] = []
                self.compiled_patterns[category] = []
                self.categories[category] = {
                    'name': category,
                    'description': data.get('description', f"Patterns for {category}"),
                    'file_path': file_path
                }
            
            # Process metadata
            if 'metadata' in data:
                self.categories[category].update(data['metadata'])
            
            # Process patterns
            if 'patterns' in data:
                for pattern_data in data['patterns']:
                    # Validate and add the pattern
                    if self._validate_pattern(pattern_data, category):
                        pattern_data['category'] = category
                        self.patterns[category].append(pattern_data)
                        
                        # Compile the pattern
                        try:
                            flags = self._parse_regex_flags(pattern_data.get('flags', []))
                            compiled = re.compile(pattern_data['pattern'], flags)
                            
                            compiled_entry = pattern_data.copy()
                            compiled_entry['compiled'] = compiled
                            self.compiled_patterns[category].append(compiled_entry)
                        except re.error as e:
                            self.logger.error(f"Error compiling pattern '{pattern_data['pattern']}': {str(e)}")
                            self.validation_errors.append({
                                'pattern': pattern_data['pattern'],
                                'category': category,
                                'error': f"Compilation error: {str(e)}"
                            })
            
            return True
        except Exception as e:
            self.logger.error(f"Error loading patterns from {file_path}: {str(e)}")
            return False
    
    def _validate_pattern(self, pattern_data: Dict[str, Any], category: str) -> bool:
        """
        Validate a pattern entry.
        
        Args:
            pattern_data: Pattern data to validate
            category: Category of the pattern
            
        Returns:
            True if the pattern is valid, False otherwise
        """
        # Check required fields
        if 'pattern' not in pattern_data:
            self.logger.error(f"Missing required field 'pattern' in {category} patterns")
            self.validation_errors.append({
                'category': category,
                'error': "Missing required field 'pattern'"
            })
            return False
        
        # Check pattern syntax
        try:
            flags = self._parse_regex_flags(pattern_data.get('flags', []))
            re.compile(pattern_data['pattern'], flags)
        except re.error as e:
            self.logger.error(f"Invalid regex pattern '{pattern_data['pattern']}': {str(e)}")
            self.validation_errors.append({
                'pattern': pattern_data['pattern'],
                'category': category,
                'error': f"Invalid regex syntax: {str(e)}"
            })
            return False
        
        return True
    
    def _parse_regex_flags(self, flag_names: List[str]) -> int:
        """
        Convert flag names to re module flag values.
        
        Args:
            flag_names: List of flag names (e.g., ['IGNORECASE', 'MULTILINE'])
            
        Returns:
            Integer with flags bitwise OR'd together
        """
        flags = 0
        flag_map = {
            'IGNORECASE': re.IGNORECASE,
            'MULTILINE': re.MULTILINE,
            'DOTALL': re.DOTALL,
            'UNICODE': re.UNICODE,
            'VERBOSE': re.VERBOSE,
            'ASCII': re.ASCII
        }
        
        for name in flag_names:
            if name.upper() in flag_map:
                flags |= flag_map[name.upper()]
        
        return flags
    
    def add_pattern(self, pattern: str, category: str, name: Optional[str] = None, 
                   description: Optional[str] = None, flags: Optional[List[str]] = None, 
                   severity: str = "medium", tags: Optional[List[str]] = None) -> bool:
        """
        Add a new regex pattern.
        
        Args:
            pattern: The regex pattern string
            category: Category to add the pattern to
            name: Optional name for the pattern
            description: Optional description
            flags: Optional list of regex flags
            severity: Severity level (low, medium, high)
            tags: Optional list of tags
            
        Returns:
            True if the pattern was added successfully, False otherwise
        """
        # Create category if it doesn't exist
        if category not in self.patterns:
            self.patterns[category] = []
            self.compiled_patterns[category] = []
            self.categories[category] = {
                'name': category,
                'description': f"Patterns for {category}"
            }
        
        # Validate severity
        if severity not in ["low", "medium", "high"]:
            severity = "medium"
        
        # Create pattern data
        pattern_data: Dict[str, Any] = {
            'pattern': pattern,
            'category': category,
            'severity': severity
        }
        
        if name:
            pattern_data['name'] = name
        
        if description:
            pattern_data['description'] = description
        
        if flags:
            pattern_data['flags'] = flags
        
        if tags:
            pattern_data['tags'] = tags
        
        # Validate and add the pattern
        if self._validate_pattern(pattern_data, category):
            self.patterns[category].append(pattern_data)
            
            # Compile the pattern
            try:
                flags_int = self._parse_regex_flags(flags or [])
                compiled_pattern = re.compile(pattern, flags_int)
                
                compiled_entry: Dict[str, Any] = pattern_data.copy()
                compiled_entry['compiled'] = compiled_pattern
                self.compiled_patterns[category].append(compiled_entry)
                
                # Save the updated patterns if we have a directory
                if self.patterns_dir:
                    self.save_category(category)
                
                return True
            except re.error as e:
                self.logger.error(f"Error compiling pattern '{pattern}': {str(e)}")
                return False
        
        return False
    
    def save_category(self, category: str) -> bool:
        """
        Save patterns for a specific category to a file.
        
        Args:
            category: Category to save
            
        Returns:
            True if saved successfully, False otherwise
        """
        if not self.patterns_dir:
            self.logger.error("No patterns directory set, cannot save")
            return False
        
        if category not in self.patterns:
            self.logger.error(f"Category {category} not found")
            return False
        
        try:
            file_path = os.path.join(self.patterns_dir, f"{category}.json")
            
            # Initialize the patterns list with a type hint
            patterns_list: List[Dict[str, Any]] = []

            # Create the export data
            data: Dict[str, Any] = {
                'metadata': {
                    'name': category,
                    'description': self.categories[category].get('description', f"Patterns for {category}"),
                    'pattern_count': len(self.patterns[category])
                },
                'patterns': patterns_list # Use the initialized list
            }
            
            # Include any additional metadata
            for key, value in self.categories[category].items():
                if key not in ['name', 'description', 'file_path']:
                    data['metadata'][key] = value
            
            # Add all patterns (excluding compiled regex objects)
            for pattern in self.patterns[category]:
                pattern_copy = pattern.copy()
                pattern_copy.pop('category', None)  # Category is implicit in the file
                # Append to the typed list
                patterns_list.append(pattern_copy)
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                
            self.categories[category]['file_path'] = file_path # type: ignore[index]
            return True
        except Exception as e:
            self.logger.error(f"Error saving category {category}: {str(e)}")
            return False
    
    def save_all_categories(self) -> bool:
        """
        Save all pattern categories to files.
        
        Returns:
            True if all categories were saved successfully, False otherwise
        """
        if not self.patterns_dir:
            self.logger.error("No patterns directory set, cannot save")
            return False
        
        all_saved = True
        for category in self.patterns:
            if not self.save_category(category):
                all_saved = False
        
        return all_saved
    
    def create_category(self, category: str, description: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Create a new pattern category.
        
        Args:
            category: Name of the category to create
            description: Optional description
            metadata: Optional additional metadata
            
        Returns:
            True if the category was created, False if it already exists
        """
        if category in self.patterns:
            return False
        
        self.patterns[category] = []
        self.compiled_patterns[category] = []
        self.categories[category] = {
            'name': category,
            'description': description or f"Patterns for {category}"
        }
        
        if metadata:
            self.categories[category].update(metadata)
        
        return True
    
    def match_text(self, text: str, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Match text against the regex patterns.
        
        Args:
            text: Text to match against patterns
            categories: Optional list of categories to match against (default: all)
            
        Returns:
            List of dictionaries with match details
        """
        matches: List[Dict[str, Any]] = []
        
        # Determine which categories to check
        cats_to_check = categories if categories else list(self.compiled_patterns.keys())
        
        # Check each category
        for category in cats_to_check:
            if category in self.compiled_patterns:
                for pattern_data in self.compiled_patterns[category]:
                    compiled_pattern = pattern_data.get('compiled')
                    if not isinstance(compiled_pattern, Pattern):
                        continue
                        
                    pattern_matches = list(compiled_pattern.finditer(text))
                    
                    if pattern_matches:
                        match_data: Dict[str, Any] = {
                            'category': category,
                            'pattern': pattern_data['pattern'],
                            'severity': pattern_data.get('severity', 'medium'),
                            'matches': [],
                            'count': len(pattern_matches)
                        }
                        
                        if 'name' in pattern_data:
                            match_data['name'] = pattern_data['name']
                            
                        if 'description' in pattern_data:
                            match_data['description'] = pattern_data['description']
                        
                        # Add detailed match information
                        for m in pattern_matches:
                            match_data['matches'].append({
                                'start': m.start(),
                                'end': m.end(),
                                'text': m.group(),
                                'groups': m.groups() if m.groups() else None
                            })
                        
                        matches.append(match_data)
        
        return matches
    
    def filter_text(self, text: str, categories: Optional[List[str]] = None, 
                   replacement: str = "[FILTERED]", min_severity: str = "low") -> Tuple[str, List[Dict[str, Any]]]:
        """
        Filter text by replacing matches with a replacement string.
        
        Args:
            text: Text to filter
            categories: Optional list of categories to filter (default: all)
            replacement: String to replace matched content with
            min_severity: Minimum severity level to filter (low, medium, high)
            
        Returns:
            Tuple of (filtered text, match details)
        """
        filtered_text = text
        matches = self.match_text(text, categories)
        
        # Define severity levels for comparison
        severity_levels = {"low": 1, "medium": 2, "high": 3}
        min_level = severity_levels.get(min_severity.lower(), 1)
        
        # Track all positions to replace
        all_positions: List[Tuple[int, int]] = []
        
        # Gather positions from matches with sufficient severity
        for match in matches:
            severity = match.get('severity', 'medium').lower()
            if severity_levels.get(severity, 2) >= min_level:
                for m in match['matches']:
                    all_positions.append((m['start'], m['end']))
        
        # Sort positions by start index, in reverse order (to replace from end to beginning)
        all_positions.sort(reverse=True)
        
        # Replace each match with the replacement text
        for start, end in all_positions:
            filtered_text = filtered_text[:start] + replacement + filtered_text[end:]
        
        return filtered_text, matches
    
    def export_pattern(self, pattern_id: str, category: str) -> Dict[str, Any]:
        """
        Export a single pattern as a dictionary.
        
        Args:
            pattern_id: ID or name of the pattern to export
            category: Category the pattern belongs to
            
        Returns:
            Dictionary with pattern data or empty dict if not found
        """
        if category not in self.patterns:
            return {}
        
        for pattern in self.patterns[category]:
            if pattern.get('name') == pattern_id or pattern.get('id') == pattern_id:
                # Create a copy without the compiled pattern
                result = pattern.copy()
                return result
        
        return {}
    
    def import_pattern(self, pattern_data: Dict[str, Any]) -> bool:
        """
        Import a pattern from a dictionary.
        
        Args:
            pattern_data: Dictionary with pattern data
            
        Returns:
            True if imported successfully, False otherwise
        """
        if 'pattern' not in pattern_data or 'category' not in pattern_data:
            self.logger.error("Pattern data missing required fields 'pattern' and 'category'")
            return False
        
        category = pattern_data['category']
        pattern = pattern_data['pattern']
        name = pattern_data.get('name')
        description = pattern_data.get('description')
        
        # Ensure flags is a list of strings
        flags: List[str] = []
        flags_data = pattern_data.get('flags')
        if isinstance(flags_data, list):
            # Convert all items to strings if they're not already
            flags = [str(flag) for flag in flags_data if flag is not None]
        
        severity = pattern_data.get('severity', 'medium')
        
        # Ensure tags is a list of strings
        tags: List[str] = []
        tags_data = pattern_data.get('tags')
        if isinstance(tags_data, list):
            # Convert all items to strings if they're not already
            tags = [str(tag) for tag in tags_data if tag is not None]
        
        return self.add_pattern(
            pattern=pattern,
            category=category,
            name=name,
            description=description,
            flags=flags,
            severity=severity,
            tags=tags
        )
    
    def get_validation_errors(self) -> List[Dict[str, Any]]:
        """
        Get a list of validation errors.
        
        Returns:
            List of dictionaries with validation error details
        """
        return self.validation_errors
    
    @staticmethod
    def create_example_patterns(file_path: str) -> bool:
        """
        Create an example patterns file.
        
        Args:
            file_path: Path to save the example file
            
        Returns:
            True if file was created, False otherwise
        """
        try:
            example_data = {
                "metadata": {
                    "name": "example_patterns",
                    "description": "Example patterns for demonstration",
                    "version": "1.0",
                    "created": "2023-01-01"
                },
                "patterns": [
                    {
                        "name": "credit_card",
                        "pattern": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
                        "description": "Credit card number pattern",
                        "flags": ["IGNORECASE"],
                        "severity": "high",
                        "tags": ["pii", "financial"]
                    },
                    {
                        "name": "email",
                        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                        "description": "Email address pattern",
                        "flags": ["IGNORECASE"],
                        "severity": "medium",
                        "tags": ["pii", "contact"]
                    },
                    {
                        "name": "ip_address",
                        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                        "description": "IPv4 address pattern",
                        "severity": "medium",
                        "tags": ["network", "infrastructure"]
                    },
                    {
                        "name": "sql_injection",
                        "pattern": r"(?i)\b(select|update|insert|delete|drop|alter|union)\b.*?(?i)\b(from|into|table|database)\b",
                        "description": "Basic SQL injection pattern",
                        "severity": "high",
                        "tags": ["security", "injection"]
                    }
                ]
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Write the example file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(example_data, f, indent=2)
                
            return True
        except Exception as e:
            logging.error(f"Error creating example patterns file: {str(e)}")
            return False 