import re
import logging
import json
import os
from typing import List, Dict, Any, Tuple, Optional, Set, Union, Pattern, cast
from pathlib import Path

class CompetitorFilter:
    """
    Filter for detecting and blocking mentions of competitors, banned code patterns,
    restricted topics, and other potentially unwanted content.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the competitor filter.
        
        Args:
            config_path: Optional path to a configuration file with custom lists
        """
        self.logger = logging.getLogger(__name__)
        
        # Default competitor companies to filter (empty by default, should be configured)
        self.competitor_names: Set[str] = set()
        self.competitor_products: Dict[str, List[str]] = {}
        self.competitor_domains: Set[str] = set()
        
        # Banned code patterns (code that should not be generated)
        self.banned_code_patterns: List[Dict[str, Any]] = []
        
        # Banned topics or subjects
        self.banned_topics: Set[str] = set()
        
        # Banned substrings (exact matches to block)
        self.banned_substrings: Set[str] = set()
        
        # Regular expressions for more complex patterns
        self.regex_patterns: List[Dict[str, Any]] = []
        
        # Load configuration if provided
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> bool:
        """
        Load filter configuration from a JSON file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(config_path):
                self.logger.error(f"Configuration file not found: {config_path}")
                return False
                
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            # Load competitor information
            if 'competitors' in config:
                comp_config = config['competitors']
                
                # Company names
                if 'names' in comp_config:
                    self.competitor_names = set(comp_config['names'])
                
                # Products
                if 'products' in comp_config:
                    self.competitor_products = comp_config['products']
                
                # Domains
                if 'domains' in comp_config:
                    self.competitor_domains = set(comp_config['domains'])
            
            # Load banned code patterns
            if 'banned_code' in config:
                self.banned_code_patterns = config['banned_code']
            
            # Load banned topics
            if 'banned_topics' in config:
                self.banned_topics = set(config['banned_topics'])
            
            # Load banned substrings
            if 'banned_substrings' in config:
                self.banned_substrings = set(config['banned_substrings'])
            
            # Load regex patterns
            if 'regex_patterns' in config:
                self.regex_patterns = config['regex_patterns']
                
                # Compile the regular expressions
                for pattern in self.regex_patterns:
                    if 'pattern' in pattern:
                        try:
                            pattern['compiled'] = re.compile(pattern['pattern'], re.IGNORECASE)
                        except re.error as e:
                            self.logger.error(f"Invalid regex pattern '{pattern['pattern']}': {str(e)}")
            
            self.logger.info(f"Successfully loaded filter configuration from {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            return False
    
    def add_competitor(self, name: str, products: Optional[List[str]] = None, domain: Optional[str] = None) -> None:
        """
        Add a competitor to the filter.
        
        Args:
            name: Name of the competitor company
            products: List of product names from the competitor
            domain: Domain name of the competitor
        """
        self.competitor_names.add(name.lower())
        
        if products:
            self.competitor_products[name.lower()] = [p.lower() for p in products]
        
        if domain:
            self.competitor_domains.add(domain.lower())
    
    def add_banned_code(self, pattern: str, language: Optional[str] = None, description: Optional[str] = None) -> None:
        """
        Add a banned code pattern.
        
        Args:
            pattern: Regex pattern for code that should be banned
            language: Optional programming language this applies to
            description: Optional description of why this code is banned
        """
        code_pattern = {
            'pattern': pattern,
            'compiled': re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        }
        
        if language:
            code_pattern['language'] = language
            
        if description:
            code_pattern['description'] = description
            
        self.banned_code_patterns.append(code_pattern)
    
    def add_banned_topic(self, topic: str) -> None:
        """
        Add a topic that should be banned.
        
        Args:
            topic: Topic to ban (e.g., "cryptocurrency", "weapons")
        """
        self.banned_topics.add(topic.lower())
    
    def add_banned_substring(self, substring: str) -> None:
        """
        Add a substring that should be banned.
        
        Args:
            substring: Exact substring to ban
        """
        self.banned_substrings.add(substring)
    
    def add_custom_regex(self, pattern: str, name: Optional[str] = None, description: Optional[str] = None) -> bool:
        """
        Add a custom regex pattern for matching.
        
        Args:
            pattern: Regex pattern string
            name: Optional name for this pattern
            description: Optional description of what this pattern detects
            
        Returns:
            True if pattern was added successfully, False if compilation failed
        """
        regex_pattern: Dict[str, Any] = {
            'pattern': pattern
        }
        
        if name:
            regex_pattern['name'] = name
            
        if description:
            regex_pattern['description'] = description
            
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            regex_pattern['compiled'] = compiled_pattern
            self.regex_patterns.append(regex_pattern)
            return True
        except re.error as e:
            self.logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
            return False
    
    def check_competitors(self, text: str) -> List[Dict[str, Any]]:
        """
        Check if text contains references to competitors.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with details of competitor mentions
        """
        findings = []
        text_lower = text.lower()
        
        # Check for company names
        for company in self.competitor_names:
            pattern = r'\b' + re.escape(company) + r'\b'
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            
            if matches:
                findings.append({
                    'type': 'competitor_company',
                    'name': company,
                    'count': len(matches),
                    'positions': [(m.start(), m.end()) for m in matches]
                })
        
        # Check for product names
        for company, products in self.competitor_products.items():
            for product in products:
                pattern = r'\b' + re.escape(product) + r'\b'
                matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
                
                if matches:
                    findings.append({
                        'type': 'competitor_product',
                        'company': company,
                        'product': product,
                        'count': len(matches),
                        'positions': [(m.start(), m.end()) for m in matches]
                    })
        
        # Check for domains
        for domain in self.competitor_domains:
            pattern = re.escape(domain)
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            
            if matches:
                findings.append({
                    'type': 'competitor_domain',
                    'domain': domain,
                    'count': len(matches),
                    'positions': [(m.start(), m.end()) for m in matches]
                })
        
        return findings
    
    def check_banned_code(self, text: str) -> List[Dict[str, Any]]:
        """
        Check if text contains banned code patterns.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with details of banned code matches
        """
        findings = []
        
        for code_pattern in self.banned_code_patterns:
            regex = code_pattern['compiled']
            matches = list(regex.finditer(text))
            
            if matches:
                finding = {
                    'type': 'banned_code',
                    'pattern': code_pattern['pattern'],
                    'count': len(matches),
                    'positions': [(m.start(), m.end()) for m in matches],
                    'matches': [m.group() for m in matches]
                }
                
                if 'language' in code_pattern:
                    finding['language'] = code_pattern['language']
                    
                if 'description' in code_pattern:
                    finding['description'] = code_pattern['description']
                    
                findings.append(finding)
        
        return findings
    
    def check_banned_topics(self, text: str) -> List[Dict[str, Any]]:
        """
        Check if text contains banned topics.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with details of banned topic matches
        """
        findings = []
        text_lower = text.lower()
        
        for topic in self.banned_topics:
            pattern = r'\b' + re.escape(topic) + r'\b'
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            
            if matches:
                findings.append({
                    'type': 'banned_topic',
                    'topic': topic,
                    'count': len(matches),
                    'positions': [(m.start(), m.end()) for m in matches]
                })
        
        return findings
    
    def check_banned_substrings(self, text: str) -> List[Dict[str, Any]]:
        """
        Check if text contains banned substrings.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with details of banned substring matches
        """
        findings = []
        
        for substring in self.banned_substrings:
            # Find all occurrences
            positions = []
            start = 0
            
            while True:
                start = text.find(substring, start)
                if start == -1:
                    break
                positions.append((start, start + len(substring)))
                start += 1
            
            if positions:
                findings.append({
                    'type': 'banned_substring',
                    'substring': substring,
                    'count': len(positions),
                    'positions': positions
                })
        
        return findings
    
    def check_regex_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Check if text matches any custom regex patterns.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with details of regex pattern matches
        """
        findings = []
        
        for pattern in self.regex_patterns:
            if 'compiled' in pattern:
                regex = cast(Pattern[str], pattern['compiled'])
                matches = list(regex.finditer(text))
                
                if matches:
                    finding = {
                        'type': 'regex_pattern',
                        'pattern': pattern['pattern'],
                        'count': len(matches),
                        'positions': [(m.start(), m.end()) for m in matches],
                        'matches': [m.group() for m in matches]
                    }
                    
                    if 'name' in pattern:
                        finding['name'] = pattern['name']
                        
                    if 'description' in pattern:
                        finding['description'] = pattern['description']
                        
                    findings.append(finding)
        
        return findings
    
    def check_text(self, text: str) -> Dict[str, Any]:
        """
        Check text for all configured filter patterns.
        
        Args:
            text: Text to check
            
        Returns:
            Dictionary with all filter check results
        """
        results = {
            'competitors': self.check_competitors(text),
            'banned_code': self.check_banned_code(text),
            'banned_topics': self.check_banned_topics(text),
            'banned_substrings': self.check_banned_substrings(text),
            'regex_patterns': self.check_regex_patterns(text),
            'has_matches': False
        }
        
        # Check if any matches were found
        categories = ['competitors', 'banned_code', 'banned_topics', 'banned_substrings', 'regex_patterns']
        total_matches = 0
        for key in categories:
            category_results = results.get(key) # Use .get() for safety
            if isinstance(category_results, list):
                total_matches += len(category_results) # Now len() is called on a variable known to be a list

        results['has_matches'] = total_matches > 0
        results['total_matches'] = total_matches
        
        return results
    
    def filter_text(self, text: str, replacement: str = "[FILTERED]") -> Tuple[str, Dict[str, Any]]:
        """
        Filter text by replacing matched patterns with a replacement string.
        
        Args:
            text: Text to filter
            replacement: String to replace matched content with
            
        Returns:
            Tuple of (filtered text, details of replacements)
        """
        filtered_text = text
        check_results = self.check_text(text)
        
        # Track all positions to replace
        all_positions = []
        
        # Gather positions from all check types
        for check_type in ['competitors', 'banned_code', 'banned_topics', 'banned_substrings', 'regex_patterns']:
            for match in check_results[check_type]:
                all_positions.extend(match['positions'])
        
        # Sort positions by start index, in reverse order (to replace from end to beginning)
        all_positions.sort(reverse=True)
        
        # Replace each match with the replacement text
        for start, end in all_positions:
            filtered_text = filtered_text[:start] + replacement + filtered_text[end:]
        
        return filtered_text, check_results
    
    def create_default_config(self, file_path: str) -> bool:
        """
        Create a default configuration file.
        
        Args:
            file_path: Path to save the configuration file
            
        Returns:
            True if file was created successfully, False otherwise
        """
        try:
            default_config = {
                "competitors": {
                    "names": [],  # Add competitor company names
                    "products": {},  # Map companies to their products
                    "domains": []  # Add competitor domains
                },
                "banned_code": [
                    {
                        "pattern": r"eval\s*\(\s*request\.data\s*\)",
                        "language": "python",
                        "description": "Dangerous code execution from user input"
                    },
                    {
                        "pattern": r"exec\s*\(\s*.*?\s*\)",
                        "language": "python",
                        "description": "Potentially unsafe code execution"
                    }
                ],
                "banned_topics": [
                    "illegal activities",
                    "weapons",
                    "gambling"
                ],
                "banned_substrings": [
                    "forbidden phrase",
                    "inappropriate content"
                ],
                "regex_patterns": [
                    {
                        "name": "Credit Card Numbers",
                        "pattern": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
                        "description": "Potential credit card number"
                    },
                    {
                        "name": "API Keys",
                        "pattern": r"\b(?:api|sk|pk)_[a-zA-Z0-9]{24,48}\b",
                        "description": "Potential API key"
                    }
                ]
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Write the configuration file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2)
                
            self.logger.info(f"Created default configuration file at {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating default configuration: {str(e)}")
            return False 