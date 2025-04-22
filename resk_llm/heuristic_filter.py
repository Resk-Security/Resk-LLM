import re
import logging
from typing import List, Dict, Set, Tuple, Any, Optional, Union

class HeuristicFilter:
    """
    A filter based on heuristics to identify and block potentially malicious user inputs.
    This is applied before any ML-based analysis to quickly reject obvious attack attempts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Suspicious keywords that might indicate prompt injection or jailbreak attempts
        self.suspicious_keywords = {
            'ignore previous instructions', 'ignore all instructions', 'bypass', 'jailbreak', 
            'ignore context', 'disregard', 'system prompt', 'new prompt', 'forget',
            'ignore restrictions', 'ignore guidelines', 'ignore rules', 'DAN', 'Do Anything Now',
            'now you are', 'you are now', 'you will now', 'in this role', 'overriding previous',
            'no ethical concerns', 'no moral limitations', 'secret mode'
        }
        
        # Suspicious patterns for jailbreak attempts
        self.suspicious_patterns = [
            # Contradiction patterns
            re.compile(r'ignore (?:previous|all|any).*?instructions', re.IGNORECASE),
            re.compile(r'forget (?:previous|all|any).*?instructions', re.IGNORECASE),
            re.compile(r'do not (?:follow|obey|respect).*?rules', re.IGNORECASE),
            
            # Role-playing patterns
            re.compile(r'you (?:are|will be) (?:now|from now on).*?', re.IGNORECASE),
            re.compile(r'pretend (?:to be|you are).*?', re.IGNORECASE),
            re.compile(r'act as if.*?', re.IGNORECASE),
            
            # Base64 and other encoding patterns
            re.compile(r'base64:[a-zA-Z0-9+/=]{20,}', re.IGNORECASE),
            
            # Whitespace obfuscation
            re.compile(r'i\s*g\s*n\s*o\s*r\s*e', re.IGNORECASE),
            re.compile(r'b\s*y\s*p\s*a\s*s\s*s', re.IGNORECASE),
            
            # Token manipulation attempts
            re.compile(r'<\|.*?\|>', re.IGNORECASE),  # Attempts to use model tokens
            re.compile(r'\[system\]|\[user\]|\[assistant\]', re.IGNORECASE),  # Role marker insertions
            
            # Contradictory instructions
            re.compile(r'answer in two different ways', re.IGNORECASE),
            re.compile(r'first.*?then ignore', re.IGNORECASE),
        ]
        
        # Indicators of potentially sensitive requests
        self.sensitive_request_indicators = {
            'password', 'credit card', 'ssn', 'social security', 'bank account',
            'address', 'phone number', 'email address', 'identity theft', 'dox',
            'private information', 'confidential', 'secret'
        }
        
    def add_suspicious_keyword(self, keyword: str) -> None:
        """Add a new suspicious keyword to the filter."""
        self.suspicious_keywords.add(keyword.lower())
        
    def add_suspicious_pattern(self, pattern: str) -> None:
        """Add a new suspicious regex pattern to the filter."""
        self.suspicious_patterns.append(re.compile(pattern, re.IGNORECASE))
        
    def check_input(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Check if the input text contains any suspicious patterns or keywords.
        
        Args:
            text: The input text to check
            
        Returns:
            A tuple (is_suspicious, reason) where:
            - is_suspicious is a boolean indicating if the text is suspicious
            - reason is an optional string explaining why the text is suspicious or None if not
        """
        try:
            # Normalize text by removing excessive whitespace and converting to lowercase
            normalized_text = ' '.join(text.split()).lower()
            
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword.lower() in normalized_text:
                    self.logger.warning(f"Suspicious keyword detected: {keyword}")
                    return True, f"Potentially harmful content detected: suspicious keyword '{keyword}'"
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                match = pattern.search(text)
                if match:
                    matched_text = match.group(0)
                    self.logger.warning(f"Suspicious pattern detected: {matched_text}")
                    return True, f"Potentially harmful content detected: suspicious pattern '{matched_text}'"
            
            # Check for contradictory instructions (a common jailbreak technique)
            instruction_count = sum(1 for phrase in [
                "ignore", "don't follow", "disregard", "bypass", "forget"
            ] if phrase in normalized_text)
            
            if instruction_count >= 2:
                self.logger.warning("Multiple contradictory instructions detected")
                return True, "Multiple contradictory instructions detected, potential jailbreak attempt"
            
            # Check for potential sensitive information requests
            for indicator in self.sensitive_request_indicators:
                if indicator in normalized_text:
                    self.logger.info(f"Sensitive request indicator detected: {indicator}")
                    # This is not necessarily malicious, just flagged for additional scrutiny
                    
            # No suspicious content detected
            return False, None
            
        except Exception as e:
            self.logger.error(f"Error during heuristic filtering: {str(e)}")
            # If there's an error, we return True to err on the side of caution
            return True, f"Error during content analysis: {str(e)}"
    
    def filter_input(self, text: str) -> Tuple[bool, Optional[str], str]:
        """
        Filter input text and return whether it passed the filter.
        
        Args:
            text: The input text to filter
            
        Returns:
            A tuple (passed_filter, reason, filtered_text) where:
            - passed_filter is a boolean indicating if the text passed the filter
            - reason is an optional string explaining why the text failed or None if passed
            - filtered_text is the original text or a sanitized version
        """
        is_suspicious, reason = self.check_input(text)
        
        if is_suspicious:
            return False, reason, text
        
        return True, None, text 