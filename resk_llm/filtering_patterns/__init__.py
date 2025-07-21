"""
RESK-LLM Filtering Patterns Module

This module provides default pattern lists for various security filters.
Uses the patterns from resk_llm.patterns module.
"""

# Import patterns from the patterns module
try:
    from resk_llm.patterns import (
        INJECTION_REGEX_PATTERNS,
        INJECTION_KEYWORD_LISTS,
        PII_PATTERNS,
        TOXICITY_PATTERNS,
        TOXICITY_KEYWORDS,
        RESK_WORDS_LIST,
        RESK_PROHIBITED_PATTERNS_ENG,
        RESK_PROHIBITED_PATTERNS_FR,
        ALL_PROHIBITED_PATTERNS
    )
    
    # Default pattern lists that can be imported by filters
    DEFAULT_PROHIBITED_PATTERNS = list(INJECTION_REGEX_PATTERNS) + [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # credit card
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
    ]
    
    DEFAULT_PROHIBITED_WORDS = set(RESK_WORDS_LIST) | {
        'hate speech', 'inappropriate', 'violence', 'abuse', 'discrimination',
        'hate', 'violent', 'offensive', 'toxic', 'harmful', 'malicious',
        'exploit', 'hack', 'bypass', 'ignore', 'disregard', 'password',
        'secret', 'confidential', 'private', 'admin', 'root'
    }
    
    DEFAULT_PII_PATTERNS = list(PII_PATTERNS) + [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # credit card
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b',  # IBAN
    ]
    
    DEFAULT_TOXIC_PATTERNS = list(TOXICITY_PATTERNS) + [
        r'\b(kill|murder|suicide|death)\b',
        r'\b(hate|racist|sexist|homophobic)\b',
        r'\b(terrorist|bomb|explosion)\b',
        r'\b(drugs|cocaine|heroin|meth)\b',
    ]
    
    # Language-specific patterns
    DEFAULT_PROHIBITED_PATTERNS_EN = list(RESK_PROHIBITED_PATTERNS_ENG)
    DEFAULT_PROHIBITED_PATTERNS_FR = list(RESK_PROHIBITED_PATTERNS_FR)
    
except ImportError:
    # Fallback patterns if the patterns module is not available
    DEFAULT_PROHIBITED_PATTERNS = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # credit card
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
    ]
    
    DEFAULT_PROHIBITED_WORDS = {
        'hate speech', 'inappropriate', 'violence', 'abuse', 'discrimination',
        'hate', 'violent', 'offensive', 'toxic', 'harmful', 'malicious',
        'exploit', 'hack', 'bypass', 'ignore', 'disregard', 'password',
        'secret', 'confidential', 'private', 'admin', 'root'
    }
    
    DEFAULT_PII_PATTERNS = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # credit card
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b',  # IBAN
    ]
    
    DEFAULT_TOXIC_PATTERNS = [
        r'\b(kill|murder|suicide|death)\b',
        r'\b(hate|racist|sexist|homophobic)\b',
        r'\b(terrorist|bomb|explosion)\b',
        r'\b(drugs|cocaine|heroin|meth)\b',
    ]
    
    DEFAULT_PROHIBITED_PATTERNS_EN = []
    DEFAULT_PROHIBITED_PATTERNS_FR = []

# Export all patterns
__all__ = [
    'DEFAULT_PROHIBITED_PATTERNS',
    'DEFAULT_PROHIBITED_WORDS', 
    'DEFAULT_PII_PATTERNS',
    'DEFAULT_TOXIC_PATTERNS',
    'DEFAULT_PROHIBITED_PATTERNS_EN',
    'DEFAULT_PROHIBITED_PATTERNS_FR'
] 