"""
RESK-LLM Filtering Patterns

This module provides filtering patterns for detecting malicious content,
personal information (PII), and other types of sensitive content in messages
intended for LLM agents.

The module is organized into several pattern categories:
- Injection and jailbreak patterns
- PII (Personally Identifiable Information) detection patterns
- Toxic content detection patterns
- Protection against emojis and special Unicode characters
- Doxxing detection patterns
- Special tokens and control characters
- Lists of prohibited words and expressions
"""

from typing import Dict, List, Set, Any, Optional, Union, Tuple, Pattern, Match
import re
import json
import os
from pathlib import Path

# Import injection patterns
from resk_llm.filtering_patterns.llm_injection_patterns import (
    INJECTION_REGEX_PATTERNS,
    INJECTION_KEYWORD_LISTS,
    WORD_SEPARATION_PATTERNS,
    KNOWN_JAILBREAK_PATTERNS,
    check_text_for_injections
)

# Import PII patterns
from resk_llm.filtering_patterns.pii_patterns import (
    PII_PATTERNS,
    NAME_PATTERNS,
    DOXXING_KEYWORDS,
    DOXXING_CONTEXTS,
    check_pii_content,
    check_doxxing_attempt,
    anonymize_text
)

# Import toxic content patterns
from resk_llm.filtering_patterns.toxic_content_patterns import (
    TOXICITY_PATTERNS,
    SUBTLE_TOXICITY_PATTERNS,
    TOXICITY_KEYWORDS,
    CONTEXTUAL_PATTERNS,
    analyze_toxicity,
    moderate_text,
    check_toxic_content
)

# Import protections against emojis and special characters
from resk_llm.filtering_patterns.emoji_patterns import (
    EMOJI_PATTERN,
    HOMOGLYPHS,
    INVERSE_HOMOGLYPHS,
    detect_emojis,
    normalize_homoglyphs,
    remove_emojis,
    replace_emojis_with_description,
    check_for_obfuscation,
    sanitize_text_from_obfuscation,
    contains_zalgo,
    remove_zalgo
)

# Import special tokens
from resk_llm.filtering_patterns.special_tokens import (
    OPENAI_SPECIAL_TOKENS,
    ANTHROPIC_SPECIAL_TOKENS,
    LLAMA_SPECIAL_TOKENS,
    MISTRAL_SPECIAL_TOKENS,
    COHERE_SPECIAL_TOKENS,
    ALL_SPECIAL_TOKENS,
    CONTROL_CHARS,
    SPECIAL_CHARS,
    get_all_special_tokens,
    get_model_special_tokens
)

# Import prohibited word lists and patterns
from resk_llm.filtering_patterns.prohibited_words import RESK_WORDS_LIST
from resk_llm.filtering_patterns.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG
from resk_llm.filtering_patterns.prohibited_patterns_fr import RESK_PROHIBITED_PATTERNS_FR

# Variable for all prohibited patterns with language support
ALL_PROHIBITED_PATTERNS: Dict[str, Set[str]] = {
    "en": RESK_PROHIBITED_PATTERNS_ENG,
    "fr": RESK_PROHIBITED_PATTERNS_FR
}

# Define what is exposed
__all__ = [
    # Injection patterns
    'INJECTION_REGEX_PATTERNS',
    'INJECTION_KEYWORD_LISTS',
    'WORD_SEPARATION_PATTERNS',
    'KNOWN_JAILBREAK_PATTERNS',
    'check_text_for_injections',
    
    # PII patterns
    'PII_PATTERNS',
    'NAME_PATTERNS',
    'DOXXING_KEYWORDS',
    'DOXXING_CONTEXTS',
    'check_pii_content',
    'check_doxxing_attempt',
    'anonymize_text',
    
    # Toxic content patterns
    'TOXICITY_PATTERNS',
    'SUBTLE_TOXICITY_PATTERNS',
    'TOXICITY_KEYWORDS',
    'CONTEXTUAL_PATTERNS',
    'analyze_toxicity',
    'moderate_text',
    'check_toxic_content',
    
    # Emoji protection and obfuscation
    'EMOJI_PATTERN',
    'HOMOGLYPHS',
    'INVERSE_HOMOGLYPHS',
    'detect_emojis',
    'normalize_homoglyphs',
    'remove_emojis',
    'replace_emojis_with_description',
    'check_for_obfuscation',
    'sanitize_text_from_obfuscation',
    'contains_zalgo',
    'remove_zalgo',
    
    # Special tokens
    'OPENAI_SPECIAL_TOKENS',
    'ANTHROPIC_SPECIAL_TOKENS',
    'LLAMA_SPECIAL_TOKENS',
    'MISTRAL_SPECIAL_TOKENS',
    'COHERE_SPECIAL_TOKENS',
    'ALL_SPECIAL_TOKENS',
    'CONTROL_CHARS',
    'SPECIAL_CHARS',
    'get_all_special_tokens',
    'get_model_special_tokens',
    
    # Prohibited word lists and patterns
    'RESK_WORDS_LIST',
    'RESK_PROHIBITED_PATTERNS_ENG',
    'RESK_PROHIBITED_PATTERNS_FR',
    'ALL_PROHIBITED_PATTERNS'
] 