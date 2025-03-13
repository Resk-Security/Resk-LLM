"""
RESK-LLM Filtering Patterns

Ce module fournit des patterns de filtrage pour la détection de contenu malveillant,
d'informations personnelles et d'autres types de contenus sensibles dans les messages
destinés aux agents LLM.

Le module est organisé en plusieurs catégories de patterns:
- Patterns d'injection et de jailbreak
- Patterns de détection de PII (informations personnelles identifiables)
- Patterns de détection de contenu toxique
- Protection contre les emojis et caractères Unicode spéciaux
- Patterns de détection de doxxing
- Tokens spéciaux et caractères de contrôle
- Listes de mots et expressions prohibés
"""

from typing import Dict, List, Set, Any, Optional, Union, Tuple, Pattern
import re
import json
import os
from pathlib import Path

# Import des patterns d'injection
from resk_llm.filtering_patterns.llm_injection_patterns import (
    INJECTION_REGEX_PATTERNS,
    INJECTION_KEYWORD_LISTS,
    WORD_SEPARATION_PATTERNS,
    KNOWN_JAILBREAK_PATTERNS,
    check_text_for_injections
)

# Import des patterns de PII
from resk_llm.filtering_patterns.pii_patterns import (
    PII_PATTERNS,
    NAME_PATTERNS,
    DOXXING_KEYWORDS,
    DOXXING_CONTEXTS,
    check_pii_content,
    check_doxxing_attempt,
    anonymize_text
)

# Import des patterns de contenu toxique
from resk_llm.filtering_patterns.toxic_content_patterns import (
    TOXICITY_PATTERNS,
    SUBTLE_TOXICITY_PATTERNS,
    TOXICITY_KEYWORDS,
    CONTEXTUAL_PATTERNS,
    analyze_toxicity,
    moderate_text,
    check_toxic_content
)

# Import des protections contre les emojis et caractères spéciaux
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

# Import des tokens spéciaux
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

# Import des listes de mots et patterns prohibés
from resk_llm.filtering_patterns.prohibited_words import RESK_WORDS_LIST
from resk_llm.filtering_patterns.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG
from resk_llm.filtering_patterns.prohibited_patterns_fr import RESK_PROHIBITED_PATTERNS_FR

# Variables pour l'ensemble des patterns prohibés
ALL_PROHIBITED_PATTERNS = {
    "en": RESK_PROHIBITED_PATTERNS_ENG,
    "fr": RESK_PROHIBITED_PATTERNS_FR
}

# Définir ce qui est exposé
__all__ = [
    # Patterns d'injection
    'INJECTION_REGEX_PATTERNS',
    'INJECTION_KEYWORD_LISTS',
    'WORD_SEPARATION_PATTERNS',
    'KNOWN_JAILBREAK_PATTERNS',
    'check_text_for_injections',
    
    # Patterns de PII
    'PII_PATTERNS',
    'NAME_PATTERNS',
    'DOXXING_KEYWORDS',
    'DOXXING_CONTEXTS',
    'check_pii_content',
    'check_doxxing_attempt',
    'anonymize_text',
    
    # Patterns de contenu toxique
    'TOXICITY_PATTERNS',
    'SUBTLE_TOXICITY_PATTERNS',
    'TOXICITY_KEYWORDS',
    'CONTEXTUAL_PATTERNS',
    'analyze_toxicity',
    'moderate_text',
    'check_toxic_content',
    
    # Protection emoji et obfuscation
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
    
    # Tokens spéciaux
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
    
    # Listes de mots et patterns prohibés
    'RESK_WORDS_LIST',
    'RESK_PROHIBITED_PATTERNS_ENG',
    'RESK_PROHIBITED_PATTERNS_FR',
    'ALL_PROHIBITED_PATTERNS'
] 