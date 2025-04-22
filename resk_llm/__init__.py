"""
RESK-LLM: Une boîte à outils complète pour la sécurisation des agents LLM

RESK-LLM fournit un ensemble de composants pour sécuriser les agents basés sur 
des grands modèles de langage (LLM) contre diverses menaces, notamment:

- Les injections de prompts et tentatives de jailbreak
- Les requêtes malveillantes et manipulations
- La fuite d'informations sensibles ou personnelles
- Les contenus toxiques et inappropriés
- L'usurpation d'identité et l'obfuscation
- Les attaques par similarité vectorielle
- Les fuites de données via jetons canari

Cette bibliothèque est spécialement conçue pour renforcer la sécurité des agents autonomes
en fournissant des protections robustes pour leurs interactions avec les utilisateurs et systèmes.
"""

from .version import __version__

# Core components
from .resk_context_manager import TokenBasedContextManager
from .tokenizer_protection import ReskWordsLists, CustomPatternManager
from .filtering_patterns import check_pii_content, moderate_text, anonymize_text
from .providers_integration import OpenAIProtector, AnthropicProtector, CohereProtector

# Advanced security components
from .text_analysis import TextAnalyzer  
from .competitor_filter import CompetitorFilter
from .url_detector import URLDetector
from .ip_protection import IPProtection
from .regex_pattern_manager import RegexPatternManager

# Existing security components
from .heuristic_filter import HeuristicFilter
from .vector_db import VectorDatabase
from .canary_tokens import CanaryTokenManager, CanaryTokenDetector
from .prompt_security import PromptSecurityManager

# Import framework integrations
from resk_llm.flask_integration import FlaskProtector
from resk_llm.fastapi_integration import FastAPIProtector

# Import agent security specific components
from resk_llm.autonomous_agent_security import (
    AgentSecurityManager,
    AgentPermission,
    AgentIdentity,
    SecureAgentExecutor,
    AGENT_DEFAULT_PERMISSIONS
)

# Import filtering patterns if available
try:
    from resk_llm.filtering_patterns import (
        # Injection patterns
        INJECTION_REGEX_PATTERNS,
        INJECTION_KEYWORD_LISTS,
        WORD_SEPARATION_PATTERNS,
        KNOWN_JAILBREAK_PATTERNS,
        check_text_for_injections,
        
        # PII patterns
        PII_PATTERNS,
        NAME_PATTERNS,
        DOXXING_KEYWORDS,
        DOXXING_CONTEXTS,
        check_pii_content,
        check_doxxing_attempt,
        anonymize_text,
        
        # Toxicity patterns
        TOXICITY_PATTERNS,
        SUBTLE_TOXICITY_PATTERNS,
        TOXICITY_KEYWORDS,
        CONTEXTUAL_PATTERNS,
        analyze_toxicity,
        moderate_text,
        
        # Emoji and Unicode protection
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
        remove_zalgo,
        
        # Special tokens and characters
        OPENAI_SPECIAL_TOKENS,
        ANTHROPIC_SPECIAL_TOKENS,
        LLAMA_SPECIAL_TOKENS,
        MISTRAL_SPECIAL_TOKENS,
        COHERE_SPECIAL_TOKENS,
        ALL_SPECIAL_TOKENS,
        CONTROL_CHARS,
        SPECIAL_CHARS,
        get_all_special_tokens,
        get_model_special_tokens,
        
        # Listes de mots et patterns prohibés
        RESK_WORDS_LIST,
        RESK_PROHIBITED_PATTERNS_ENG,
        RESK_PROHIBITED_PATTERNS_FR,
        ALL_PROHIBITED_PATTERNS
    )
except ImportError:
    pass

# Define what's available in the public API
__all__ = [
    # Core functionality
    'TokenBasedContextManager',
    'ReskWordsLists',
    'CustomPatternManager',
    'OpenAIProtector',
    'AnthropicProtector',
    'CohereProtector',
    
    # Filtering and content moderation
    'check_pii_content',
    'moderate_text',
    'anonymize_text',
    
    # Advanced security features
    'TextAnalyzer',
    'CompetitorFilter',
    'URLDetector',
    'IPProtection',
    'RegexPatternManager',
    
    # Existing security components
    'HeuristicFilter',
    'VectorDatabase',
    'CanaryTokenManager',
    'CanaryTokenDetector',
    'PromptSecurityManager',
]