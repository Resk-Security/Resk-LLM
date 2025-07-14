"""
RESK-LLM: A Comprehensive Toolkit for Securing LLM Agents

RESK-LLM provides a set of components to secure Large Language Model (LLM) based agents
against various threats, including:

- Prompt injections and jailbreak attempts
- Malicious requests and manipulations
- Leakage of sensitive or personal information (PII)
- Toxic and inappropriate content
- Identity spoofing and obfuscation
- Vector similarity attacks
- Data leakage via canary tokens

This library is specifically designed to enhance the security of autonomous agents
by providing robust protections for their interactions with users and systems.
"""

from .version import __version__

# --- Core Abstractions ---
from .core.abc import (
    SecurityComponent,
    FilterBase,
    DetectorBase,
    ProtectorBase,
    PatternProviderBase,
    SecurityManagerBase
)

# --- Enhanced Core Components ---
from .core.cache import IntelligentCache, ParallelProcessor, get_cache, cached_component_call
from .core.monitoring import (
    ReskMonitor, SecurityEvent, EventType, Severity, AlertRule,
    get_monitor, log_security_event, performance_monitor
)
from .core.advanced_security import (
    AdvancedCrypto, AnomalyDetector, AdaptiveSecurityManager,
    ThreatIntelligence, ThreatLevel, AuthenticationMethod,
    get_security_manager,
    ActivityAnalysisResult,
)

# --- Factory Functions ---
from .factory import (
    create_heuristic_filter,
    create_text_analyzer,
    create_canary_token_manager,
    create_vector_database,
    create_security_manager,
    create_component
)

# --- LLM Provider Integrations ---
from .providers_integration import OpenAIProtector, AnthropicProtector, CohereProtector

# --- Security Filters & Detectors ---
from .heuristic_filter import HeuristicFilter 
from .filtering_patterns import ( 
    check_pii_content, moderate_text, anonymize_text,
    check_text_for_injections, check_doxxing_attempt, analyze_toxicity, 
    check_for_obfuscation, sanitize_text_from_obfuscation
)
from .url_detector import URLDetector
from .ip_detector import IPDetector
from .content_policy_filter import ContentPolicyFilter
from .core.canary_tokens import CanaryTokenDetector
from .word_list_filter import WordListFilter

# --- Pattern Management ---
from .pattern_provider import FileSystemPatternProvider

# --- Vector Database & Similarity ---
from .vector_db import VectorDatabase

# --- Token & Context Management ---
from .resk_context_manager import TokenBasedContextManager
from .core.canary_tokens import CanaryTokenManager

# --- Security Management ---
from .prompt_security import PromptSecurityManager

# --- Text Analysis Utilities ---
from .text_analysis import TextAnalyzer
from .filtering_patterns import (
    normalize_homoglyphs, remove_emojis, replace_emojis_with_description,
    remove_zalgo, contains_zalgo
)

# --- Framework Integrations ---
from .flask_integration import FlaskProtector
from .fastapi_integration import FastAPIProtector

# --- Autonomous Agent Security ---
from .autonomous_agent_security import (
    AgentSecurityManager,
    AgentPermission,
    AgentIdentity,
    SecureAgentExecutor,
    AGENT_DEFAULT_PERMISSIONS
)

# --- Embedding Utilities (torch-free alternatives) ---
from .embedding_utils import (
    SklearnEmbedder,
    create_embedder
)

# Define the public API (organized by category)
__all__ = [
    # Version
    '__version__',

    # Core Abstractions
    'SecurityComponent',
    'FilterBase',
    'DetectorBase',
    'ProtectorBase',
    'PatternProviderBase',
    'SecurityManagerBase',
    
    # Enhanced Core Components
    'IntelligentCache',
    'ParallelProcessor',
    'get_cache',
    'cached_component_call',
    'ReskMonitor',
    'SecurityEvent',
    'EventType',
    'Severity',
    'AlertRule',
    'get_monitor',
    'log_security_event',
    'performance_monitor',
    'AdvancedCrypto',
    'AnomalyDetector',
    'AdaptiveSecurityManager',
    'ThreatIntelligence',
    'ThreatLevel',
    'AuthenticationMethod',
    'get_security_manager',
    'ActivityAnalysisResult',
    
    # Factory Functions
    'create_heuristic_filter',
    'create_text_analyzer',
    'create_canary_token_manager',
    'create_vector_database',
    'create_security_manager',
    'create_component',

    # LLM Provider Protectors
    'OpenAIProtector',
    'AnthropicProtector',
    'CohereProtector',

    # Security Filters & Detectors
    'HeuristicFilter',
    'URLDetector',
    'IPDetector',
    'ContentPolicyFilter',
    'CanaryTokenDetector',
    'WordListFilter',
    # Functions (to be potentially wrapped in Filter/Detector classes later)
    'check_pii_content', 
    'moderate_text', 
    'anonymize_text',
    'check_text_for_injections', 
    'check_doxxing_attempt', 
    'analyze_toxicity',
    'check_for_obfuscation', 
    'sanitize_text_from_obfuscation',

    # Pattern Management
    'FileSystemPatternProvider',

    # Vector Database & Similarity
    'VectorDatabase',

    # Token & Context Management
    'TokenBasedContextManager',
    'CanaryTokenManager',

    # Security Management
    'PromptSecurityManager',

    # Text Analysis & Utilities
    'TextAnalyzer',
    'normalize_homoglyphs', 
    'remove_emojis', 
    'replace_emojis_with_description',
    'remove_zalgo',
    'contains_zalgo',

    # Framework Integrations
    'FlaskProtector',
    'FastAPIProtector',

    # Autonomous Agent Security
    'AgentSecurityManager',
    'AgentPermission',
    'AgentIdentity',
    'SecureAgentExecutor',
    'AGENT_DEFAULT_PERMISSIONS',
    
    # Embedding Utilities (torch-free alternatives)
    'SklearnEmbedder',
    'create_embedder',
]