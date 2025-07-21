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
"""

from .version import __version__

# --- Core Abstractions & Core Components ---
from .core.abc import (
    SecurityComponent, FilterBase, DetectorBase, ProtectorBase, PatternProviderBase, SecurityManagerBase
)
from .core.cache import IntelligentCache, ParallelProcessor, get_cache, cached_component_call
from .core.monitoring import (
    ReskMonitor, SecurityEvent, EventType, Severity, AlertRule,
    get_monitor, log_security_event, performance_monitor
)
from .core.advanced_security import (
    AdvancedCrypto, AnomalyDetector, AdaptiveSecurityManager,
    ThreatIntelligence, ThreatLevel, AuthenticationMethod,
    get_security_manager, ActivityAnalysisResult
)
from .core.canary_tokens import CanaryTokenManager, CanaryTokenDetector

# --- Models ---
from .models.resk_models import ModelRegistry, RESK_MODELS, IndividualModelConfig, default_registry

# --- Filters ---
from .filters.resk_heuristic_filter import RESK_HeuristicFilter
from .filters.resk_content_policy_filter import RESK_ContentPolicyFilter
from .filters.resk_word_list_filter import RESK_WordListFilter

# --- Detectors ---
from .detectors.resk_ip_detector import RESK_IPDetector
from .detectors.resk_url_detector import RESK_URLDetector

# --- Managers ---
from .managers.factory import (
    create_heuristic_filter, create_text_analyzer, create_canary_token_manager,
    create_vector_database, create_security_manager, create_component
)
from .managers.resk_context_manager import (
    RESK_ContextManager, RESK_TokenBasedContextManager, RESK_MessageBasedContextManager, RESK_ContextWindowManager
)
from .managers.prompt_security import PromptSecurityManager

# --- Integrations ---
from .integrations.resk_providers_integration import OpenAIProtector, AnthropicProtector, CohereProtector
from .integrations.resk_fastapi_integration import FastAPIProtector
from .integrations.resk_flask_integration import FlaskProtector
from .integrations.resk_huggingface_integration import HuggingFaceProtector
from .integrations.resk_langchain_integration import LangChainProtector

# --- Utilities ---
from .utilities.resk_text_analysis import RESK_TextAnalyzer
from .utilities.resk_embedding_utils import RESK_Embedder, create_embedder
from .utilities.resk_vector_db import RESK_VectorDatabase

# --- Patterns ---
from .patterns.pattern_provider import FileSystemPatternProvider
from .patterns.llm_injection_patterns import *
from .patterns.special_tokens import *
from .patterns.prohibited_words import *
from .patterns.prohibited_patterns_eng import *
from .patterns.prohibited_patterns_fr import *
from .patterns.emoji_patterns import *
from .patterns.toxic_content_patterns import *
from .patterns.pii_patterns import *

# --- Agents ---
from .agents.autonomous_agent_security import (
    AgentSecurityManager, AgentPermission, AgentIdentity, SecureAgentExecutor, AGENT_DEFAULT_PERMISSIONS
)

# Define the public API (organized by category)
__all__ = [
    # Version
    '__version__',
    # Core Abstractions
    'SecurityComponent', 'FilterBase', 'DetectorBase', 'ProtectorBase', 'PatternProviderBase', 'SecurityManagerBase',
    # Core Components
    'IntelligentCache', 'ParallelProcessor', 'get_cache', 'cached_component_call',
    'ReskMonitor', 'SecurityEvent', 'EventType', 'Severity', 'AlertRule',
    'get_monitor', 'log_security_event', 'performance_monitor',
    'AdvancedCrypto', 'AnomalyDetector', 'AdaptiveSecurityManager',
    'ThreatIntelligence', 'ThreatLevel', 'AuthenticationMethod', 'get_security_manager', 'ActivityAnalysisResult',
    'CanaryTokenManager', 'CanaryTokenDetector',
    # Models
    'ModelRegistry', 'RESK_MODELS', 'IndividualModelConfig', 'default_registry',
    # Filters
    'RESK_HeuristicFilter', 'RESK_ContentPolicyFilter', 'RESK_WordListFilter',
    # Detectors
    'RESK_IPDetector', 'RESK_URLDetector',
    # Managers
    'create_heuristic_filter', 'create_text_analyzer', 'create_canary_token_manager',
    'create_vector_database', 'create_security_manager', 'create_component',
    'RESK_ContextManager', 'RESK_TokenBasedContextManager', 'RESK_MessageBasedContextManager', 'RESK_ContextWindowManager', 'PromptSecurityManager',
    # Integrations
    'OpenAIProtector', 'AnthropicProtector', 'CohereProtector',
    'FastAPIProtector', 'FlaskProtector', 'HuggingFaceProtector', 'LangchainIntegration',
    # Utilities
    'RESK_Embedder', 'create_embedder', 'RESK_TextAnalyzer', 'RESK_VectorDatabase',
    # Patterns (expose main providers, pas tous les symboles internes)
    'FileSystemPatternProvider',
    # Agents
    'AgentSecurityManager', 'AgentPermission', 'AgentIdentity', 'SecureAgentExecutor', 'AGENT_DEFAULT_PERMISSIONS',
]