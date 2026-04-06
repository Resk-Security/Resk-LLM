"""RESK-LLM v2.1 - Comprehensive security toolkit for LLM applications."""
__version__ = "2.1.0"

# Core
from .core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector
from .core.pipeline import SecurityPipeline, PipelineResult
from .core.config import SecurityConfig
from .core.context import ConversationContext, ConversationEntry

# Detectors
from .detectors.direct_injection import DirectInjectionDetector
from .detectors.bypass_detection import BypassDetector
from .detectors.memory_poisoning import MemoryPoisoningDetector
from .detectors.goal_hijack import GoalHijackDetector
from .detectors.exfiltration import ExfiltrationDetector
from .detectors.inter_agent_injection import InterAgentInjectionDetector
from .detectors.vector_similarity import VectorSimilarityDetector
from .detectors.acl_decision_tree import ACLDecisionTreeDetector
from .detectors.content_framing import ContentFramingDetector

# Protection
from .protection.sanitizer import InputSanitizer
from .protection.validator import OutputValidator
from .protection.canary import CanaryManager

# Integrations
from .integrations.fastapi import ReskMiddleware
from .integrations.resk_openai import OpenAIWrapper
from .integrations.resk_logits import ReskLogitsIntegration

__all__ = [
    "__version__",
    # Core
    "DetectionResult", "Severity", "ThreatCategory", "BaseDetector",
    "SecurityPipeline", "PipelineResult", "SecurityConfig",
    "ConversationContext", "ConversationEntry",
    # Detectors
    "DirectInjectionDetector", "BypassDetector", "MemoryPoisoningDetector",
    "GoalHijackDetector", "ExfiltrationDetector", "InterAgentInjectionDetector",
    "VectorSimilarityDetector", "ACLDecisionTreeDetector", "ContentFramingDetector",
    # Protection
    "InputSanitizer", "OutputValidator", "CanaryManager",
    # Integrations
    "ReskMiddleware", "OpenAIWrapper", "ReskLogitsIntegration",
]
