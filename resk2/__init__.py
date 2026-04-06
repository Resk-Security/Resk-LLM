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

# Integrations — optional, imported lazily on demand
_ReskMiddleware = None
_OpenAIWrapper = None
_ReskLogitsIntegration = None

def _load_integrations():
    global _ReskMiddleware, _OpenAIWrapper, _ReskLogitsIntegration
    if _ReskMiddleware is not None:
        return
    try:
        from .integrations.fastapi import ReskMiddleware as _M
        _ReskMiddleware = _M
    except ImportError:
        pass
    try:
        from .integrations.resk_openai import OpenAIWrapper as _O
        _OpenAIWrapper = _O
    except ImportError:
        pass
    try:
        from .integrations.resk_logits import ReskLogitsIntegration as _L
        _ReskLogitsIntegration = _L
    except ImportError:
        pass

def __getattr__(name):
    if name in ("ReskMiddleware", "OpenAIWrapper", "ReskLogitsIntegration"):
        _load_integrations()
        if name == "ReskMiddleware" and _ReskMiddleware is not None:
            return _ReskMiddleware
        if name == "OpenAIWrapper" and _OpenAIWrapper is not None:
            return _OpenAIWrapper
        if name == "ReskLogitsIntegration" and _ReskLogitsIntegration is not None:
            return _ReskLogitsIntegration
        raise ImportError(
            f"{name} requires optional dependencies. Install with: pip install resk-llm[all]"
        )
    raise AttributeError(f"module {__name__} has no attribute {name}")

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
    # Integrations (optional, lazy-loaded)
    "ReskMiddleware", "OpenAIWrapper", "ReskLogitsIntegration",
]
