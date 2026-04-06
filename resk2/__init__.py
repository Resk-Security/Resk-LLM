"""RESK-LLM v2.1 - Comprehensive security toolkit for LLM applications."""
__version__ = "2.1.0"

# Core
from .core.detector import DetectionResult, Severity, ThreatCategory, BaseDetector
from .core.pipeline import SecurityPipeline, PipelineResult
from .core.config import SecurityConfig

# Detectors
from .detectors.direct_injection import DirectInjectionDetector
from .detectors.bypass_detection import BypassDetector
from .detectors.memory_poisoning import MemoryPoisoningDetector
from .detectors.goal_hijack import GoalHijackDetector
from .detectors.exfiltration import ExfiltrationDetector
from .detectors.inter_agent_injection import InterAgentInjectionDetector

# Protection
from .protection.sanitizer import InputSanitizer
from .protection.validator import OutputValidator
from .protection.canary import CanaryManager

# Integrations
from .integrations.fastapi import ReskMiddleware
from .integrations.resk_openai import OpenAIWrapper

__all__ = [
    # Version
    "__version__",
    # Core
    "DetectionResult", "Severity", "ThreatCategory", "BaseDetector",
    "SecurityPipeline", "PipelineResult", "SecurityConfig",
    # Detectors
    "DirectInjectionDetector", "BypassDetector", "MemoryPoisoningDetector",
    "GoalHijackDetector", "ExfiltrationDetector", "InterAgentInjectionDetector",
    # Protection
    "InputSanitizer", "OutputValidator", "CanaryManager",
    # Integrations
    "ReskMiddleware", "OpenAIWrapper",
]
