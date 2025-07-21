from dataclasses import dataclass, field
from typing import Any, List, Optional, Dict
from .filters.resk_heuristic_filter import RESK_HeuristicFilter
from .filters.resk_content_policy_filter import RESK_ContentPolicyFilter
from .filters.resk_word_list_filter import RESK_WordListFilter
from .detectors.resk_ip_detector import RESK_IPDetector
from .detectors.resk_url_detector import RESK_URLDetector
from .managers.prompt_security import PromptSecurityManager
from .managers.resk_context_manager import RESK_TokenBasedContextManager
from .integrations.resk_providers_integration import OpenAIProtector
from .utilities.resk_text_analysis import RESK_TextAnalyzer
from .utilities.resk_embedding_utils import RESK_Embedder
from .patterns.pattern_provider import FileSystemPatternProvider

@dataclass
class RESK:
    filters: List[Any] = field(default_factory=list)
    detectors: List[Any] = field(default_factory=list)
    managers: List[Any] = field(default_factory=list)
    integrations: List[Any] = field(default_factory=list)
    utilities: List[Any] = field(default_factory=list)
    patterns: Optional[Any] = None
    model_info: Optional[dict] = None

    def __post_init__(self):
        if self.model_info is None:
            self.model_info = {"context_window": 4096, "model_name": "gpt2"}
        
        # Si des filtres sont fournis dans la configuration, les utiliser
        # Sinon, utiliser les filtres par défaut
        if not self.filters:
            self.filters = [RESK_HeuristicFilter(), RESK_ContentPolicyFilter(), RESK_WordListFilter()]
        else:
            # S'assurer que les filtres sont des objets et non des chaînes
            processed_filters = []
            for f in self.filters:
                if isinstance(f, str):
                    # Si c'est une chaîne, essayer de créer l'objet correspondant
                    if f == 'RESK_HeuristicFilter':
                        processed_filters.append(RESK_HeuristicFilter())
                    elif f == 'RESK_ContentPolicyFilter':
                        processed_filters.append(RESK_ContentPolicyFilter())
                    elif f == 'RESK_WordListFilter':
                        processed_filters.append(RESK_WordListFilter())
                    else:
                        # Ignorer les filtres non reconnus
                        continue
                else:
                    processed_filters.append(f)
            self.filters = processed_filters
        
        if not self.detectors:
            self.detectors = [RESK_IPDetector(), RESK_URLDetector()]
        else:
            # S'assurer que les détecteurs sont des objets
            processed_detectors = []
            for d in self.detectors:
                if isinstance(d, str):
                    if d == 'RESK_IPDetector':
                        processed_detectors.append(RESK_IPDetector())
                    elif d == 'RESK_URLDetector':
                        processed_detectors.append(RESK_URLDetector())
                    else:
                        continue
                else:
                    processed_detectors.append(d)
            self.detectors = processed_detectors
            
        if not self.managers:
            self.managers = [PromptSecurityManager(), RESK_TokenBasedContextManager(model_info=self.model_info)]
        if not self.integrations:
            self.integrations = [OpenAIProtector()]
        if not self.utilities:
            self.utilities = [RESK_TextAnalyzer(), RESK_Embedder()]
        if not self.patterns:
            self.patterns = FileSystemPatternProvider()

    def process_prompt(self, prompt: str) -> dict:
        result: Dict[str, Any] = {
            'input': prompt,
            'filters': [],
            'detectors': [],
            'managers': [],
            'output': None,
            'blocked': False,
            'reason': None
        }
        # Process input through filters
        for f in self.filters:
            filter_result = f.filter(prompt)
            result['filters'].append(getattr(f, '__class__', type(f)).__name__)
            
            # Handle FilterResult objects
            if hasattr(filter_result, 'is_safe'):
                if not filter_result.is_safe:
                    result['blocked'] = True
                    result['reason'] = filter_result.reason or 'Blocked by filter'
                    result['output'] = '[BLOCKED] ' + (filter_result.reason or 'Blocked by filter')
                    return result
                prompt = filter_result.data if filter_result.data is not None else prompt
            # Handle tuple format (legacy)
            elif isinstance(filter_result, tuple):
                passed, reason, filtered = filter_result
                if not passed:
                    result['blocked'] = True
                    result['reason'] = reason or 'Blocked by filter'
                    result['output'] = '[BLOCKED] ' + (reason or 'Blocked by filter')
                    return result
                prompt = filtered if filtered is not None else prompt
            else:
                prompt = filter_result
                
        # Process input through detectors
        for d in self.detectors:
            try:
                detection_result = d.detect(prompt)
                result['detectors'].append(getattr(d, '__class__', type(d)).__name__)
                # Handle DetectionResult objects
                if hasattr(detection_result, 'is_detected') and detection_result.is_detected:
                    result['blocked'] = True
                    result['reason'] = f'Detected by {getattr(d, "__class__", type(d)).__name__}'
                    result['output'] = '[BLOCKED] ' + result['reason']
                    return result
            except Exception as e:
                result['blocked'] = True
                result['reason'] = str(e)
                result['output'] = '[BLOCKED] ' + str(e)
                return result
                
        # Process input through managers
        for m in self.managers:
            if hasattr(m, 'process_input'):
                try:
                    prompt = m.process_input(prompt)
                    result['managers'].append(getattr(m, '__class__', type(m)).__name__)
                except Exception as e:
                    result['blocked'] = True
                    result['reason'] = str(e)
                    result['output'] = '[BLOCKED] ' + str(e)
                    return result
                    
        # Call LLM (placeholder)
        output = self._call_llm(prompt)
        result['output'] = output
        # Process output through managers, filters, detectors (optional, can be expanded)
        return result

    def _process_input(self, prompt: str) -> str:
        for f in self.filters:
            prompt = f.filter(prompt)
        for d in self.detectors:
            d.detect(prompt)
        for m in self.managers:
            if hasattr(m, 'process_input'):
                prompt = m.process_input(prompt)
        return prompt

    def _call_llm(self, prompt: str) -> str:
        # Placeholder for LLM call
        return prompt + " [LLM output]"

    def _process_output(self, output: str) -> str:
        for m in self.managers:
            if hasattr(m, 'process_output'):
                output = m.process_output(output)
        for f in self.filters:
            output = f.filter(output)
        for d in self.detectors:
            d.detect(output)
        return output 