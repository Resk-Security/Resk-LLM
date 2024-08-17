import re
import html
from typing import List, Dict, Any, Callable, Union

from resk_llm.resk_models import RESK_MODELS
from resk_llm.resk_openai_tokens import OPENAI_SPECIAL_TOKENS
from resk_llm.resk_control_chars import RESK_CONTROL_CHARS

from resk_llm.resk_context_manager import MessageBasedContextManager, TokenBasedContextManager, TextCleaner


class OpenAIProtector:
    def __init__(self, model: str = "gpt-4o", context_manager: Union[TokenBasedContextManager, MessageBasedContextManager] = None):
        self.model = model
        self.model_info = RESK_MODELS.get(model, RESK_MODELS["gpt-4o"])
        self.special_tokens = set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"])
        self.context_manager = context_manager or TokenBasedContextManager(self.model_info)

    def sanitize_input(self, text: str) -> str:
        # Nettoyer le texte
        text = self.context_manager.clean_message(text)
        
        # Supprimer les tokens spéciaux
        for token in self.special_tokens:
            text = text.replace(token, "")
        
        # Encoder en UTF-8
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        
        # Échapper les caractères HTML
        text = html.escape(text, quote=False)
        
        return text

    def protect_openai_call(self, api_function: Callable, *args: Any, **kwargs: Any) -> Any:
        sanitized_args = [self.sanitize_input(arg) if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {k: self.sanitize_input(v) if isinstance(v, str) else v for k, v in kwargs.items()}
        
        if 'messages' in sanitized_kwargs:
            sanitized_kwargs['messages'] = self.context_manager.manage_sliding_context(sanitized_kwargs['messages'])
        
        sanitized_kwargs['model'] = self.model_info.get('version', self.model)
        
        return api_function(*sanitized_args, **sanitized_kwargs)
    

    @classmethod
    def get_available_models(cls) -> List[str]:
        return list(RESK_MODELS.keys())

    @classmethod
    def get_model_info(cls, model: str) -> Dict[str, Any]:
        return RESK_MODELS.get(model, None)
    
    @classmethod
    def get_special_tokens(cls) -> Dict[str, List[str]]:
        return OPENAI_SPECIAL_TOKENS

    @classmethod
    def update_special_tokens(cls, new_tokens: Dict[str, List[str]]) -> None:
        global OPENAI_SPECIAL_TOKENS
        OPENAI_SPECIAL_TOKENS = new_tokens

    @classmethod
    def get_control_chars(cls) -> Dict[str, str]:
        return RESK_CONTROL_CHARS

    @classmethod
    def update_control_chars(cls, new_chars: Dict[str, str]) -> None:
        global RESK_CONTROL_CHARS
        RESK_CONTROL_CHARS = new_chars
