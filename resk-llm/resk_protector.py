from resk_models import RESK_MODELS
from resk_openai_tokens import OPENAI_SPECIAL_TOKENS
from resk_context_manager import ContextManager

import html

class ReskProtector:
    def __init__(self, model="gpt-4o", preserved_prompts=2, reserved_tokens=1000):
        self.model = model
        self.model_info = RESK_MODELS.get(model, RESK_MODELS["gpt-4o"])
        self.special_tokens = set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"])
        self.context_manager = ContextManager(self.model_info, preserved_prompts, reserved_tokens)

    def sanitize_input(self, text):
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        for token in self.special_tokens:
            text = text.replace(token, "")
        text = self._close_html_tags(text)
        text = html.escape(text)
        return text

    def _close_html_tags(self, text):
        # Implémentation de la fermeture des balises HTML
        pass

    def protect_openai_call(self, api_function, *args, **kwargs):
        sanitized_args = [self.sanitize_input(arg) if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {k: self.sanitize_input(v) if isinstance(v, str) else v for k, v in kwargs.items()}
        
        if 'messages' in sanitized_kwargs:
            sanitized_kwargs['messages'] = self.context_manager.manage_sliding_context(sanitized_kwargs['messages'])
        
        return api_function(*sanitized_args, **sanitized_kwargs)

    @classmethod
    def get_special_tokens(cls):
        return OPENAI_SPECIAL_TOKENS

    @classmethod
    def update_special_tokens(cls, new_tokens):
        global OPENAI_SPECIAL_TOKENS
        OPENAI_SPECIAL_TOKENS = new_tokens