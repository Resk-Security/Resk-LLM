import re
import html
from typing import List, Dict, Any, Callable

from resk.resk_models import RESK_MODELS
from resk.resk_openai_tokens import OPENAI_SPECIAL_TOKENS

class OpenAIProtector:
    def __init__(self, model: str = "gpt-4o", max_context_length: int = None, reserved_tokens: int = 1000, preserved_prompts: int = 2):
        self.model = model
        self.model_info = RESK_MODELS.get(model, RESK_MODELS["gpt-4o"])
        self.max_context_length = max_context_length or self.model_info["context_window"]
        self.max_output_tokens = self.model_info["max_output_tokens"]
        self.reserved_tokens = reserved_tokens
        self.preserved_prompts = preserved_prompts
        self.special_tokens = set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"])

    def sanitize_input(self, text: str) -> str:
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        for token in self.special_tokens:
            text = text.replace(token, "")
        text = self._close_html_tags(text)
        return html.escape(text)

    def _close_html_tags(self, text: str) -> str:
        opened_tags = []
        for match in re.finditer(r'<(\w+)[^>]*>', text):
            tag = match.group(1)
            if tag.lower() not in ['br', 'hr', 'img']:
                opened_tags.append(tag)
        for tag in reversed(opened_tags):
            text += f'</{tag}>'
        return text

    def _truncate_text(self, text: str) -> str:
        max_chars = self.max_context_length * 4  # Estimation grossière : 1 token ≈ 4 caractères
        return text[:max_chars] if len(text) > max_chars else text

    def manage_sliding_context(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        total_tokens = sum(len(msg['content'].split()) for msg in messages)
        if total_tokens <= self.max_context_length:
            return messages

        preserved_messages = messages[:self.preserved_prompts]
        remaining_messages = messages[self.preserved_prompts:]

        available_tokens = self.max_context_length - self.reserved_tokens
        preserved_tokens = sum(len(msg['content'].split()) for msg in preserved_messages)
        available_tokens -= preserved_tokens

        while remaining_messages and sum(len(msg['content'].split()) for msg in remaining_messages) > available_tokens:
            remaining_messages.pop(0)

        return preserved_messages + remaining_messages

    def protect_openai_call(self, api_function: Callable, *args: Any, **kwargs: Any) -> Any:
        sanitized_args = [self.sanitize_input(arg) if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {k: self.sanitize_input(v) if isinstance(v, str) else v for k, v in kwargs.items()}
        
        if 'messages' in sanitized_kwargs:
            sanitized_kwargs['messages'] = self.manage_sliding_context(sanitized_kwargs['messages'])
        
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
