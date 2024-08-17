from typing import Dict, List, Union
import re

class TextCleaner:
    @staticmethod
    def clean_text(text: str) -> str:
        return ' '.join(text.split())

    @staticmethod
    def truncate_text(text: str, max_length: int) -> str:
        return text[:max_length]

class ContextManagerBase:
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2):
        self.max_context_length = model_info["context_window"]
        self.preserved_prompts = preserved_prompts
        self.text_cleaner = TextCleaner()

    def clean_message(self, message: str) -> str:
        return self.text_cleaner.clean_text(message)

    def _close_html_tags(self, text: str) -> str:
        opened_tags = []
        for match in re.finditer(r'<(\w+)[^>]*>', text):
            tag = match.group(1)
            if tag.lower() not in ['br', 'hr', 'img']:
                opened_tags.append(tag)
        for tag in reversed(opened_tags):
            text += f'</{tag}>'
        return text

class TokenBasedContextManager(ContextManagerBase):
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2, reserved_tokens: int = 1000):
        super().__init__(model_info, preserved_prompts)
        self.reserved_tokens = reserved_tokens

    def manage_sliding_context(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        cleaned_messages = [{'role': msg['role'], 'content': self.clean_message(msg['content'])} for msg in messages]
        total_tokens = sum(len(msg['content'].split()) for msg in cleaned_messages)
        
        if total_tokens <= self.max_context_length:
            return cleaned_messages

        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]

        available_tokens = self.max_context_length - self.reserved_tokens
        preserved_tokens = sum(len(msg['content'].split()) for msg in preserved_messages)
        available_tokens -= preserved_tokens

        while remaining_messages and available_tokens > 0:
            message = remaining_messages.pop(0)
            message_tokens = len(message['content'].split())
            
            if message_tokens > available_tokens:
                truncated_content = self.text_cleaner.truncate_text(message['content'], available_tokens)
                preserved_messages.append({'role': message['role'], 'content': truncated_content})
                break
            else:
                preserved_messages.append(message)
                available_tokens -= message_tokens

        return preserved_messages

class MessageBasedContextManager(ContextManagerBase):
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2, max_messages: int = 3):
        super().__init__(model_info, preserved_prompts)
        self.max_messages = max_messages

    def manage_sliding_context(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        cleaned_messages = [{'role': msg['role'], 'content': self.clean_message(msg['content'])} for msg in messages]
        
        if len(cleaned_messages) <= self.max_messages:
            return cleaned_messages

        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]

        return preserved_messages + remaining_messages[-(self.max_messages):]
