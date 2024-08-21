import re
import html
from typing import List, Dict, Any, Callable, Union
from functools import lru_cache

from resk_llm.resk_models import RESK_MODELS
from resk_llm.resk_openai_tokens import OPENAI_SPECIAL_TOKENS
from resk_llm.resk_control_chars import RESK_CONTROL_CHARS

from resk_llm.resk_context_manager import MessageBasedContextManager, TokenBasedContextManager
from resk_llm.resk_malicious_patterns import ReskWordsLists

class OpenAIProtector:
    def __init__(self, model: str = "gpt-4o", context_manager: Union[TokenBasedContextManager, MessageBasedContextManager] = None):
        self.model = model
        self.model_info = RESK_MODELS.get(model, RESK_MODELS["gpt-4o"])
        self.special_tokens = set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"])
        self.context_manager = context_manager or TokenBasedContextManager(self.model_info)
        self.ReskWordsLists = ReskWordsLists()


    def sanitize_input(self, text: str) -> str:
         # Encoder en UTF-8
        text = text.encode('utf-8', errors='ignore').decode('utf-8')

        text = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', lambda m: m.group(0).replace('<script>', '').replace('</script>', ''), text)

        # Nettoyer le texte
        text = self.context_manager.clean_message(text)
        
        # Supprimer les tokens spéciaux
        for token in self.special_tokens:
            text = text.replace(token, "")
        
        # Échapper les caractères HTML
        text = html.escape(text, quote=False)
        
        return text

    def protect_openai_call(self, api_function: Callable, messages: List[Dict[str, str]], *args: Any, **kwargs: Any) -> Any:
        try:
            sanitized_messages = []
            for message in messages:
                content = message['content']
                sanitized_content = self.sanitize_input(content)
                
                warning = self.ReskWordsLists.check_input(sanitized_content)
                if warning:
                    return {"error": warning}
                
                sanitized_messages.append({"role": message['role'], "content": sanitized_content})

            kwargs['messages'] = self.context_manager.manage_sliding_context(sanitized_messages)
            kwargs['model'] = self.model

            return api_function(*args, **kwargs)

        except Exception as e:
            self.logger.error(f"Erreur lors de l'appel à l'API OpenAI : {str(e)}")
            return {"error": "Une erreur s'est produite lors du traitement de votre demande. Veuillez réessayer. error"}
    

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

    def update_prohibited_list(self, item: str, action: str, item_type: str) -> None:
        self.ReskWordsLists.update_prohibited_list(item, action, item_type)
        self.sanitize_input.cache_clear()

    def batch_update(self, updates: List[Dict[str, Union[str, List[str]]]]) -> None:
        self.ReskWordsLists.batch_update(updates)
        self.sanitize_input.cache_clear()