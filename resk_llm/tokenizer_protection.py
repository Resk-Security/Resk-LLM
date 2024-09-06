import re
import json
import logging
from typing import List, Dict, Any, Union
from transformers import PreTrainedTokenizer
import json
import os
from typing import Dict, Any, List
from transformers import PreTrainedTokenizer
from resk_llm.resk_openai_tokens import OPENAI_SPECIAL_TOKENS
from resk_llm.resk_control_chars import RESK_CONTROL_CHARS
from resk_llm.prohibited_words import RESK_WORDS_LIST
from resk_llm.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG

class ReskWordsLists:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.prohibited_words = set(RESK_WORDS_LIST)
        self.prohibited_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in RESK_PROHIBITED_PATTERNS_ENG]

    def check_input(self, text: str) -> Union[str, None]:
        try:
            for word in text.split():
                if word.lower() in self.prohibited_words:
                    return f"Avertissement : Le mot '{word}' n'est pas autorisé. Veuillez reformuler votre message."
            
            for pattern in self.prohibited_patterns:
                if pattern.search(text):
                    return f"Avertissement : expression interdite & n'est pas autorisé"
            
            return None
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de l'entrée : {str(e)}")
            return "Une erreur s'est produite lors de la vérification de votre message. Veuillez réessayer."

    def add_prohibited_word(self, word: str) -> None:
        self.prohibited_words.add(word.lower())

    def add_prohibited_pattern(self, pattern: str) -> None:
        self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))

    def remove_prohibited_word(self, word: str) -> None:
        self.prohibited_words.discard(word.lower())

    def remove_prohibited_pattern(self, pattern: str) -> None:
        self.prohibited_patterns = [p for p in self.prohibited_patterns if p.pattern != pattern]


class SecureTokenizer:
    def __init__(self, tokenizer: PreTrainedTokenizer, max_tokens: int = 1024):
        self.tokenizer = tokenizer
        self.max_tokens = max_tokens
        self.special_tokens = self._get_all_special_tokens()
        self.custom_special_tokens = set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"])
        self.control_chars = set(RESK_CONTROL_CHARS.values())
        self.resk_words_lists = ReskWordsLists()

    def _get_all_special_tokens(self) -> set[str]:
        special_tokens = set(self.tokenizer.all_special_tokens)
        
        # Récupérer les tokens spéciaux depuis tokenizer_config.json
        tokenizer_config_path = os.path.join(self.tokenizer.name_or_path, "tokenizer_config.json")
        if os.path.exists(tokenizer_config_path):
            with open(tokenizer_config_path, "r") as f:
                tokenizer_config = json.load(f)
            special_tokens.update(tokenizer_config.get("special_tokens", []))

        # Récupérer les tokens spéciaux depuis special_tokens_map.json
        special_tokens_map_path = os.path.join(self.tokenizer.name_or_path, "special_tokens_map.json")
        if os.path.exists(special_tokens_map_path):
            with open(special_tokens_map_path, "r") as f:
                special_tokens_map = json.load(f)
            special_tokens.update(special_tokens_map.values())

        return special_tokens

    def tokenize(self, text: str) -> Dict[str, Any]:
        cleaned_text = self._clean_text(text)
        
        tokens = self.tokenizer.tokenize(cleaned_text)

        # Filtrer les tokens spéciaux
        tokens = [token for token in tokens if token not in self.special_tokens]

        if len(tokens) > self.max_tokens:
            tokens = tokens[:self.max_tokens]

        return {"tokens": tokens, "num_tokens": len(tokens)}

    def _clean_text(self, text: str) -> str:
        # Nettoyer le texte au lieu de renvoyer une erreur
        for word in self.resk_words_lists.prohibited_words:
            text = re.sub(r'\b' + re.escape(word) + r'\b', '[REMOVED]', text, flags=re.IGNORECASE)
        
        for pattern in self.resk_words_lists.prohibited_patterns:
            text = pattern.sub('[REMOVED]', text)
        
        text = self._remove_custom_special_tokens(text)
        text = self._remove_control_chars(text)
        
        return text

    def _remove_custom_special_tokens(self, text: str) -> str:
        for token in self.custom_special_tokens:
            text = text.replace(token, "")
        return text

    def _remove_control_chars(self, text: str) -> str:
        return ''.join(char for char in text if char not in self.control_chars)

class TokenizerProtector:
    def __init__(self, tokenizer: PreTrainedTokenizer):
        self.secure_tokenizer = SecureTokenizer(tokenizer)

    def __call__(self, text: str, **kwargs) -> str:
        try:
            result = self.secure_tokenizer.tokenize(text)
            if "error" in result:
                return json.dumps({"status": "error", "message": result["error"]})
            
            safe_text = ' '.join(result["tokens"])
            tokenizer_output = self.secure_tokenizer.tokenizer(safe_text, **kwargs)
            
            response = {
                "status": "success",
                "tokens": result["tokens"],
                "num_tokens": result["num_tokens"],
                "tokenizer_output": {k: v.tolist() if hasattr(v, 'tolist') else v for k, v in tokenizer_output.items()}
            }
            return json.dumps(response)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})