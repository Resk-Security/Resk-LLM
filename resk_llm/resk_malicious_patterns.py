import re
import logging
from typing import List, Dict, Union

from resk_llm.prohibited_words import RESK_WORDS_LIST
from resk_llm.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG

class ReskWordsLists:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.prohibited_words = set(RESK_WORDS_LIST)
        self.prohibited_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in RESK_PROHIBITED_PATTERNS_ENG]

    def check_input(self, text: str) -> Union[str, None]:
        try:
            # Vérifier les mots interdits
            for word in text.split():
                if word.lower() in self.prohibited_words:
                    return f"Avertissement : Le mot '{word}' n'est pas autorisé. Veuillez reformuler votre message."

            # Vérifier les expressions interdites
            for pattern in self.prohibited_patterns:
                if pattern.search(text):
                    return f"Avertissement : expression interdite & n'est pas autorisé"

            # Si aucun mot ou expression interdit n'est trouvé, retourner None
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