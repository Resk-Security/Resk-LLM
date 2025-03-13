"""
Module for tokenizer protection against prompt injections and malicious inputs.
"""

import re
import json
import os
import logging
from typing import Dict, List, Optional, Set, Union, Tuple, Any
from pathlib import Path
from transformers import PreTrainedTokenizer

# Importer depuis filtering_patterns au lieu des fichiers directs
from resk_llm.filtering_patterns.special_tokens import OPENAI_SPECIAL_TOKENS, CONTROL_CHARS
from resk_llm.filtering_patterns.prohibited_words import RESK_WORDS_LIST
from resk_llm.filtering_patterns.prohibited_patterns_eng import RESK_PROHIBITED_PATTERNS_ENG
from resk_llm.filtering_patterns.prohibited_patterns_fr import RESK_PROHIBITED_PATTERNS_FR

# Import filtering patterns
try:
    from resk_llm.filtering_patterns import (
        INJECTION_REGEX_PATTERNS,
        INJECTION_KEYWORD_LISTS,
        WORD_SEPARATION_PATTERNS,
        KNOWN_JAILBREAK_PATTERNS,
        check_text_for_injections,
        check_for_obfuscation,
        sanitize_text_from_obfuscation
    )
    FILTERING_PATTERNS_AVAILABLE = True
except ImportError:
    FILTERING_PATTERNS_AVAILABLE = False

logger = logging.getLogger(__name__)

class ReskWordsLists:
    """
    Classe pour gérer les mots et patterns prohibés pour protéger les agents LLM.
    
    Cette classe permet de détecter des tentatives d'injection, des instructions 
    malveillantes et d'autres contenus inappropriés avant de les envoyer aux modèles.
    Elle intègre des patterns en français et en anglais, et peut être étendue avec
    des patterns personnalisés.
    """
    
    def __init__(self, 
                 custom_patterns_path: Optional[str] = None,
                 use_default_patterns: bool = True,
                 load_filtering_patterns: bool = True):
        """
        Initialisation avec les patterns par défaut et/ou personnalisés.
        
        Args:
            custom_patterns_path: Chemin vers un fichier JSON de patterns personnalisés
            use_default_patterns: Utiliser les patterns prohibés par défaut
            load_filtering_patterns: Charger les patterns du module filtering_patterns
        """
        self.logger = logging.getLogger(__name__)
        self.prohibited_words = set(RESK_WORDS_LIST)
        
        # Initialiser les patterns en anglais et en français
        self.prohibited_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in RESK_PROHIBITED_PATTERNS_ENG
        ]
        
        # Ajouter les patterns en français
        self.prohibited_patterns.extend([
            re.compile(pattern, re.IGNORECASE) for pattern in RESK_PROHIBITED_PATTERNS_FR
        ])
        
        # Load default patterns if requested
        if use_default_patterns:
            # Convertir tous les mots en minuscules pour une comparaison insensible à la casse
            lowercase_words = {word.lower() for word in self.prohibited_words}
            self.prohibited_words.update(lowercase_words)
        
        # Load additional patterns from filtering_patterns if available and requested
        if load_filtering_patterns and FILTERING_PATTERNS_AVAILABLE:
            self._load_filtering_patterns()
            
        # Load custom patterns if provided
        if custom_patterns_path:
            self._load_custom_patterns(custom_patterns_path)
    
    def _load_filtering_patterns(self) -> None:
        """
        Load patterns from the filtering_patterns module.
        """
        # Add regex patterns from llm_injection_patterns
        for pattern_name, pattern_obj in INJECTION_REGEX_PATTERNS.items():
            # Convert these compiled patterns to string patterns for our use
            pattern_str = pattern_obj.pattern
            self.prohibited_patterns.append(re.compile(pattern_str))
        
        # Add keyword lists from llm_injection_patterns
        for category, keywords in INJECTION_KEYWORD_LISTS.items():
            for keyword in keywords:
                self.prohibited_words.add(keyword.lower())
        
        # Add known jailbreak patterns
        for pattern_str in KNOWN_JAILBREAK_PATTERNS:
            # Get the pattern string from the compiled regex
            pattern_string = pattern_str.pattern
            # Remove the (?i).* prefix/suffix typical in these patterns
            clean_pattern = pattern_string.replace("(?i).*", "").replace(".*", "")
            if clean_pattern:  # Only add if we have something meaningful left
                self.prohibited_patterns.append(re.compile(clean_pattern, re.IGNORECASE))
    
    def _load_custom_patterns(self, path: str) -> None:
        """
        Load custom patterns from a JSON file.
        
        Args:
            path: Path to the JSON file containing custom patterns
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                custom_patterns = json.load(f)
            
            # Load custom words
            if 'prohibited_words' in custom_patterns:
                for word in custom_patterns['prohibited_words']:
                    self.prohibited_words.add(word.lower())
            
            # Load custom patterns
            if 'prohibited_patterns' in custom_patterns:
                for pattern in custom_patterns['prohibited_patterns']:
                    try:
                        self.prohibited_patterns.append(re.compile(pattern, re.IGNORECASE))
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            
            logger.info(f"Loaded custom patterns from {path}")
        except Exception as e:
            logger.error(f"Error loading custom patterns from {path}: {e}")
    
    def save_custom_patterns(self, path: str) -> None:
        """
        Save current patterns to a JSON file.
        
        Args:
            path: Path to save the JSON file
        """
        try:
            patterns_dict = {
                'prohibited_words': list(self.prohibited_words),
                'prohibited_patterns': [p.pattern for p in self.prohibited_patterns]
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(patterns_dict, f, indent=2)
            
            logger.info(f"Saved patterns to {path}")
        except Exception as e:
            logger.error(f"Error saving patterns to {path}: {e}")
    
    def update_prohibited_list(self, item: str, action: str = "add", item_type: str = "word") -> bool:
        """
        Update the prohibited words or patterns list.
        
        Args:
            item: Word or pattern to add/remove
            action: Action to perform ('add' or 'remove')
            item_type: Type of item ('word' or 'pattern')
            
        Returns:
            Success status of the operation
        """
        if action not in ["add", "remove"]:
            logger.error(f"Invalid action: {action}. Must be 'add' or 'remove'")
            return False
        
        if item_type not in ["word", "pattern"]:
            logger.error(f"Invalid item type: {item_type}. Must be 'word' or 'pattern'")
            return False
        
        try:
            if item_type == "word":
                if action == "add":
                    self.prohibited_words.add(item.lower())
                else:  # remove
                    self.prohibited_words.discard(item.lower())
            else:  # pattern
                if action == "add":
                    try:
                        pattern = re.compile(item, re.IGNORECASE)
                        self.prohibited_patterns.append(pattern)
                    except re.error as e:
                        logger.error(f"Invalid regex pattern: {e}")
                        return False
                else:  # remove
                    # Find and remove the pattern with the same string representation
                    self.prohibited_patterns = [p for p in self.prohibited_patterns 
                                              if p.pattern != item]
            return True
        except Exception as e:
            logger.error(f"Error updating prohibited list: {e}")
            return False
    
    def check_input(self, text: str, threshold: float = 0.6) -> Optional[str]:
        """
        Check if input text contains prohibited words or patterns.
        Enhanced with checks from filtering_patterns if available.
        
        Args:
            text: Text to check
            threshold: Similarity threshold for fuzzy matching
            
        Returns:
            Warning message if prohibited content is found, None otherwise
        """
        if not text:
            return None
        
        # Convert to lowercase for case-insensitive matching
        text_lower = text.lower()
        
        # Check for exact prohibited word matches
        for word in self.prohibited_words:
            if word in text_lower:
                return f"Prohibited word detected: '{word}'"
        
        # Check for prohibited pattern matches
        for pattern in self.prohibited_patterns:
            match = pattern.search(text)
            if match:
                match_text = match.group(0)
                return f"Prohibited pattern detected: '{match_text}'"
        
        # Advanced check using filtering_patterns if available
        if FILTERING_PATTERNS_AVAILABLE:
            injection_results = check_text_for_injections(text)
            if injection_results:
                # Get first detected injection
                for category, matches in injection_results.items():
                    if matches:
                        if isinstance(matches[0], tuple):
                            match_text = " ".join(matches[0])
                        else:
                            match_text = str(matches[0])
                        return f"Potential injection detected ({category}): '{match_text}'"
        
        return None
    
    def sanitize_input(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Sanitize input by detecting and masking prohibited content.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Tuple of (sanitized text, list of detected issues)
        """
        if not text:
            return text, []
        
        detected_issues = []
        sanitized_text = text
        text_lower = text.lower()
        
        # Check and mask prohibited words
        for word in self.prohibited_words:
            if word in text_lower:
                # Record the issue
                detected_issues.append({
                    "type": "prohibited_word",
                    "content": word,
                    "start_pos": text_lower.find(word)
                })
                # Replace with asterisks
                sanitized_text = sanitized_text.replace(word, '*' * len(word))
        
        # Check and mask prohibited patterns
        for pattern in self.prohibited_patterns:
            for match in pattern.finditer(sanitized_text):
                match_text = match.group(0)
                # Record the issue
                detected_issues.append({
                    "type": "prohibited_pattern",
                    "content": match_text,
                    "start_pos": match.start()
                })
                # Replace with asterisks
                sanitized_text = sanitized_text[:match.start()] + ('*' * len(match_text)) + sanitized_text[match.end():]
        
        return sanitized_text, detected_issues


class CustomPatternManager:
    """
    Manager for user-defined custom patterns.
    """
    
    def __init__(self, base_directory: Optional[str] = None):
        """
        Initialize the custom pattern manager.
        
        Args:
            base_directory: Base directory for storing custom patterns
        """
        if base_directory:
            self.base_directory = Path(base_directory)
        else:
            # Default to user's home directory
            self.base_directory = Path.home() / ".resk_llm" / "custom_patterns"
        
        # Create directory if it doesn't exist
        self.base_directory.mkdir(parents=True, exist_ok=True)
    
    def create_custom_pattern_file(self, name: str, words: Optional[List[str]] = None, 
                                  patterns: Optional[List[str]] = None) -> str:
        """
        Create a new custom pattern file.
        
        Args:
            name: Name for the custom pattern file
            words: List of prohibited words
            patterns: List of prohibited patterns
            
        Returns:
            Path to the created file
        """
        if words is None:
            words = []
        if patterns is None:
            patterns = []
        
        # Sanitize name for file system
        name = "".join(c for c in name if c.isalnum() or c in "._- ").strip()
        name = name.replace(" ", "_")
        
        if not name:
            name = "custom_patterns"
        
        file_path = self.base_directory / f"{name}.json"
        
        # Create pattern dictionary
        pattern_dict = {
            "prohibited_words": words,
            "prohibited_patterns": patterns
        }
        
        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(pattern_dict, f, indent=2)
        
        return str(file_path)
    
    def list_custom_pattern_files(self) -> List[str]:
        """
        List all available custom pattern files.
        
        Returns:
            List of file paths
        """
        pattern_files = list(self.base_directory.glob("*.json"))
        return [str(path) for path in pattern_files]
    
    def load_custom_pattern_file(self, name: str) -> Dict[str, List[str]]:
        """
        Load a custom pattern file by name.
        
        Args:
            name: Name of the custom pattern file (without .json extension)
            
        Returns:
            Dictionary containing the patterns
        """
        if not name.endswith(".json"):
            name = f"{name}.json"
        
        file_path = self.base_directory / name
        
        if not file_path.exists():
            raise FileNotFoundError(f"Custom pattern file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def delete_custom_pattern_file(self, name: str) -> bool:
        """
        Delete a custom pattern file.
        
        Args:
            name: Name of the custom pattern file (without .json extension)
            
        Returns:
            Whether the file was successfully deleted
        """
        if not name.endswith(".json"):
            name = f"{name}.json"
        
        file_path = self.base_directory / name
        
        if not file_path.exists():
            return False
        
        file_path.unlink()
        return True


class ReskProtectorTokenizer:
    """
    Enhanced tokenizer protector that integrates with improved ReskWordsLists.
    """
    
    def __init__(self, 
                 tokenizer: PreTrainedTokenizer,
                 custom_patterns_path: Optional[str] = None):
        """
        Initialize the tokenizer protector.
        
        Args:
            tokenizer: Hugging Face tokenizer to protect
            custom_patterns_path: Optional path to custom patterns JSON file
        """
        self.tokenizer = tokenizer
        self.specials_tokens_identifiers = self._get_special_tokens()
        self.special_tokens_ids = [tokenizer.convert_tokens_to_ids(token) for token in self.specials_tokens_identifiers]
        
        # Initialize the prohibited words/patterns checker
        self.checker = ReskWordsLists(
            custom_patterns_path=custom_patterns_path,
            use_default_patterns=True,
            load_filtering_patterns=True
        )
    
    def _get_special_tokens(self) -> List[str]:
        """
        Get special tokens from the tokenizer.
        
        Returns:
            List of special tokens
        """
        specials = []
        
        # Get special tokens from tokenizer attributes
        for attr in ['bos_token', 'eos_token', 'unk_token', 'sep_token', 'pad_token', 'cls_token', 'mask_token']:
            if hasattr(self.tokenizer, attr) and getattr(self.tokenizer, attr) is not None:
                token = getattr(self.tokenizer, attr)
                if token:
                    specials.append(token)
        
        # Add OpenAI special tokens
        specials.extend(OPENAI_SPECIAL_TOKENS)
        
        return specials
    
    def check_and_protect(self, text: str) -> Tuple[str, bool, Optional[str]]:
        """
        Check and protect the input text.
        
        Args:
            text: Input text to check and protect
            
        Returns:
            Tuple of (sanitized text, whether malicious content was detected, warning message)
        """
        # Check for prohibited content
        warning = self.checker.check_input(text)
        
        if warning:
            # Sanitize the input if prohibited content is detected
            sanitized_text, _ = self.checker.sanitize_input(text)
            return sanitized_text, True, warning
        
        # No prohibited content found
        return text, False, None
    
    def add_custom_prohibited_item(self, item: str, item_type: str = "word") -> bool:
        """
        Add a custom prohibited word or pattern.
        
        Args:
            item: Word or pattern to prohibit
            item_type: Type of item ('word' or 'pattern')
            
        Returns:
            Success status
        """
        return self.checker.update_prohibited_list(item, "add", item_type)
    
    def remove_prohibited_item(self, item: str, item_type: str = "word") -> bool:
        """
        Remove a prohibited word or pattern.
        
        Args:
            item: Word or pattern to remove from prohibited list
            item_type: Type of item ('word' or 'pattern')
            
        Returns:
            Success status
        """
        return self.checker.update_prohibited_list(item, "remove", item_type)
    
    def save_current_patterns(self, path: str) -> None:
        """
        Save current prohibited patterns to a file.
        
        Args:
            path: Path to save the patterns
        """
        self.checker.save_custom_patterns(path)
    
    def encode(self, text: str, **kwargs) -> Dict[str, Any]:
        """
        Encode text with protection against prohibited content.
        
        Args:
            text: Text to encode
            kwargs: Additional arguments to pass to the tokenizer
            
        Returns:
            Dictionary with encoding results and status
        """
        # Check and sanitize the input
        sanitized_text, is_malicious, warning = self.check_and_protect(text)
        
        # Encode the sanitized text
        encoding = self.tokenizer.encode_plus(sanitized_text, **kwargs)
        
        # Add status information to the result
        result = {
            "encoding": encoding,
            "is_malicious": is_malicious,
            "warning": warning,
            "sanitized_text": sanitized_text if is_malicious else text
        }
        
        return result
    
    def decode(self, token_ids: List[int], **kwargs) -> str:
        """
        Decode token IDs to text.
        
        Args:
            token_ids: Token IDs to decode
            kwargs: Additional arguments to pass to the tokenizer
            
        Returns:
            Decoded text
        """
        # Remove special tokens that could be used for injection
        filtered_ids = [token_id for token_id in token_ids if token_id not in self.special_tokens_ids]
        
        # Decode the filtered tokens
        text = self.tokenizer.decode(filtered_ids, **kwargs)
        
        return text


class TokenizerProtector:
    """
    Wrapper autour de ReskProtectorTokenizer pour la compatibilité avec le code existant.
    Cette classe protège un tokenizer Hugging Face contre les tentatives d'injection et le contenu malveillant.
    """
    
    def __init__(self, tokenizer: PreTrainedTokenizer, custom_patterns_path: Optional[str] = None):
        """
        Initialise le protecteur de tokenizer.
        
        Args:
            tokenizer: Le tokenizer Hugging Face à protéger
            custom_patterns_path: Chemin vers un fichier de patterns personnalisés (optionnel)
        """
        self.tokenizer = tokenizer
        self.secure_tokenizer = ReskProtectorTokenizer(tokenizer, custom_patterns_path)
        self.resk_words_lists = self.secure_tokenizer.checker
        
    def __call__(self, text: str, **kwargs) -> str:
        """
        Traite un texte avec le tokenizer sécurisé et renvoie le résultat au format JSON.
        
        Args:
            text: Le texte à tokenizer
            kwargs: Arguments supplémentaires à passer au tokenizer
            
        Returns:
            Résultat au format JSON
        """
        try:
            # Vérifier et protéger le texte
            cleaned_text, is_modified, warning = self.secure_tokenizer.check_and_protect(text)
            
            if warning:
                return json.dumps({
                    "status": "warning",
                    "message": warning,
                    "is_modified": is_modified,
                    "original_text": text,
                    "modified_text": cleaned_text
                })
            
            # Encoder le texte
            result = self.secure_tokenizer.encode(cleaned_text, **kwargs)
            
            # Ajouter des méta-informations
            result.update({
                "status": "success",
                "is_modified": is_modified,
                "original_text": text
            })
            
            if is_modified:
                result["modified_text"] = cleaned_text
                
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e),
                "original_text": text
            })
            
class SecureTokenizer:
    """
    Classe de compatibilité pour maintenir la rétrocompatibilité avec le code existant.
    """
    
    def __init__(self, tokenizer: PreTrainedTokenizer, resk_words_lists: Optional[ReskWordsLists] = None):
        """
        Initialise le tokenizer sécurisé.
        
        Args:
            tokenizer: Le tokenizer Hugging Face à sécuriser
            resk_words_lists: Instance de ReskWordsLists (optionnel)
        """
        self.tokenizer = tokenizer
        self.resk_words_lists = resk_words_lists or ReskWordsLists()
        
    def encode(self, text: str, **kwargs) -> Dict[str, Any]:
        """
        Encode un texte avec le tokenizer sécurisé.
        
        Args:
            text: Le texte à encoder
            kwargs: Arguments supplémentaires pour le tokenizer
            
        Returns:
            Résultat de l'encodage
        """
        # Nettoyer le texte
        cleaned_text, modifications = self.resk_words_lists.sanitize_input(text)
        
        # Encoder avec le tokenizer original
        encoding = self.tokenizer(cleaned_text, **kwargs)
        
        # Convertir en dictionnaire si nécessaire
        if not isinstance(encoding, dict):
            encoding = {
                "input_ids": encoding.input_ids,
                "attention_mask": encoding.attention_mask
            }
            
        # Ajouter les tokens
        tokens = self.tokenizer.convert_ids_to_tokens(encoding["input_ids"])
        
        return {
            "tokens": tokens,
            "num_tokens": len(tokens),
            "tokenizer_output": encoding,
            "modifications": modifications
        }
        
    def decode(self, token_ids: List[int], **kwargs) -> str:
        """
        Décode des token_ids vers du texte.
        
        Args:
            token_ids: Les IDs de tokens à décoder
            kwargs: Arguments supplémentaires pour le décodeur
            
        Returns:
            Texte décodé
        """
        return self.tokenizer.decode(token_ids, **kwargs)