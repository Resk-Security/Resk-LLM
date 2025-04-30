"""
Hugging Face integration module for securing LLM interactions.

This module provides classes and utilities to secure Hugging Face models
and transformers, implementing protection mechanisms for inputs and outputs.
"""

import re
import logging
import warnings
from typing import Dict, List, Any, Optional, Union, Callable, TypeVar, Type, cast, Any

from transformers import AutoTokenizer, PreTrainedTokenizer
from PIL import Image

from resk_llm.tokenizer_protection import ReskWordsLists
from resk_llm.filtering_patterns import check_for_obfuscation, sanitize_text_from_obfuscation
from resk_llm.core.abc import ProtectorBase

# Type definitions
HuggingFaceProtectorConfig = Dict[str, Any]
MultiModalProtectorConfig = Dict[str, Any]

# Logger configuration
logger = logging.getLogger(__name__)

class HuggingFaceProtector(ProtectorBase[str, str, HuggingFaceProtectorConfig]):
    """
    Protector for Hugging Face text models.
    
    This class provides protection mechanisms for Hugging Face text models,
    implementing input and output sanitization to prevent prompt injections
    and other security issues.
    """
    
    def __init__(self, config: Optional[HuggingFaceProtectorConfig] = None):
        """
        Initialize the Hugging Face protector.
        
        Args:
            config: Configuration dictionary which may contain:
                model_name: Model name to use for tokenization (e.g. "gpt2")
                max_tokens: Maximum tokens allowed in input
                enable_detection: Enable detection of malicious content
                enable_sanitization: Enable sanitization of inputs
                tokenizer: Custom tokenizer to use
        """
        default_config: HuggingFaceProtectorConfig = {
            'model_name': 'gpt2',
            'max_tokens': 4096,
            'enable_detection': True,
            'enable_sanitization': True,
            'tokenizer': None
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        # Initialize properties from config
        self.model_name = self.config.get('model_name', 'gpt2')
        self.max_tokens = self.config.get('max_tokens', 4096)
        self.enable_detection = self.config.get('enable_detection', True)
        self.enable_sanitization = self.config.get('enable_sanitization', True)
        
        # Initialize tokenizer
        self.tokenizer = self.config.get('tokenizer')
        if self.tokenizer is None:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            except Exception as e:
                warnings.warn(f"Could not load tokenizer for {self.model_name}: {str(e)}")
                self.tokenizer = None
        
        # Initialize ReskWordsLists
        self.resk_words_lists = ReskWordsLists()
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if not isinstance(self.config.get('model_name', 'gpt2'), str):
            raise ValueError("model_name must be a string")
            
        if not isinstance(self.config.get('max_tokens', 4096), int):
            raise ValueError("max_tokens must be an integer")
            
        if not isinstance(self.config.get('enable_detection', True), bool):
            raise ValueError("enable_detection must be a boolean")
            
        if not isinstance(self.config.get('enable_sanitization', True), bool):
            raise ValueError("enable_sanitization must be a boolean")
            
        if 'tokenizer' in self.config and self.config['tokenizer'] is not None:
            if not isinstance(self.config['tokenizer'], PreTrainedTokenizer):
                raise ValueError("tokenizer must be a PreTrainedTokenizer or None")
    
    def update_config(self, config: HuggingFaceProtectorConfig) -> None:
        """Update the configuration with new values."""
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if 'model_name' in config:
            self.model_name = config['model_name']
            if 'tokenizer' not in config:
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                except Exception as e:
                    warnings.warn(f"Could not load tokenizer for {self.model_name}: {str(e)}")
        
        if 'max_tokens' in config:
            self.max_tokens = config['max_tokens']
        
        if 'enable_detection' in config:
            self.enable_detection = config['enable_detection']
        
        if 'enable_sanitization' in config:
            self.enable_sanitization = config['enable_sanitization']
        
        if 'tokenizer' in config:
            self.tokenizer = config['tokenizer']
    
    def protect(self, text: str) -> str:
        """
        Main protection method required by ProtectorBase.
        Sanitizes and checks the input text for malicious content.
        
        Args:
            text: Input text to protect
            
        Returns:
            Protected version of the input text
            
        Raises:
            ValueError: If the input contains malicious content and detection is enabled
        """
        sanitized_text = text
        
        # Check for obfuscation (hidden characters, unicode tricks, etc.)
        obfuscation = check_for_obfuscation(text)
        if obfuscation:
            sanitized_text = sanitize_text_from_obfuscation(text)
        
        # Apply sanitization if enabled
        if self.enable_sanitization:
            sanitized_text = self.sanitize_input(sanitized_text)
        
        # Check for malicious content if detection is enabled
        if self.enable_detection:
            warning = self.resk_words_lists.check_input(sanitized_text)
            if warning:
                raise ValueError(f"Malicious content detected: {warning}")
        
        # Check token length if tokenizer is available
        if self.tokenizer:
            tokens = self.tokenizer.encode(sanitized_text)
            if len(tokens) > self.max_tokens:
                warnings.warn(f"Input exceeds maximum token length ({len(tokens)} > {self.max_tokens})")
                sanitized_text = self.tokenizer.decode(tokens[:self.max_tokens])
        
        return sanitized_text
    
    def sanitize_input(self, text: str) -> str:
        """
        Sanitize the input text.
        
        Args:
            text: Input text to sanitize
            
        Returns:
            Sanitized text
        """
        # Basic sanitization: remove control characters and zero-width spaces
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u2028-\u202F\u2060-\u206F]', '', text)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Remove potential HTML/XML tags
        sanitized = re.sub(r'<[^>]*>', '', sanitized)
        
        return sanitized
    
    def tokenize(self, text: str) -> List[int]:
        """
        Tokenize the input text.
        
        Args:
            text: Input text to tokenize
            
        Returns:
            List of token IDs
            
        Raises:
            ValueError: If tokenizer is not initialized
        """
        if self.tokenizer is None:
            raise ValueError("Tokenizer not initialized")
        
        return self.tokenizer.encode(text)
    
    def detokenize(self, tokens: List[int]) -> str:
        """
        Convert tokens back to text.
        
        Args:
            tokens: List of token IDs
            
        Returns:
            Decoded text
            
        Raises:
            ValueError: If tokenizer is not initialized
        """
        if self.tokenizer is None:
            raise ValueError("Tokenizer not initialized")
        
        return self.tokenizer.decode(tokens)
    
    def check_for_forbidden_words(self, text: str) -> Optional[str]:
        """
        Check if the text contains forbidden words.
        
        Args:
            text: Text to check
            
        Returns:
            Warning message if forbidden words are found, None otherwise
        """
        return self.resk_words_lists.check_input(text)

    # Implementation for abstract methods
    def protect_input(self, prompt: str, **kwargs) -> str:
        """Apply security measures to the input before sending to the LLM."""
        # Delegate to the existing protect method for input protection
        return self.protect(prompt)

    def protect_output(self, response: str, **kwargs) -> str:
        """Apply security measures to the output received from the LLM."""
        # Basic sanitization for output, can be expanded
        if self.enable_sanitization:
             return self.sanitize_input(response)
        return response


class MultiModalProtector(ProtectorBase[Union[str, Image.Image, Dict[str, Any]], Union[str, Dict[str, Any]], MultiModalProtectorConfig]):
    """
    Protector for multi-modal models that handle both text and images.
    
    This class extends protection to multi-modal models that handle both
    text and visual inputs, with specific protection mechanisms for each modality.
    """
    
    def __init__(self, config: Optional[MultiModalProtectorConfig] = None):
        """
        Initialize the multi-modal protector.
        
        Args:
            config: Configuration dictionary which may contain:
                text_model: Model name for text protection
                max_tokens: Maximum tokens allowed in input
                enable_text_detection: Enable detection for text inputs
                enable_text_sanitization: Enable sanitization for text inputs
                enable_image_sanitization: Enable sanitization for image inputs
                text_tokenizer: Custom tokenizer for text
        """
        default_config: MultiModalProtectorConfig = {
            'text_model': 'gpt2',
            'max_tokens': 4096,
            'enable_text_detection': True,
            'enable_text_sanitization': True,
            'enable_image_sanitization': True,
            'text_tokenizer': None
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        # Initialize properties from config
        self.text_model = self.config.get('text_model', 'gpt2')
        self.max_tokens = self.config.get('max_tokens', 4096)
        self.enable_text_detection = self.config.get('enable_text_detection', True)
        self.enable_text_sanitization = self.config.get('enable_text_sanitization', True)
        self.enable_image_sanitization = self.config.get('enable_image_sanitization', True)
        
        # Initialize text protector
        self.text_protector = HuggingFaceProtector({
            'model_name': self.text_model,
            'max_tokens': self.max_tokens,
            'enable_detection': self.enable_text_detection,
            'enable_sanitization': self.enable_text_sanitization,
            'tokenizer': self.config.get('text_tokenizer')
        })
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if not isinstance(self.config.get('text_model', 'gpt2'), str):
            raise ValueError("text_model must be a string")
            
        if not isinstance(self.config.get('max_tokens', 4096), int):
            raise ValueError("max_tokens must be an integer")
            
        if not isinstance(self.config.get('enable_text_detection', True), bool):
            raise ValueError("enable_text_detection must be a boolean")
            
        if not isinstance(self.config.get('enable_text_sanitization', True), bool):
            raise ValueError("enable_text_sanitization must be a boolean")
            
        if not isinstance(self.config.get('enable_image_sanitization', True), bool):
            raise ValueError("enable_image_sanitization must be a boolean")
    
    def update_config(self, config: MultiModalProtectorConfig) -> None:
        """Update the configuration with new values."""
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if 'text_model' in config:
            self.text_model = config['text_model']
        
        if 'max_tokens' in config:
            self.max_tokens = config['max_tokens']
        
        if 'enable_text_detection' in config:
            self.enable_text_detection = config['enable_text_detection']
        
        if 'enable_text_sanitization' in config:
            self.enable_text_sanitization = config['enable_text_sanitization']
        
        if 'enable_image_sanitization' in config:
            self.enable_image_sanitization = config['enable_image_sanitization']
        
        # Recreate text protector with updated config
        updated_text_config = {
            'model_name': self.text_model,
            'max_tokens': self.max_tokens,
            'enable_detection': self.enable_text_detection,
            'enable_sanitization': self.enable_text_sanitization
        }
        
        if 'text_tokenizer' in config:
            updated_text_config['tokenizer'] = config['text_tokenizer']
        
        self.text_protector.update_config(updated_text_config)
    
    # Implementation for abstract methods
    def protect_input(self, prompt: Any, **kwargs) -> Any:
        """Apply security measures to the input before sending to the LLM."""
        # Add type checking internally
        if not isinstance(prompt, (str, Image.Image, dict)):
             logger.warning(f"MultiModalProtector received unsupported input type: {type(prompt)}. Passing through.")
             return prompt
             
        # Delegate to the existing protect method for input protection
        return self.protect(prompt)

    def protect_output(self, response: Union[str, Dict[str, Any]], **kwargs) -> Union[str, Dict[str, Any]]:
        """Apply security measures to the output received from the LLM."""
        # Handle different output types
        if isinstance(response, str):
            return self.sanitize_text(response) # Use the class's sanitize_text
        elif isinstance(response, dict):
            # Basic protection for dictionary outputs (e.g., text fields)
            return self._protect_dict(response) # Use the existing dict protection logic
        else:
            # Pass through unknown types
            return response

    def protect(self, data: Union[str, Image.Image, Dict[str, Any]]) -> Union[str, Image.Image, Dict[str, Any]]:
        """
        Main protection method required by ProtectorBase.
        Provides appropriate protection based on input type.
        
        Args:
            data: Input data to protect (text, image, or dictionary with both)
            
        Returns:
            Protected version of the input
            
        Raises:
            ValueError: If the input contains malicious content
            TypeError: If the input type is not supported
        """
        # Handle text input
        if isinstance(data, str):
            return self.text_protector.protect(data)
        
        # Handle image input
        elif isinstance(data, Image.Image):
            return self._protect_image(data)
        
        # Handle dictionary input (common for multi-modal models)
        elif isinstance(data, dict):
            return self._protect_dict(data)
        
        # Unsupported input type
        else:
            raise TypeError(f"Unsupported input type: {type(data)}")
    
    def _protect_image(self, image: Image.Image) -> Image.Image:
        """
        Protect an image input.
        
        Args:
            image: Input image to protect
            
        Returns:
            Protected image
        """
        # Currently a placeholder for image sanitization
        # Real implementation would check for steganography, metadata, etc.
        if self.enable_image_sanitization:
            # Remove EXIF and other metadata
            data = list(image.getdata())
            clean_img = Image.new(image.mode, image.size)
            clean_img.putdata(data)
            return clean_img
        
        return image
    
    def _protect_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Protect a dictionary containing multi-modal data.
        
        Args:
            data: Dictionary containing text and/or image data
            
        Returns:
            Protected dictionary
        """
        result: Dict[str, Any] = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.text_protector.protect(value)
            elif isinstance(value, Image.Image):
                result[key] = self._protect_image(value)
            elif isinstance(value, dict):
                result[key] = self._protect_dict(value)
            elif isinstance(value, list):
                result[key] = self._protect_list(value)
            else:
                result[key] = value
        
        return result
    
    def _protect_list(self, data: List[Any]) -> List[Any]:
        """
        Protect a list containing multi-modal data.
        
        Args:
            data: List containing text and/or image data
            
        Returns:
            Protected list
        """
        result: List[Any] = []
        
        for item in data:
            if isinstance(item, str):
                result.append(self.text_protector.protect(item))
            elif isinstance(item, Image.Image):
                result.append(self._protect_image(item))
            elif isinstance(item, dict):
                result.append(self._protect_dict(item))
            elif isinstance(item, list):
                result.append(self._protect_list(item))
            else:
                result.append(item)
        
        return result
    
    def sanitize_text(self, text: str) -> str:
        """
        Sanitize text input.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text
        """
        return self.text_protector.sanitize_input(text)


# Factory function to create an appropriate protector based on model type
def create_huggingface_protector(
    model_name: str,
    is_multimodal: bool = False,
    config: Optional[Dict[str, Any]] = None
) -> Union[HuggingFaceProtector, MultiModalProtector]:
    """
    Create a Hugging Face protector based on model type.
    
    Args:
        model_name: Name of the Hugging Face model
        is_multimodal: Whether the model is multi-modal
        config: Additional configuration options
        
    Returns:
        An appropriate protector instance for the model
    """
    if not config:
        config = {}
    
    if is_multimodal:
        mm_config: MultiModalProtectorConfig = {
            'text_model': model_name,
            **config
        }
        return MultiModalProtector(mm_config)
    else:
        hf_config: HuggingFaceProtectorConfig = {
            'model_name': model_name,
            **config
        }
        return HuggingFaceProtector(hf_config) 