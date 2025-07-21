"""
LangChain integration module for securing LLM interactions.

This module provides classes and utilities to protect LangChain components,
implementing protection mechanisms for inputs and outputs to prevent prompt injections.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Type, cast

from langchain.chains.base import Chain
from langchain.schema import BasePromptTemplate, PromptValue
from langchain.schema.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage

from resk_llm.core.abc import ProtectorBase, FilterBase, DetectorBase
from resk_llm.filters.resk_word_list_filter import RESK_WordListFilter
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider

# Type definitions
LangChainProtectorConfig = Dict[str, Any]

# Logger configuration
logger = logging.getLogger(__name__)

class LangChainProtector(ProtectorBase[Union[BasePromptTemplate, Chain, BaseMessage, str], 
                                      Union[BasePromptTemplate, Chain, BaseMessage, str],
                                      LangChainProtectorConfig]):
    """
    Protector for LangChain components.
    
    This class provides protection mechanisms for LangChain components,
    implementing input and output sanitization to prevent prompt injections
    and other security issues.
    """
    
    def __init__(self, config: Optional[LangChainProtectorConfig] = None):
        """
        Initialize the LangChain protector.
        
        Args:
            config: Configuration dictionary which may contain:
                enable_detection: Enable detection of malicious content
                enable_sanitization: Enable sanitization of inputs
                protected_variable_pattern: Regex pattern for protected variables
                block_protected_variables: Whether to block requests with protected variables
        """
        default_config: LangChainProtectorConfig = {
            'enable_detection': True,
            'enable_sanitization': True,
            'protected_variable_pattern': r'\${{\s*secrets\..+?\s*}}',
            'block_protected_variables': True
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        # Initialize properties from config
        self.enable_detection = self.config.get('enable_detection', True)
        self.enable_sanitization = self.config.get('enable_sanitization', True)
        self.protected_variable_pattern = self.config.get('protected_variable_pattern', r'\${{\s*secrets\..+?\s*}}')
        self.block_protected_variables = self.config.get('block_protected_variables', True)
        
        # Initialize ReskWordsLists
        provider = FileSystemPatternProvider() # Needs proper config source
        filter_config = self.config.get('word_list_filter_config', {'pattern_provider': provider})
        self.resk_words_lists = RESK_WordListFilter(config=filter_config)
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if not isinstance(self.config.get('enable_detection', True), bool):
            raise ValueError("enable_detection must be a boolean")
            
        if not isinstance(self.config.get('enable_sanitization', True), bool):
            raise ValueError("enable_sanitization must be a boolean")
            
        if not isinstance(self.config.get('block_protected_variables', True), bool):
            raise ValueError("block_protected_variables must be a boolean")
            
        pattern = self.config.get('protected_variable_pattern', r'\${{\s*secrets\..+?\s*}}')
        if not isinstance(pattern, str):
            raise ValueError("protected_variable_pattern must be a string")
        try:
            re.compile(pattern)
        except re.error:
            raise ValueError(f"Invalid regex pattern: {pattern}")
    
    def update_config(self, config: LangChainProtectorConfig) -> None:
        """Update the configuration with new values."""
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if 'enable_detection' in config:
            self.enable_detection = config['enable_detection']
        
        if 'enable_sanitization' in config:
            self.enable_sanitization = config['enable_sanitization']
        
        if 'protected_variable_pattern' in config:
            self.protected_variable_pattern = config['protected_variable_pattern']
        
        if 'block_protected_variables' in config:
            self.block_protected_variables = config['block_protected_variables']
    
    def create_secure_chain(self, chain: Chain) -> Chain:
        """
        Create a secure version of a LangChain chain.
        
        Args:
            chain: Original LangChain chain
            
        Returns:
            Protected chain with security measures
        """
        return self._protect_chain(chain)
    
    def validate_prompt(self, prompt: Union[str, BasePromptTemplate, BaseMessage]) -> Dict[str, Any]:
        """
        Validate a prompt for security issues.
        
        Args:
            prompt: Prompt to validate
            
        Returns:
            Dictionary with validation results
        """
        try:
            is_valid = False
            issues = []
            
            if isinstance(prompt, str):
                is_valid = self._validate_text(prompt)
                if not is_valid:
                    issues.append("Text validation failed")
            elif isinstance(prompt, BaseMessage):
                is_valid = self._validate_message(prompt)
                if not is_valid:
                    issues.append("Message validation failed")
            elif isinstance(prompt, BasePromptTemplate):
                is_valid = self._validate_prompt_template(prompt)
                if not is_valid:
                    issues.append("Prompt template validation failed")
            else:
                is_valid = True
            
            return {
                'valid': is_valid,
                'is_safe': is_valid,  # For backward compatibility
                'issues': issues,
                'prompt_type': type(prompt).__name__
            }
        except Exception as e:
            logger.error(f"Error validating prompt: {e}")
            return {
                'valid': False,
                'is_safe': False,  # For backward compatibility
                'issues': [f"Validation error: {str(e)}"],
                'prompt_type': type(prompt).__name__ if prompt else 'unknown'
            }
    
    def create_secure_agent(self, agent: Any = None, agent_class: Any = None, agent_type: str = "default", tools: Optional[List[Any]] = None, llm: Optional[Any] = None) -> Any:
        """
        Create a secure version of a LangChain agent.
        
        Args:
            agent: Original LangChain agent (optional)
            agent_class: Agent class to instantiate (optional)
            agent_type: Type of agent to create (optional)
            
        Returns:
            Protected agent with security measures
        """
        # If agent_class is provided, instantiate it
        if agent_class is not None and agent is None:
            try:
                agent = agent_class()
            except Exception as e:
                logger.error(f"Failed to instantiate agent class: {e}")
                return None
        
        # If tools and llm are provided but no agent, create a mock agent
        if agent is None and tools is not None and llm is not None:
            class MockAgent:
                def __init__(self, tools, llm):
                    self.tools = tools
                    self.llm = llm
                
                def run(self, *args, **kwargs):
                    return "Mock agent response"
            
            agent = MockAgent(tools, llm)
        
        if agent is None:
            logger.warning("No agent or agent_class provided")
            return None
        
        # This is a simplified implementation
        # In a real implementation, you would wrap the agent's methods
        # to add security checks before and after execution
        
        class SecureAgent:
            def __init__(self, original_agent: Any, protector: 'LangChainProtector', agent_type: str = "default"):
                self.original_agent = original_agent
                self.protector = protector
                self.agent_type = agent_type
            
            def __getattr__(self, name: str):
                # Delegate to original agent for most attributes
                return getattr(self.original_agent, name)
            
            def run(self, *args, **kwargs):
                # Protect inputs before running
                protected_args = [self.protector.protect_input(arg) for arg in args]
                protected_kwargs = {k: self.protector.protect_input(v) for k, v in kwargs.items()}
                
                # Run the original agent
                result = self.original_agent.run(*protected_args, **protected_kwargs)
                
                # Protect outputs
                return self.protector.protect_output(result)
        
        return SecureAgent(agent, self, agent_type)
    
    def _validate_text(self, text: str) -> bool:
        """Validate text content for security issues."""
        if not text:
            return True
        
        # Check for protected variables
        if self.block_protected_variables and re.search(self.protected_variable_pattern, text):
            return False
        
        # Check for injection patterns
        injection_patterns = [
            r'ignore\s+previous\s+instructions',
            r'forget\s+all\s+rules',
            r'bypass\s+security',
            r'<script',
            r'javascript:',
            r'eval\s*\(',
            r'exec\s*\('
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False
        
        return True
    
    def _validate_message(self, message: BaseMessage) -> bool:
        """Validate LangChain message for security issues."""
        if hasattr(message, 'content'):
            return self._validate_text(str(message.content))
        return True
    
    def _validate_prompt_template(self, template: BasePromptTemplate) -> bool:
        """Validate LangChain prompt template for security issues."""
        if hasattr(template, 'template'):
            return self._validate_text(template.template)
        return True
    
    def protect(self, component: Union[BasePromptTemplate, Chain, BaseMessage, str]) -> Union[BasePromptTemplate, Chain, BaseMessage, str]:
        """
        Main protection method required by ProtectorBase.
        Protects LangChain components based on their type.
        
        Args:
            component: LangChain component to protect
            
        Returns:
            Protected version of the component
            
        Raises:
            ValueError: If the input contains malicious content and detection is enabled
            TypeError: If the component type is not supported
        """
        if isinstance(component, BasePromptTemplate):
            return self._protect_prompt_template(component)
        elif isinstance(component, Chain):
            return self._protect_chain(component)
        elif isinstance(component, BaseMessage):
            return self._protect_message(component)
        elif isinstance(component, str):
            return self._protect_text(component)
        else:
            raise TypeError(f"Unsupported component type: {type(component)}")
    
    def _protect_text(self, text: str) -> str:
        """
        Protect a text string.
        
        Args:
            text: Text to protect
            
        Returns:
            Protected text
            
        Raises:
            ValueError: If the text contains malicious content and detection is enabled
        """
        # Check for protected variables
        if self.block_protected_variables and re.search(self.protected_variable_pattern, text):
            raise ValueError("Detected attempt to access protected variables")
        
        # Apply sanitization if enabled
        if self.enable_sanitization:
            text = self.sanitize_input(text)
        
        # Check for malicious content if detection is enabled
        if self.enable_detection:
            # Use the filter method and check the result
            result = self.resk_words_lists.filter(text)
            if not result.is_safe:
                # If not safe, raise ValueError with the reason
                raise ValueError(f"Malicious content detected: {result.reason or 'Unknown word list violation'}")
        
        return text
    
    def _protect_message(self, message: BaseMessage) -> BaseMessage:
        """
        Protect a LangChain message.
        
        Args:
            message: Message to protect
            
        Returns:
            Protected message
        """
        # Create a new message of the same type with protected content
        content = message.content
        
        if isinstance(content, str):
            # Pour le contenu texte simple
            protected_content = self._protect_text(content)
            
            # Create a new message of the same type
            if isinstance(message, HumanMessage):
                return HumanMessage(content=protected_content)
            elif isinstance(message, SystemMessage):
                return SystemMessage(content=protected_content)
            elif isinstance(message, AIMessage):
                return AIMessage(content=protected_content)
            else:
                # For other message types, preserve the original type but update content
                message_copy = message.copy()
                message_copy.content = protected_content
                return message_copy
        elif isinstance(content, list):
            # Handle multi-modal content (list)
            protected_list_content: List[Dict[str, Any]] = []
            
            for item in content:
                if isinstance(item, dict) and 'type' in item and 'text' in item and item['type'] == 'text':
                    # Text content in multi-modal format
                    item_copy = item.copy()
                    item_copy['text'] = self._protect_text(item['text'])
                    protected_list_content.append(item_copy)
                else:
                    # Non-text content, pass through unchanged
                    # Ensure only dicts are appended to maintain list type
                    if isinstance(item, dict):
                        protected_list_content.append(item)
                    else:
                        logger.warning(f"Skipping non-dict item in multi-modal content: {type(item)}")
                        # Optionally append a placeholder or the original item if the list type allows Any
                        # protected_list_content.append(item) # If list type were List[Any]
            
            # Create a new message with protected content
            message_copy = message.copy()
            message_copy.content = protected_list_content  # type: ignore
            return message_copy
        else:
            # For non-text content, return unchanged
            return message
    
    def _protect_prompt_template(self, template: BasePromptTemplate) -> BasePromptTemplate:
        """
        Protect a LangChain prompt template.
        
        Args:
            template: Prompt template to protect
            
        Returns:
            Protected prompt template
        """
        # We can't modify the template directly, but we can wrap its format method
        original_format = template.format
        original_format_prompt = template.format_prompt
        
        def protected_format(*args: Any, **kwargs: Any) -> str:
            result = original_format(*args, **kwargs)
            return self._protect_text(result)
        
        def protected_format_prompt(*args: Any, **kwargs: Any) -> PromptValue:
            prompt_value = original_format_prompt(*args, **kwargs)
            
            # Get the original string representation
            original_string = prompt_value.to_string()
            
            # Apply protection
            protected_string = self._protect_text(original_string)
            
            # Create a new prompt value with the protected content
            # This is tricky since PromptValue is an interface
            # As a workaround, we'll modify the to_string method
            original_to_string = prompt_value.to_string
            # Ignore type error for dynamic method assignment
            prompt_value.to_string = lambda: protected_string # type: ignore [method-assign]
            
            return prompt_value
        
        # Replace the methods with protected versions
        # Ignore type errors for dynamic method assignment (monkey-patching)
        template.format = protected_format # type: ignore [method-assign]
        template.format_prompt = protected_format_prompt # type: ignore [method-assign]
        
        return template
    
    def _protect_chain(self, chain: Chain) -> Chain:
        """
        Protect a LangChain chain.
        
        Args:
            chain: Chain to protect
            
        Returns:
            Protected chain
        """
        # Save the original __call__ method
        original_call = chain.__call__
        
        # Define a protected version of the __call__ method
        def protected_call(*args: Any, **kwargs: Any) -> Any:
            # Protect the inputs
            protected_kwargs: Dict[str, Any] = {}
            for key, value in kwargs.items():
                if isinstance(value, str):
                    protected_kwargs[key] = self._protect_text(value)
                elif isinstance(value, BaseMessage):
                    protected_kwargs[key] = self._protect_message(value)
                elif isinstance(value, list):
                    # Pour les listes, on doit traiter chaque élément selon son type
                    if all(isinstance(x, BaseMessage) for x in value):
                        # Si tous les éléments sont des BaseMessage, protéger chacun
                        protected_value: List[BaseMessage] = []
                        for msg in value:
                            protected_value.append(self._protect_message(msg))
                        protected_kwargs[key] = protected_value
                    else:
                        # Pour les autres types de listes, garder inchangé
                        protected_kwargs[key] = value
                else:
                    protected_kwargs[key] = value
            
            # Call the original method with protected inputs
            original_result = original_call(*args, **protected_kwargs)

            # Process the result based on its type
            if isinstance(original_result, dict):
                # Protect the outputs if they're strings, creating a new dictionary
                protected_result: Dict[str, Any] = {}
                for key, value in original_result.items():
                    if isinstance(value, str):
                        protected_result[key] = self._protect_text(value)
                    else:
                        protected_result[key] = value
                return protected_result
            else:
                # For non-dict results, log a warning and return the original result as is
                logger.warning(f"Chain call returned non-dict type: {type(original_result)}")
                return original_result
        
        # Replace the original __call__ method with the protected version
        # Ignore type error for dynamic method assignment (monkey-patching)
        chain.__call__ = protected_call # type: ignore [method-assign]
            
        return chain
    
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

    # Implementation of abstract method from ProtectorBase
    def protect_input(self, prompt: Union[BasePromptTemplate, Chain, BaseMessage, str], **kwargs) -> Union[BasePromptTemplate, Chain, BaseMessage, str]:
        """
        Apply security measures to the input before sending to the LLM.
        Delegates to the main protect method.
        """
        # LangChain protector's main 'protect' handles input types
        return self.protect(prompt)

    # Implementation of abstract method from ProtectorBase
    def protect_output(self, response: Union[BasePromptTemplate, Chain, BaseMessage, str], **kwargs) -> Union[BasePromptTemplate, Chain, BaseMessage, str]:
        """
        Apply security measures to the output received from the LLM.
        Delegates to the main protect method for sanitization/checks.
        """
        # For now, apply the same protection logic to output as input
        # Specific output filters/detectors could be added later
        return self.protect(response)

# Factory function to create and configure a LangChain protector
def create_langchain_protector(config: Optional[LangChainProtectorConfig] = None) -> LangChainProtector:
    """
    Create a LangChain protector with the specified configuration.
        
        Args:
        config: Configuration options for the protector
            
        Returns:
        Configured LangChain protector
    """
    return LangChainProtector(config) 