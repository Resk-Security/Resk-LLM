"""
RESK-LLM Provider Integration Module

This module provides protector classes for various LLM providers, integrating RESK-LLM's
security components (filters, detectors) into the API call lifecycle.
Supports OpenAI, Anthropic (Claude), Cohere, etc. (Others to be refactored).
"""

import re
import html
import logging
import traceback
from typing import Any, Dict, List, Optional, Union, Callable, Type, Sequence, Coroutine, Tuple, Set

# Import RESK-LLM core components
from resk_llm.core.abc import ProtectorBase, FilterBase, DetectorBase
from resk_llm.heuristic_filter import HeuristicFilter # Example filter

# Define configuration structure
ProtectorConfig = Dict[str, Any] # Can be refined with TypedDict later if needed

logger = logging.getLogger(__name__)

# --- Custom Exception ---
class SecurityException(Exception):
    """Custom exception for security violations detected by RESK-LLM."""
    pass

# --- Base Class ---

class BaseProviderProtector(ProtectorBase[Any, Any, ProtectorConfig]):
    """
    Base class for RESK-LLM provider protectors.
    Manages the configuration of security components (filters, detectors)
    and provides common sanitization utilities.
    """
    DEFAULT_INPUT_FILTERS: List[Type[FilterBase]] = [HeuristicFilter] # Example default
    DEFAULT_OUTPUT_FILTERS: List[Type[FilterBase]] = [] # Example default
    DEFAULT_DETECTORS: List[Type[DetectorBase]] = [] # Example default

    def __init__(self, config: Optional[ProtectorConfig] = None):
        """
        Initializes the base protector.
        
        Args:
            config: Configuration dictionary. Expected keys:
                'model': Name of the LLM model (provider-specific).
                'input_filters': List of FilterBase instances for input processing.
                'output_filters': List of FilterBase instances for output processing.
                'detectors': List of DetectorBase instances.
                'filter_configs': Optional dict mapping filter class names to their configs.
                'detector_configs': Optional dict mapping detector class names to their configs.
                'use_default_components': Boolean (default True) to instantiate default filters/detectors.
                Other provider-specific settings might be included.
        """
        self.input_filters: List[FilterBase] = []
        self.output_filters: List[FilterBase] = []
        self.detectors: List[DetectorBase] = []
        self.model: Optional[str] = None
        self.logger = logger # Use the module logger
        super().__init__(config) # Calls _validate_config

    def _validate_config(self) -> None:
        """Validate configuration and instantiate security components."""
        if not isinstance(self.config, dict):
            self.logger.warning("Invalid config type, expected dict. Using empty config.")
            self.config = {}

        self.model = self.config.get('model') # Provider-specific classes should validate this
        if not self.model:
             self.logger.warning("Model name not specified in configuration.")

        filter_configs = self.config.get('filter_configs', {})
        detector_configs = self.config.get('detector_configs', {})
        use_defaults = self.config.get('use_default_components', True)

        # Instantiate Input Filters
        self.input_filters = []
        input_filter_instances = self.config.get('input_filters', [])
        if use_defaults:
            # Add defaults if not already provided as instances
            default_filter_types = {type(f) for f in input_filter_instances}
            for FilterClass in self.DEFAULT_INPUT_FILTERS:
                if FilterClass not in default_filter_types:
                    cfg = filter_configs.get(FilterClass.__name__, {})
                    try:
                        self.input_filters.append(FilterClass(config=cfg))
                    except Exception as e:
                         self.logger.error(f"Failed to instantiate default input filter {FilterClass.__name__}: {e}")
        # Add explicitly provided instances
        for filt in input_filter_instances:
             if isinstance(filt, FilterBase):
                 self.input_filters.append(filt)
             else:
                 self.logger.warning(f"Invalid item in 'input_filters': {filt}. Expected FilterBase instance.")

        # Instantiate Output Filters (similar logic)
        self.output_filters = []
        output_filter_instances = self.config.get('output_filters', [])
        if use_defaults:
            default_filter_types = {type(f) for f in output_filter_instances}
            for FilterClass in self.DEFAULT_OUTPUT_FILTERS:
                 if FilterClass not in default_filter_types:
                    cfg = filter_configs.get(FilterClass.__name__, {})
                    try:
                        self.output_filters.append(FilterClass(config=cfg))
                    except Exception as e:
                         self.logger.error(f"Failed to instantiate default output filter {FilterClass.__name__}: {e}")
        for filt in output_filter_instances:
             if isinstance(filt, FilterBase):
                 self.output_filters.append(filt)
             else:
                 self.logger.warning(f"Invalid item in 'output_filters': {filt}. Expected FilterBase instance.")

        # Instantiate Detectors (similar logic)
        self.detectors = []
        detector_instances = self.config.get('detectors', [])
        if use_defaults:
            default_detector_types = {type(d) for d in detector_instances}
            for DetectorClass in self.DEFAULT_DETECTORS:
                if DetectorClass not in default_detector_types:
                    cfg = detector_configs.get(DetectorClass.__name__, {})
                    try:
                         self.detectors.append(DetectorClass(config=cfg))
                    except Exception as e:
                         self.logger.error(f"Failed to instantiate default detector {DetectorClass.__name__}: {e}")
        for det in detector_instances:
            if isinstance(det, DetectorBase):
                self.detectors.append(det)
            else:
                self.logger.warning(f"Invalid item in 'detectors': {det}. Expected DetectorBase instance.")

        self.logger.info(f"Initialized {self.__class__.__name__} with {len(self.input_filters)} input filters, "
                         f"{len(self.output_filters)} output filters, {len(self.detectors)} detectors.")


    def update_config(self, config: ProtectorConfig) -> None:
        """Update the protector's configuration and re-validate."""
        self.config.update(config)
        self._validate_config() # Re-instantiate filters/detectors based on new config

    def _apply_filters(self, data: Any, filters: List[FilterBase]) -> Any:
        """
        Helper to apply a list of filters sequentially.
        Assumes filters might raise SecurityException on failure or return modified data.
        Needs refinement based on finalized FilterBase contract.
        """
        processed_data = data
        for filt in filters:
            # Check if the filter object is valid before trying to use it
            if not (hasattr(filt, 'filter') and callable(filt.filter)):
                self.logger.error(f"Filter object {filt} does not have a callable 'filter' method.")
                # Decide how to handle this: raise, skip, block? Let's block.
                raise SecurityException(f"Invalid filter configuration: {filt.__class__.__name__}")

            try:
                # Call the filter method
                result = filt.filter(processed_data)

                # Process the result based on expected format (e.g., HeuristicFilter)
                # HeuristicFilter returns Tuple[bool, Optional[str], str]
                if isinstance(result, tuple) and len(result) == 3 and isinstance(result[0], bool):
                    passed, reason, current_data = result
                    if not passed:
                        self.logger.warning(f"Filter {filt.__class__.__name__} blocked execution: {reason}")
                        raise SecurityException(f"Blocked by {filt.__class__.__name__}: {reason}")
                    processed_data = current_data # Use the returned data
                else:
                    # Assume other filters return modified data or raise on failure
                    # If the filter modified data, update processed_data
                    # This part might need adjustment based on other filter contracts
                    if result != processed_data:
                         processed_data = result # Assuming filter returns the processed data directly

            except SecurityException: # Catch specific security blocks
                self.logger.warning(f"Security filter {filt.__class__.__name__} triggered.")
                raise # Re-raise immediately
            except Exception as e:
                self.logger.error(f"Error applying filter {filt.__class__.__name__}: {e}", exc_info=True)
                # Wrap non-security exceptions as SecurityException to signal failure.
                raise SecurityException(f"Error during filtering by {filt.__class__.__name__}") from e
            
        return processed_data

    @staticmethod
    def basic_sanitize(text: str) -> str:
        """
        Perform basic, universal text sanitization.
        Encodes/decodes UTF-8 and escapes HTML entities.
        Removes most control characters.
        """
        if not isinstance(text, str):
            logger.debug(f"basic_sanitize received non-string type: {type(text)}. Returning as-is.")
            return text # Return non-strings as-is
        try:
            # Ensure valid UTF-8
            text = text.encode('utf-8', errors='replace').decode('utf-8')
            # Basic HTML escaping
            text = html.escape(text, quote=True) # Escapes < > & \" '
            # Remove control characters except tab, newline, carriage return
            text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)
            return text
        except Exception as e:
             logger.error(f"Error during basic sanitization: {e}", exc_info=True)
             # Return original text on error to avoid breaking valid data
             return text


    # --- Abstract Methods (Default async implementations provided) ---

    async def protect_input(self, prompt: Any, **kwargs) -> Any:
        """
        Apply input filters and provider-specific sanitization asynchronously.
        Default implementation applies synchronous filters. Override if needed.
        """
        self.logger.debug(f"Applying {len(self.input_filters)} input filters...")
        try:
            # Provider-specific sanitization should happen within _apply_filters
            # or via dedicated filters if complex.
            processed_prompt = self._apply_filters(prompt, self.input_filters)
            self.logger.debug("Input filters applied successfully.")
            return processed_prompt
        except SecurityException as e:
             self.logger.warning(f"Input protection failed: {e}")
             raise
        except Exception as e:
             self.logger.error(f"Unexpected error during input protection: {e}", exc_info=True)
             raise SecurityException("Failed during input protection") from e


    async def protect_output(self, response: Any, **kwargs) -> Any:
        """
        Apply output filters and provider-specific sanitization asynchronously.
        Default implementation applies synchronous filters. Override if needed.
        """
        self.logger.debug(f"Applying {len(self.output_filters)} output filters...")
        try:
            # Provider-specific sanitization should happen within _apply_filters
            # or via dedicated filters.
            processed_response = self._apply_filters(response, self.output_filters)
            self.logger.debug("Output filters applied successfully.")
            return processed_response
        except SecurityException as e:
             self.logger.warning(f"Output protection failed: {e}")
             raise
        except Exception as e:
             self.logger.error(f"Unexpected error during output protection: {e}", exc_info=True)
             raise SecurityException("Failed during output protection") from e

    async def execute_protected(self, api_function: Callable[..., Coroutine[Any, Any, Any]], *args: Any, **kwargs: Any) -> Any:
         """
         Wraps an async API call with input/output protection.
         Relies on subclass implementations of `extract_input_data` and `prepare_api_args`.
         """
         self.logger.info(f"Executing protected API call: {api_function.__name__}")
         input_data = self.extract_input_data(args, kwargs)

         try:
             # 1. Protect Input
             protected_input = await self.protect_input(input_data)

             # 2. Prepare API Arguments
             api_args, api_kwargs = self.prepare_api_args(protected_input, args, kwargs)

             # 3. Call API
             self.logger.debug(f"Calling API function {api_function.__name__}...")
             raw_response = await api_function(*api_args, **api_kwargs)
             self.logger.debug(f"API function {api_function.__name__} returned.")

             # 4. Protect Output
             protected_response = await self.protect_output(raw_response)
             self.logger.info(f"Protected API call {api_function.__name__} completed.")

             return protected_response

         except SecurityException as e:
             self.logger.warning(f"Security exception during protected execution of {api_function.__name__}: {e}")
             # Depending on policy, might return a default safe response or re-raise
             raise # Re-raise security exceptions by default
         except Exception as e:
             self.logger.error(f"Error executing protected call {api_function.__name__}: {e}", exc_info=True)
             # Wrap non-security errors? Or let original exception bubble up?
             raise # Re-raise other exceptions by default


    # --- Helper methods for execute_protected (MUST be overridden by subclasses) ---

    def extract_input_data(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        """
        Extract the primary input data (e.g., messages, prompt) from API call arguments.
        Needs to be implemented by subclasses based on the provider's API signature.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement 'extract_input_data'")

    def prepare_api_args(self, processed_input: Any, original_args: Tuple[Any, ...], original_kwargs: Dict[str, Any]) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
        """
        Merge the processed input data back into the arguments for the API call.
        Needs to be implemented by subclasses.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement 'prepare_api_args'")


# --- OpenAI Protector ---

# Define OpenAI specific input/output types if needed (e.g., using TypedDict)
OpenAIInputType = List[Dict[str, Any]] # Example: List of message dicts
OpenAIOutputType = Any # Example: OpenAIObject response

class OpenAIProtector(BaseProviderProtector):
    """
    RESK-LLM Protector for OpenAI (GPT) models.
    Applies configured filters and OpenAI-specific sanitization.
    Uses async methods for protection steps.
    """

    # OpenAI specific special tokens (consider moving to filtering_patterns.special_tokens)
    OPENAI_SPECIAL_TOKENS: Set[str] = {
        "<|endoftext|>", "<|fim_prefix|>", "<|fim_middle|>", "<|fim_suffix|>",
        "<|endofprompt|>", "<s>", "</s>", "<|im_start|>", "<|im_end|>", "<|im_sep|>"
    }

    def __init__(self, config: Optional[ProtectorConfig] = None):
        """
        Initializes the OpenAIProtector.
        
        Args:
            config: Configuration dictionary. Inherits base config keys, plus:
                'model': OpenAI model name (e.g., "gpt-4o"). Default "gpt-4o".
                'strip_special_tokens': Boolean (default True) to remove OpenAI special tokens.
        """
        base_config = config or {}
        base_config.setdefault('model', 'gpt-4o')
        base_config.setdefault('strip_special_tokens', True)
        super().__init__(base_config)

    def _validate_config(self) -> None:
        """Validate OpenAI specific config and call base validation."""
        if not self.config.get('model'):
             self.logger.error("OpenAI model name ('model') is required in configuration.")
             raise ValueError("OpenAI model name is required.")
        super()._validate_config() # Validate filters, detectors etc.

    def _sanitize_openai_text(self, text: str) -> str:
        """Apply basic sanitization and remove OpenAI special tokens if configured."""
        sanitized_text = self.basic_sanitize(text)
        if self.config.get('strip_special_tokens', True) and isinstance(sanitized_text, str):
            # Simple replace is often sufficient and faster
            for token in self.OPENAI_SPECIAL_TOKENS:
                 sanitized_text = sanitized_text.replace(token, "")
        return sanitized_text

    async def _process_message_content(self, content: Union[str, List[Dict[str, Any]]], filters: List[FilterBase]) -> Union[str, List[Dict[str, Any]]]:
        """Sanitize and filter content within an OpenAI message structure using provided filters."""
        if isinstance(content, str):
            sanitized_content = self._sanitize_openai_text(content)
            # Apply string-based filters (using base class helper)
            filtered_content = self._apply_filters(sanitized_content, filters)
            return filtered_content
        elif isinstance(content, list): # Handle multi-modal content
            processed_list = []
            idx = 0
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text_content = item.get('text', '')
                    sanitized_text = self._sanitize_openai_text(text_content)
                    # Apply filters to text part
                    filtered_text = self._apply_filters(sanitized_text, filters)
                    processed_list.append({**item, 'text': filtered_text})
                else:
                    # Keep non-text parts (like images) as is for now
                    processed_list.append(item)
            return processed_list
        else:
            self.logger.warning(f"Unexpected content type in message: {type(content)}")
            return content # Return as-is


    async def protect_input(self, prompt: Any, **kwargs) -> Any:
        """
        Apply input filters and sanitization to OpenAI messages asynchronously.
        Overrides base implementation to handle message structure.
        """
        # Check if the input 'prompt' is actually the expected list of messages
        if not isinstance(prompt, list):
            self.logger.warning(f"OpenAI protect_input received non-list data type: {type(prompt)}. Passing through.")
            async def return_prompt(): # Simple coroutine return
                 return prompt
            return await return_prompt()

        # Type hint for clarity within the method
        messages: List[Dict[str, Any]] = prompt

        processed_messages = []
        for i, message in enumerate(messages):
            if 'content' in message:
                 original_content = message['content']
                 # Process content using input filters
                 processed_content = await self._process_message_content(original_content, self.input_filters)
                 processed_messages.append({**message, 'content': processed_content})
            else:
                 # Keep messages without content as is, preserve order
                 processed_messages.append(message)

        return processed_messages


    async def protect_output(self, response: OpenAIOutputType, **kwargs) -> OpenAIOutputType:
        """
        Apply output filters and sanitization to the OpenAI API response asynchronously.
        Overrides base implementation to handle response structure.
        """
        if not response:
            return response
            
        try:
            if hasattr(response, 'choices') and isinstance(response.choices, list):
                 for i, choice in enumerate(response.choices):
                      if hasattr(choice, 'message') and hasattr(choice.message, 'content'):
                           original_content = choice.message.content
                           # Process content using output filters
                           processed_content = await self._process_message_content(original_content, self.output_filters)
                           # Modify the response object directly
                           # Be careful if the object is immutable
                           try:
                                choice.message.content = processed_content
                           except AttributeError:
                                self.logger.warning(f"Could not directly modify response content attribute for choice {i}.")
                                # Output won't be fully protected for this choice
                                pass

        except SecurityException:
             self.logger.warning(f"Output blocked by filter during OpenAI response processing.")
             raise # Re-raise the security exception
        except AttributeError as e:
             self.logger.warning(f"Could not access expected attributes in OpenAI response for output filtering: {e}")
             # Fail open: return original response
             return response
        except Exception as e:
             self.logger.error(f"Unexpected error during OpenAI output protection: {e}", exc_info=True)
             # Fail open: return original response
             return response

        return response # Return the (potentially modified) response


    # --- Overrides for execute_protected helpers ---

    def extract_input_data(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        """Extracts the 'messages' list from OpenAI call arguments."""
        # OpenAI chat completions typically use keyword argument 'messages'
        if 'messages' in kwargs:
            return kwargs['messages']
        # Check positional arguments if needed (less common for 'messages')
        # Example: if len(args) > 0 and isinstance(args[0], list): return args[0]
        self.logger.error("Missing 'messages' keyword argument for OpenAI API call.")
        raise ValueError("Missing 'messages' keyword argument for OpenAI API call.")


    def prepare_api_args(self, processed_input: Any, original_args: Tuple[Any, ...], original_kwargs: Dict[str, Any]) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
        """Merges the processed messages back into the keyword arguments."""
        if not isinstance(processed_input, list):
             raise TypeError("Processed input for OpenAI must be a list of messages.")

        api_kwargs = original_kwargs.copy()
        api_kwargs['messages'] = processed_input # Replace original messages
        api_kwargs['model'] = self.model # Ensure correct model is set

        # Ensure other essential args like 'max_tokens' aren't lost if they were in original_kwargs
        # but handle potential None values if the API expects them to be absent
        # Example: api_kwargs.setdefault('max_tokens', self.config.get('max_tokens'))

        # Remove None values ONLY if the target API function signature requires it.
        # api_kwargs = {k: v for k, v in api_kwargs.items() if v is not None}

        return original_args, api_kwargs # Return original args, modified kwargs


# --- Anthropic Protector ---

class AnthropicProtector(BaseProviderProtector):
    """
    RESK-LLM Protector for Anthropic (Claude) models.
    """
    ANTHROPIC_SPECIAL_TOKENS: Set[str] = set() # Add relevant tokens if needed for stripping

    def __init__(self, config: Optional[ProtectorConfig] = None):
        base_config = config or {}
        base_config.setdefault('model', 'claude-3-opus-20240229') # Example default
        # Anthropic uses 'max_tokens' now, previously 'max_tokens_to_sample'
        # base_config.setdefault('max_tokens', 4096)
        super().__init__(base_config)

    def _validate_config(self) -> None:
        if not self.config.get('model'):
             raise ValueError("Anthropic model name ('model') is required.")
        super()._validate_config()

    def _sanitize_anthropic_text(self, text: str) -> str:
        """Apply basic sanitization and remove Anthropic special tokens if configured."""
        sanitized_text = self.basic_sanitize(text)
        # Add token stripping if needed and configured
        # if self.config.get('strip_special_tokens', False): # Default False for Anthropic?
        #    for token in self.ANTHROPIC_SPECIAL_TOKENS:
        #         sanitized_text = sanitized_text.replace(token, "")
        return sanitized_text

    async def _process_message_content(self, content: Union[str, List[Dict[str, Any]]], filters: List[FilterBase]) -> Union[str, List[Dict[str, Any]]]:
        """Sanitize and filter content within an Anthropic message structure."""
        # Anthropic v3 uses a list of content blocks even for simple text
        if isinstance(content, str):
            # Wrap simple string in expected block structure for processing
            content_blocks = [{'type': 'text', 'text': content}]
        elif isinstance(content, list):
            content_blocks = content
        else:
            self.logger.warning(f"Unexpected content type in Anthropic message: {type(content)}")
            return content

        processed_blocks = []
        for block in content_blocks:
            if isinstance(block, dict) and block.get('type') == 'text':
                 text_content = block.get('text', '')
                 sanitized_text = self._sanitize_anthropic_text(text_content)
                 filtered_text = self._apply_filters(sanitized_text, filters)
                 processed_blocks.append({**block, 'text': filtered_text})
            else:
                 # Keep non-text blocks (e.g., images)
                 processed_blocks.append(block)

        # Return in the same format as received (string or list) if possible,
        # otherwise return the list of blocks format.
        if isinstance(content, str) and len(processed_blocks) == 1 and processed_blocks[0]['type'] == 'text':
             return processed_blocks[0]['text']
        else:
             return processed_blocks


    async def protect_input(self, prompt: Any, **kwargs) -> Any: 
        """Apply input filters and sanitization to Anthropic messages."""
        # Check if the input 'prompt' is actually the expected list of messages
        if not isinstance(prompt, list):
             self.logger.warning(f"Anthropic protect_input received non-list data type: {type(prompt)}. Passing through.")
             # Return a coroutine that simply returns the original input
             async def return_prompt():
                 return prompt
             return return_prompt()

        # Type hint for clarity within the method
        messages: List[Dict[str, Any]] = prompt

        processed_messages = []
        for message in messages:
             if 'content' in message:
                 original_content = message['content']
                 processed_content = await self._process_message_content(original_content, self.input_filters)
                 processed_messages.append({**message, 'content': processed_content})
             else:
                 processed_messages.append(message)
        return processed_messages

    async def protect_output(self, response: Any, **kwargs) -> Any:
          """Apply output filters and sanitization to the Anthropic API response."""
          if not response: return response
          try:
               if hasattr(response, 'content') and isinstance(response.content, list):
                    # Process content blocks using output filters
                    processed_content_blocks = await self._process_message_content(response.content, self.output_filters)
                    # How to update response.content? Anthropic SDK objects might be mutable.
                    try:
                         response.content = processed_content_blocks
                    except AttributeError:
                          self.logger.warning("Could not assign processed content blocks back to Anthropic response.")

          except SecurityException:
              self.logger.warning(f"Output blocked by filter during Anthropic processing.")
              raise
          except Exception as e:
              self.logger.error(f"Unexpected error during Anthropic output protection: {e}", exc_info=True)
              return response # Fail open
          # Ensure this return is aligned with the try/except block
          return response
            
    def extract_input_data(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        if 'messages' in kwargs:
            return kwargs['messages']
        self.logger.error("Missing 'messages' keyword argument for Anthropic API call.")
        raise ValueError("Missing 'messages' keyword argument for Anthropic API call.")

    def prepare_api_args(self, processed_input: Any, original_args: Tuple[Any, ...], original_kwargs: Dict[str, Any]) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
        if not isinstance(processed_input, list):
             raise TypeError("Processed input for Anthropic must be a list of messages.")
        api_kwargs = original_kwargs.copy()
        api_kwargs['messages'] = processed_input
        api_kwargs['model'] = self.model
        # Ensure essential args like 'max_tokens' are present
        api_kwargs.setdefault('max_tokens', self.config.get('max_tokens', 4096)) # Default or passed value
        return original_args, api_kwargs


# --- Cohere Protector ---

class CohereProtector(BaseProviderProtector):
    """
    RESK-LLM Protector for Cohere models.
    Needs careful handling of different API endpoints (generate, chat).
    """
    COHERE_SPECIAL_TOKENS: Set[str] = set() # Add if needed

    def __init__(self, config: Optional[ProtectorConfig] = None):
        base_config = config or {}
        base_config.setdefault('model', 'command-r-plus') # Example default
        # base_config.setdefault('max_tokens', 2048)
        super().__init__(base_config)

    def _validate_config(self) -> None:
        if not self.config.get('model'):
             raise ValueError("Cohere model name ('model') is required.")
        super()._validate_config()

    def _sanitize_cohere_text(self, text: str) -> str:
        """Apply basic sanitization and remove Cohere special tokens if configured."""
        sanitized_text = self.basic_sanitize(text)
        # Add token stripping if needed
        return sanitized_text

    async def _process_text_input(self, text: str, filters: List[FilterBase]) -> str:
        """Sanitize and filter a simple text string."""
        sanitized_text = self._sanitize_cohere_text(text)
        filtered_text = self._apply_filters(sanitized_text, filters)
        return filtered_text

    async def _process_chat_history(self, chat_history: List[Dict[str, str]], filters: List[FilterBase]) -> List[Dict[str, str]]:
         """Sanitize and filter messages within Cohere chat history."""
         processed_history = []
         for msg in chat_history:
             # Cohere uses 'role' (USER, CHATBOT) and 'message' keys
             role = msg.get('role')
             message_text = msg.get('message', '')
             if role and isinstance(message_text, str):
                 # Only filter user messages? Or all? Let's filter all for now.
                 sanitized_text = self._sanitize_cohere_text(message_text)
                 filtered_text = self._apply_filters(sanitized_text, filters)
                 processed_history.append({'role': role, 'message': filtered_text})
             else:
                 processed_history.append(msg) # Keep malformed items as-is?
         return processed_history

    # protect_input and protect_output need context about which API endpoint is called
    # This suggests the 'execute_protected' approach is better, where helpers extract specific args.

    async def protect_output(self, response: Any, **kwargs) -> Any:
         """Apply output filters and sanitization to the Cohere API response."""
         if not response: return response
         try:
             # Handle co.generate response
             if hasattr(response, 'generations') and isinstance(response.generations, list):
                 for gen in response.generations:
                      if hasattr(gen, 'text') and isinstance(gen.text, str):
                           original_text = gen.text
                           sanitized_text = self._sanitize_cohere_text(original_text)
                           filtered_text = self._apply_filters(sanitized_text, self.output_filters)
                           try:
                                gen.text = filtered_text
                           except AttributeError:
                                self.logger.warning("Could not modify Cohere generation text directly.")
             # Handle co.chat response
             elif hasattr(response, 'text') and isinstance(response.text, str):
                 # The main response text
                 original_text = response.text
                 sanitized_text = self._sanitize_cohere_text(original_text)
                 filtered_text = self._apply_filters(sanitized_text, self.output_filters)
                 try:
                      response.text = filtered_text
                 except AttributeError:
                      self.logger.warning("Could not modify Cohere chat response text directly.")
                 # Also process chat history in the response if needed (and exists)
                 if hasattr(response, 'chat_history') and isinstance(response.chat_history, list):
                      # Be careful: filtering output history might remove context needed for follow-up
                      # Only filter the last CHATBOT message?
                      # For now, let's skip filtering response chat_history to avoid issues.
                      pass


         except SecurityException:
             self.logger.warning(f"Output blocked by filter during Cohere processing.")
             raise
         except Exception as e:
             self.logger.error(f"Unexpected error during Cohere output protection: {e}", exc_info=True)
             return response # Fail open
         return response


    def extract_input_data(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        # This needs to determine if it's a chat or generate call based on args/kwargs
        if 'message' in kwargs and 'chat_history' in kwargs: # Likely chat
             return {'message': kwargs['message'], 'chat_history': kwargs['chat_history']}
        elif 'prompt' in kwargs: # Likely generate
             return {'prompt': kwargs['prompt']}
        # Add more specific checks based on cohere SDK usage
        raise ValueError("Could not determine input data (prompt or message/chat_history) for Cohere API call.")

    async def protect_input(self, prompt: Any, **kwargs) -> Any: 
         """ Protects input for either chat or generate based on extracted data. """
         if not isinstance(prompt, dict):
              self.logger.warning(f"Cohere protect_input received non-dict data: {type(prompt)}. Passing through.")
              # Async functions implicitly return a Coroutine
              return prompt # Return the input data directly

         processed_data = prompt.copy()
         if 'prompt' in prompt: # Generate
             processed_data['prompt'] = await self._process_text_input(prompt['prompt'], self.input_filters)
         elif 'message' in prompt: # Chat
             processed_data['message'] = await self._process_text_input(prompt['message'], self.input_filters)
             if 'chat_history' in prompt and isinstance(prompt['chat_history'], list):
                 processed_data['chat_history'] = await self._process_chat_history(prompt['chat_history'], self.input_filters)
         
         # Async functions implicitly return a Coroutine containing the return value
         return processed_data # Return the processed dictionary directly


    def prepare_api_args(self, processed_input: Dict[str, Any], original_args: Tuple[Any, ...], original_kwargs: Dict[str, Any]) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
         """Merges the processed data back into the keyword arguments."""
         api_kwargs = original_kwargs.copy()
         api_kwargs.update(processed_input) # Add processed parts back
         api_kwargs['model'] = self.model
         # Handle other params like max_tokens, temperature etc.
         # api_kwargs.setdefault('max_tokens', self.config.get('max_tokens', 2048))
         return original_args, api_kwargs


# --- Placeholders for other providers ---

# TODO: Implement DeepSeekProtector following the pattern
# class DeepSeekProtector(BaseProviderProtector):
#     # ... implementation ...
#     pass

# TODO: Implement OpenRouterProtector following the pattern
# class OpenRouterProtector(BaseProviderProtector):
#     # ... implementation ...
#     pass 