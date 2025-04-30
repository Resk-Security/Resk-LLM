"""
Models information module for the RESK LLM security library.

This module contains information about supported LLM models, including context window sizes,
token limits, and capabilities. This information is used by various components in the
library to make decisions about prompt handling, context management, and security measures.
"""

from typing import Dict, Any, Optional, List, Union, TypedDict, cast
from resk_llm.core.abc import SecurityComponent

# Define the structure for individual model configurations
class IndividualModelConfig(TypedDict, total=False):
    description: str
    context_window: int
    max_output_tokens: int
    training_data: str
    version: str
    # Note: TypedDict doesn't easily support arbitrary extra keys across all Python versions.
    # We assume the defined keys cover the primary uses.

# Define the overall configuration structure for the ModelRegistry
class ModelConfig(TypedDict):
    models: Dict[str, IndividualModelConfig]


# Ignore type-var error because ModelConfig (TypedDict) is a valid subtype of Dict[str, Any]
class ModelRegistry(SecurityComponent[ModelConfig]): # type: ignore[type-var]
    """
    Registry for LLM model information.
    
    This class provides methods for accessing information about supported models,
    validating model names, and querying model capabilities.
    """
    
    def __init__(self, models_data: Optional[Dict[str, IndividualModelConfig]] = None):
        """
        Initialize the model registry.
        
        Args:
            models_data: Optional dictionary of model information to initialize with.
                         If not provided, the default RESK_MODELS data will be used.
        """
        # Load models from a JSON file or use defaults.
        if models_data is None:
            models_data = {}
        
        # Ignore complex assignment error
        initial_models: Dict[str, IndividualModelConfig] = models_data or RESK_MODELS.copy() # type: ignore[assignment]
        
        config: ModelConfig = {
            "models": initial_models 
        }
        super().__init__(config)
        
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if "models" not in self.config:
            raise ValueError("models dictionary is required in configuration")
            
        models = self.config["models"]
        if not isinstance(models, dict):
            raise ValueError("models must be a dictionary")
        
        # Optional: Deeper validation of individual model configs if needed
        for model_name, model_info in models.items():
            if not isinstance(model_info, dict):
                raise ValueError(f"Configuration for model '{model_name}' must be a dictionary")
            # Add more specific checks based on IndividualModelConfig keys if desired
            
    def update_config(self, config: ModelConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
    
    def get_model_info(self, model_name: str) -> Dict[str, Any]:
        """
        Get information about a specific model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Dictionary with model information
            
        Raises:
            ValueError: If model is not found
        """
        models = self.config["models"]
        
        if model_name not in models:
            raise ValueError(f"Model '{model_name}' not found in registry")
            
        # Cast the result of the copy to Dict[str, Any]
        model_info: Dict[str, Any] = cast(Dict[str, Any], models[model_name].copy())
        
        # If model has a version, include that version's data
        if "version" in model_info:
            version_name = model_info["version"]
            if version_name in models:
                # Update with version data, keeping original values if they exist
                # Cast to Dict to help mypy with .items() on TypedDict
                for key, value in cast(Dict[str, Any], models[version_name]).items():
                    if key not in model_info:
                        model_info[key] = value
        
        # Cast return type explicitly as Dict[str, Any]
        return cast(Dict[str, Any], model_info)
    
    def is_model_supported(self, model_name: str) -> bool:
        """
        Check if a model is supported by the registry.
        
        Args:
            model_name: Name of the model
            
        Returns:
            True if the model is supported, False otherwise
        """
        return model_name in self.config["models"]
    
    def get_context_window(self, model_name: str) -> int:
        """
        Get the context window size for a model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Context window size in tokens
            
        Raises:
            ValueError: If model is not found or doesn't have context window info
        """
        model_info = self.get_model_info(model_name)
        
        if "context_window" not in model_info:
            raise ValueError(f"Context window size not available for model '{model_name}'")
            
        return int(model_info["context_window"])
    
    def get_max_output_tokens(self, model_name: str) -> int:
        """
        Get the maximum output tokens for a model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Maximum output tokens
            
        Raises:
            ValueError: If model is not found or doesn't have max output tokens info
        """
        model_info = self.get_model_info(model_name)
        
        if "max_output_tokens" not in model_info:
            raise ValueError(f"Maximum output tokens not available for model '{model_name}'")
            
        return int(model_info["max_output_tokens"])
    
    def list_models(self, filter_by: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        List all models in the registry, optionally filtered by attributes.
        
        Args:
            filter_by: Optional dictionary of attributes to filter models by
            
        Returns:
            List of model names
        """
        models = self.config["models"]
        
        if not filter_by:
            return list(models.keys())
            
        filtered_models = []
        for model_name, model_info in models.items():
            matches = True
            for key, value in filter_by.items():
                # Use .get() for safer access on IndividualModelConfig (TypedDict)
                model_value = model_info.get(key)
                if model_value is None or model_value != value:
                    matches = False
                    break
            
            if matches:
                filtered_models.append(model_name)
                
        return filtered_models
    
    def add_model(self, model_name: str, model_info: Dict[str, Any]) -> None:
        """
        Add a new model to the registry.
        
        Args:
            model_name: Name of the model
            model_info: Dictionary with model information
            
        Raises:
            ValueError: If model already exists
        """
        models = self.config["models"]
        
        if model_name in models:
            raise ValueError(f"Model '{model_name}' already exists in registry")
            
        # Cast input dict to expected TypedDict type
        models[model_name] = cast(IndividualModelConfig, model_info)
    
    def update_model(self, model_name: str, model_info: Dict[str, Any]) -> None:
        """
        Update information for an existing model.
        
        Args:
            model_name: Name of the model
            model_info: Dictionary with model information
            
        Raises:
            ValueError: If model doesn't exist
        """
        models = self.config["models"]
        
        if model_name not in models:
            raise ValueError(f"Model '{model_name}' not found in registry")
            
        # Cast input dict before updating TypedDict   
        models[model_name].update(cast(IndividualModelConfig, model_info))
    
    def remove_model(self, model_name: str) -> None:
        """
        Remove a model from the registry.
        
        Args:
            model_name: Name of the model
            
        Raises:
            ValueError: If model doesn't exist
        """
        models = self.config["models"]
        
        if model_name not in models:
            raise ValueError(f"Model '{model_name}' not found in registry")
            
        del models[model_name]


# Default model information
# Add explicit type hint for the complex dictionary literal
RESK_MODELS: Dict[str, IndividualModelConfig] = {
    # GPT-4o models
    "gpt-4o": {
        "description": "Our high-intelligence flagship model for complex, multi-step tasks. GPT-4o is cheaper and faster than GPT-4 Turbo.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Oct 2023",
        "version": "gpt-4o-2024-05-13"
    },
    "gpt-4o-2024-05-13": {
        "description": "gpt-4o currently points to this version.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Oct 2023"
    },
    "gpt-4o-2024-08-06": {
        "description": "Latest snapshot that supports Structured Outputs",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    "chatgpt-4o-latest": {
        "description": "Dynamic model continuously updated to the current version of GPT-4o in ChatGPT. Intended for research and evaluation.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    
    # GPT-4o mini models
    "gpt-4o-mini": {
        "description": "Our affordable and intelligent small model for fast, lightweight tasks. GPT-4o mini is cheaper and more capable than GPT-3.5 Turbo.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023",
        "version": "gpt-4o-mini-2024-07-18"
    },
    "gpt-4o-mini-2024-07-18": {
        "description": "gpt-4o-mini currently points to this version.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    
    # GPT-4 Turbo and GPT-4 models
    "gpt-4-turbo": {
        "description": "The latest GPT-4 Turbo model with vision capabilities. Vision requests can now use JSON mode and function calling.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023",
        "version": "gpt-4-turbo-2024-04-09"
    },
    "gpt-4-turbo-2024-04-09": {
        "description": "GPT-4 Turbo with Vision model. Vision requests can now use JSON mode and function calling.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023"
    },
    "gpt-4-turbo-preview": {
        "description": "GPT-4 Turbo preview model.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023",
        "version": "gpt-4-0125-preview"
    },
    "gpt-4-0125-preview": {
        "description": "GPT-4 Turbo preview model intended to reduce cases of 'laziness' where the model doesn't complete a task.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023"
    },
    "gpt-4-1106-preview": {
        "description": "GPT-4 Turbo preview model featuring improved instruction following, JSON mode, reproducible outputs, parallel function calling, and more.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Apr 2023"
    },
    "gpt-4": {
        "description": "Currently points to gpt-4-0613.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021",
        "version": "gpt-4-0613"
    },
    "gpt-4-0613": {
        "description": "Snapshot of gpt-4 from June 13th 2023 with improved function calling support.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021"
    },
    "gpt-4-0314": {
        "description": "Legacy Snapshot of gpt-4 from March 14th 2023.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021"
    },
    
    # GPT-3.5 Turbo models
    "gpt-3.5-turbo": {
        "description": "Currently points to gpt-3.5-turbo-0125.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021",
        "version": "gpt-3.5-turbo-0125"
    },
    "gpt-3.5-turbo-0125": {
        "description": "The latest GPT-3.5 Turbo model with higher accuracy at responding in requested formats and a fix for a bug which caused a text encoding issue for non-English language function calls.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    },
    "gpt-3.5-turbo-1106": {
        "description": "GPT-3.5 Turbo model with improved instruction following, JSON mode, reproducible outputs, parallel function calling, and more.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    },
    "gpt-3.5-turbo-instruct": {
        "description": "Similar capabilities as GPT-3 era models. Compatible with legacy Completions endpoint and not Chat Completions.",
        "context_window": 4096,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    }
}

# Create a default registry instance
default_registry = ModelRegistry(RESK_MODELS)