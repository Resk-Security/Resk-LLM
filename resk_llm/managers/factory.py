"""
Resk-LLM Factory module for easy component creation and dependency injection.
This module provides convenient factory functions to create and configure
security components without having to handle all dependencies manually.
"""

import logging
from typing import Dict, List, Set, Optional, Tuple, Any, Union, Callable, Type, TypeVar, cast
import numpy as np
import os

from resk_llm.core.abc import SecurityComponent, FilterBase, DetectorBase
from resk_llm.filters.resk_heuristic_filter import RESK_HeuristicFilter
from resk_llm.utilities.resk_text_analysis import RESK_TextAnalyzer
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase
from resk_llm.core.canary_tokens import CanaryTokenManager, CanaryTokenDetector
from resk_llm.managers.prompt_security import PromptSecurityManager
from resk_llm.models.resk_models import ModelRegistry, RESK_MODELS, IndividualModelConfig
from resk_llm.managers.resk_context_manager import (
    RESK_TokenBasedContextManager, 
    RESK_MessageBasedContextManager,
    RESK_ContextWindowManager
)

# Generic type for security components
T = TypeVar('T', bound=SecurityComponent)

logger = logging.getLogger(__name__)

def create_heuristic_filter(
    suspicious_keywords: Optional[Set[str]] = None,
    suspicious_patterns: Optional[List[str]] = None,
    use_defaults: bool = True
) -> RESK_HeuristicFilter:
    """
    Create a configured HeuristicFilter instance.
    
    Args:
        suspicious_keywords: Additional suspicious keywords to detect
        suspicious_patterns: Additional suspicious patterns to detect
        use_defaults: Whether to use default patterns and keywords
    
    Returns:
        Configured HeuristicFilter instance
    """
    config: Dict[str, Any] = {'use_defaults': use_defaults}
    
    if suspicious_keywords:
        config['suspicious_keywords'] = suspicious_keywords
    
    if suspicious_patterns:
        config['suspicious_patterns'] = suspicious_patterns
        
    return RESK_HeuristicFilter(config=config)

def create_text_analyzer(
    additional_homoglyphs: Optional[Dict[str, List[str]]] = None,
    additional_invisible_chars: Optional[List[str]] = None
) -> RESK_TextAnalyzer:
    """
    Create a configured TextAnalyzer instance.
    
    Args:
        additional_homoglyphs: Additional homoglyphs to detect
        additional_invisible_chars: Additional invisible characters to detect
    
    Returns:
        Configured TextAnalyzer instance
    """
    # Add explicit type hint for config
    config: Dict[str, Any] = {}
    
    if additional_homoglyphs:
        config['additional_homoglyphs'] = additional_homoglyphs
    
    if additional_invisible_chars:
        config['additional_invisible_chars'] = additional_invisible_chars
    
    return RESK_TextAnalyzer(config=config)

def create_canary_token_manager(
    token_length: int = 10,
    use_uuid: bool = True,
    token_prefix: str = 'CT',
    token_suffix: str = 'ZZ'
) -> CanaryTokenManager:
    """
    Create a configured CanaryTokenManager instance.
    
    Args:
        token_length: Length of random tokens
        use_uuid: Whether to use UUIDs for tokens
        token_prefix: Prefix for tokens
        token_suffix: Suffix for tokens
    
    Returns:
        Configured CanaryTokenManager instance
    """
    config = {
        'token_length': token_length,
        'use_uuid': use_uuid,
        'token_prefix': token_prefix,
        'token_suffix': token_suffix
    }
    
    return CanaryTokenManager(config=config)

def create_vector_database(
    embedding_dim: int = 1536,
    similarity_threshold: float = 0.85,
    db_path: Optional[str] = None
) -> RESK_VectorDatabase:
    """
    Create a configured VectorDatabase instance.
    
    Args:
        embedding_dim: Dimension of embeddings
        similarity_threshold: Threshold for similarity detection
        db_path: Optional path to load database from
    
    Returns:
        Configured VectorDatabase instance
    """
    vector_db = RESK_VectorDatabase(
        embedding_dim=embedding_dim,
        similarity_threshold=similarity_threshold
    )
    
    if db_path and os.path.exists(db_path):
        success = vector_db.load_from_disk(db_path)
        if success:
            logger.info(f"Loaded vector database from {db_path}")
        else:
            logger.warning(f"Failed to load vector database from {db_path}")
    
    return vector_db

def create_model_registry(
    models_data: Optional[Dict[str, Dict[str, Any]]] = None,
    additional_models: Optional[Dict[str, Dict[str, Any]]] = None
) -> ModelRegistry:
    """
    Create a configured ModelRegistry instance.
    
    Args:
        models_data: Custom model data to use instead of defaults
        additional_models: Additional models to add to the registry
        
    Returns:
        Configured ModelRegistry instance
    """
    # Start with default data or ensure custom data conforms to the required type
    registry_data: Dict[str, IndividualModelConfig]
    if models_data:
        # Cast the provided dictionary to the expected type
        registry_data = {k: cast(IndividualModelConfig, v) for k, v in models_data.items()}
    else:
        # Use a copy of the default models (already correctly typed)
        registry_data = RESK_MODELS.copy()
    
    # Add additional models if provided, ensuring type compatibility
    if additional_models:
        for key, value in additional_models.items():
            # Cast each additional model's info before adding/updating
            registry_data[key] = cast(IndividualModelConfig, value)
    
    # Pass the correctly typed data to the constructor
    return ModelRegistry(registry_data)

def create_token_context_manager(
    model_name: str,
    model_registry: Optional[ModelRegistry] = None,
    preserved_prompts: int = 2,
    reserved_tokens: int = 1000,
    compression_enabled: bool = False
) -> RESK_TokenBasedContextManager:
    """
    Create a token-based context manager for the specified model.
    
    Args:
        model_name: Name of the model to use
        model_registry: ModelRegistry to get model info from, or None to use the default
        preserved_prompts: Number of prompts to preserve
        reserved_tokens: Number of tokens to reserve for the response
        compression_enabled: Whether to enable context compression
        
    Returns:
        Configured TokenBasedContextManager instance
    """
    # Get the registry
    registry = model_registry or ModelRegistry(RESK_MODELS)
    
    # Get model info
    model_info = registry.get_model_info(model_name)
    
    return RESK_TokenBasedContextManager(
        model_info=model_info,
        preserved_prompts=preserved_prompts,
        reserved_tokens=reserved_tokens,
        compression_enabled=compression_enabled
    )

def create_message_context_manager(
    model_name: str,
    model_registry: Optional[ModelRegistry] = None,
    preserved_prompts: int = 2,
    max_messages: int = 50,
    smart_pruning: bool = False
) -> RESK_MessageBasedContextManager:
    """
    Create a message-based context manager for the specified model.
    
    Args:
        model_name: Name of the model to use
        model_registry: ModelRegistry to get model info from, or None to use the default
        preserved_prompts: Number of prompts to preserve
        max_messages: Maximum number of messages to keep
        smart_pruning: Whether to use smart pruning for message selection
        
    Returns:
        Configured MessageBasedContextManager instance
    """
    # Get the registry
    registry = model_registry or ModelRegistry(RESK_MODELS)
    
    # Get model info
    model_info = registry.get_model_info(model_name)
    
    return RESK_MessageBasedContextManager(
        model_info=model_info,
        preserved_prompts=preserved_prompts,
        max_messages=max_messages,
        smart_pruning=smart_pruning
    )

def create_context_window_manager(
    model_name: str,
    model_registry: Optional[ModelRegistry] = None,
    window_size: int = 10,
    max_windows: int = 5,
    overlap: int = 2
) -> RESK_ContextWindowManager:
    """
    Create a context window manager for the specified model.
    
    Args:
        model_name: Name of the model to use
        model_registry: ModelRegistry to get model info from, or None to use the default
        window_size: Size of each context window
        max_windows: Maximum number of windows to maintain
        overlap: Number of overlapping messages between windows
        
    Returns:
        Configured ContextWindowManager instance
    """
    # Get the registry
    registry = model_registry or ModelRegistry(RESK_MODELS)
    
    # Get model info
    model_info = registry.get_model_info(model_name)
    
    return RESK_ContextWindowManager(
        model_info=model_info,
        window_size=window_size,
        max_windows=max_windows,
        overlap=overlap
    )

def create_security_manager(
    embedding_function: Optional[Callable[[str], np.ndarray]] = None,
    embedding_dim: int = 1536,
    similarity_threshold: float = 0.85,
    use_canary_tokens: bool = True,
    enable_heuristic_filter: bool = True,
    vector_db_path: Optional[str] = None,
    components: Optional[List[Union[FilterBase, DetectorBase]]] = None
) -> PromptSecurityManager:
    """
    Create a fully configured PromptSecurityManager with all required components.
    
    Args:
        embedding_function: Function to convert text to embeddings
        embedding_dim: Dimension of embeddings
        similarity_threshold: Threshold for similarity detection
        use_canary_tokens: Whether to enable canary tokens
        enable_heuristic_filter: Whether to enable heuristic filtering
        vector_db_path: Path to load vector database from
        components: Additional components to add to the manager
    
    Returns:
        Configured PromptSecurityManager instance
    """
    manager = PromptSecurityManager(
        embedding_function=embedding_function,
        embedding_dim=embedding_dim,
        similarity_threshold=similarity_threshold,
        use_canary_tokens=use_canary_tokens,
        enable_heuristic_filter=enable_heuristic_filter,
        vector_db_path=vector_db_path
    )
    
    # Add any additional components
    if components:
        for component in components:
            manager.add_component(component)
    
    return manager

def create_component(component_class: Type[T], config: Optional[Dict[str, Any]] = None) -> T:
    """
    Create a component of the specified class with the given configuration.
    
    Args:
        component_class: The class of the component to create
        config: Configuration for the component
    
    Returns:
        An instance of the specified component class
    """
    if config is None:
        config = {}
    
    return component_class(config=config) 