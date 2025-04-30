"""
FastAPI integration module for securing LLM APIs.

This module provides classes and utilities to secure FastAPI applications
that interact with LLMs, particularly for protecting against injections,
data leakage, and other security concerns.
"""

import re
import logging
import json
import os
from typing import Callable, Dict, Any, List, Optional, Union, TypeVar, Type, cast
from pathlib import Path
import traceback

from fastapi import FastAPI, Request, Response, Depends, HTTPException, APIRouter, status, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

from resk_llm.providers_integration import OpenAIProtector
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider
from resk_llm.filtering_patterns import (
    check_for_obfuscation, 
    sanitize_text_from_obfuscation,
    check_text_for_injections,
    check_pii_content,
    moderate_text
)
from resk_llm.core.abc import ProtectorBase, SecurityManagerBase

# Type definitions for config
FastAPIProtectorConfig = Dict[str, Any]

# Logger configuration
logger = logging.getLogger(__name__)

class FastAPIProtector(ProtectorBase[Any, Any, FastAPIProtectorConfig]):
    """
    Protector for FastAPI applications that interact with LLMs.
    Protects against injections, XSS attacks and data leakage.
    """
    def __init__(self, 
                 config: Optional[FastAPIProtectorConfig] = None):
        """
        Initialize the FastAPI protector.
        
        Args:
            config: Configuration dictionary which may contain:
            app: FastAPI application
                model: OpenAI model to use
            rate_limit: Requests per minute limit
            request_sanitization: Enable request sanitization
            response_sanitization: Enable response sanitization
            custom_patterns_dir: Directory for custom patterns
            enable_patterns_api: Enable patterns management API
            patterns_api_prefix: Prefix for patterns API routes
                patterns_api_auth: Authentication function for patterns API
                cors_origins: CORS allowed origins
        """
        # Add logger initialization
        self.logger = logger
        
        default_config: FastAPIProtectorConfig = {
            'app': None,
            'model': 'gpt-4o',
            'rate_limit': 60,
            'request_sanitization': True,
            'response_sanitization': True,
            'custom_patterns_dir': None,
            'enable_patterns_api': False,
            'patterns_api_prefix': '/api/patterns',
            'patterns_api_auth': None,
            'cors_origins': ["*"]
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        # Initialize properties from config
        self.rate_limit = self.config.get('rate_limit', 60)
        self.request_sanitization = self.config.get('request_sanitization', True)
        self.response_sanitization = self.config.get('response_sanitization', True)
        self.protector = OpenAIProtector(config={'model': self.config.get('model', 'gpt-4o')})
        
        # Custom patterns management
        self.custom_patterns_dir = self.config.get('custom_patterns_dir')
        if self.custom_patterns_dir:
            self.pattern_provider = FileSystemPatternProvider(config=self.config.get('pattern_provider_config'))
            self.word_list_filter = WordListFilter(config={'pattern_provider': self.pattern_provider, **self.config.get('word_list_filter_config', {})})
        else:
            self.pattern_provider = FileSystemPatternProvider()
            self.word_list_filter = WordListFilter()
        
        # Patterns API options
        self.enable_patterns_api = self.config.get('enable_patterns_api', False)
        self.patterns_api_prefix = self.config.get('patterns_api_prefix', '/api/patterns')
        self.patterns_api_auth = self.config.get('patterns_api_auth')
        self.api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
        
        # CORS options
        self.cors_origins = self.config.get('cors_origins', ["*"])
        
        # Initialize app if provided
        app = self.config.get('app')
        if app is not None:
            self.init_app(app)
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if 'rate_limit' in self.config and not isinstance(self.config['rate_limit'], int):
            raise ValueError("rate_limit must be an integer")
            
        if 'request_sanitization' in self.config and not isinstance(self.config['request_sanitization'], bool):
            raise ValueError("request_sanitization must be a boolean")
            
        if 'response_sanitization' in self.config and not isinstance(self.config['response_sanitization'], bool):
            raise ValueError("response_sanitization must be a boolean")
            
        if 'custom_patterns_dir' in self.config and self.config['custom_patterns_dir'] is not None:
            if not isinstance(self.config['custom_patterns_dir'], str):
                raise ValueError("custom_patterns_dir must be a string or None")
            
        if 'enable_patterns_api' in self.config and not isinstance(self.config['enable_patterns_api'], bool):
            raise ValueError("enable_patterns_api must be a boolean")
            
        if 'patterns_api_prefix' in self.config and not isinstance(self.config['patterns_api_prefix'], str):
            raise ValueError("patterns_api_prefix must be a string")
            
        if 'cors_origins' in self.config and not isinstance(self.config['cors_origins'], list):
            raise ValueError("cors_origins must be a list of strings")
    
    def update_config(self, config: FastAPIProtectorConfig) -> None:
        """Update the configuration with new values."""
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if 'rate_limit' in config:
            self.rate_limit = config['rate_limit']
        if 'request_sanitization' in config:
            self.request_sanitization = config['request_sanitization']
        if 'response_sanitization' in config:
            self.response_sanitization = config['response_sanitization']
        if 'model' in config:
            self.protector = OpenAIProtector(config={'model': config['model']})
        if 'custom_patterns_dir' in config:
            self.custom_patterns_dir = config['custom_patterns_dir']
            if self.custom_patterns_dir:
                self.pattern_provider = FileSystemPatternProvider(config=self.config.get('pattern_provider_config'))
                self.word_list_filter = WordListFilter(config={'pattern_provider': self.pattern_provider, **self.config.get('word_list_filter_config', {})})
        if 'enable_patterns_api' in config:
            self.enable_patterns_api = config['enable_patterns_api']
        if 'patterns_api_prefix' in config:
            self.patterns_api_prefix = config['patterns_api_prefix']
        if 'patterns_api_auth' in config:
            self.patterns_api_auth = config['patterns_api_auth']
        if 'cors_origins' in config:
            self.cors_origins = config['cors_origins']
            
    def protect(self, data: Any) -> Any:
        """
        Main protection method required by ProtectorBase.
        This is a generic entry point that delegates to more specific methods.
        
        Args:
            data: Input data to protect (FastAPI app or request data)
            
        Returns:
            Protected version of the input
        """
        try:
            # Check if data is a FastAPI app instance
            if hasattr(data, '__class__') and hasattr(data.__class__, '__module__'):
                # Use fully qualified name check for robustness
                if f"{data.__class__.__module__}.{data.__class__.__name__}" == 'fastapi.applications.FastAPI':
                    # If it's the app, initialize it
                    return self.init_app(cast(FastAPI, data))
                
            # Assume it's request data that needs sanitization
            if isinstance(data, dict):
                return self._sanitize_nested_dict(data)
            elif isinstance(data, list):
                return self._sanitize_list(data)
            elif isinstance(data, str):
                 # Use the internal text sanitization method
                return self._sanitize_text(data)
            else:
                # For other types, just return as is
                return data
        except Exception as e:
            logger.error(f"Error in FastAPIProtector protect method: {str(e)}")
            # Fail open in case of unexpected error during protection logic
            return data
            
    # Implementation of abstract method from ProtectorBase
    async def protect_input(self, prompt: Any, **kwargs) -> Any:
        """
        Apply security measures to the input before sending to the LLM.
        This might involve running filters or detectors.
        """
        # TODO: Implement actual input protection logic using self.protector.protect_input if needed
        # For now, just sanitize as per the protect() method's logic for non-app data.
        # Note: self.protector.protect_input expects OpenAIInputType (List[Dict]) and is async.
        # This basic implementation assumes prompt is simple data (dict/list/str).
        if isinstance(prompt, dict):
            return self._sanitize_nested_dict(prompt)
        elif isinstance(prompt, list):
            return self._sanitize_list(prompt)
        elif isinstance(prompt, str):
            return self._sanitize_text(prompt)
        return prompt

    # Implementation of abstract method from ProtectorBase
    async def protect_output(self, response: Any, **kwargs) -> Any:
        """
        Apply security measures to the output received from the LLM.
        This might involve running filters or detectors.
        """
        # TODO: Implement actual output protection logic using self.protector.protect_output if needed
        # For now, just sanitize as per the _sanitize_nested_dict/_sanitize_list logic.
        # Note: self.protector.protect_output expects OpenAIOutputType and is async.
        # This basic implementation assumes response is simple data (dict/list/str).
        if isinstance(response, dict):
            return self._sanitize_nested_dict(response)
        elif isinstance(response, list):
            return self._sanitize_list(response)
        elif isinstance(response, str):
            # Output sanitization might be different from input, e.g., less aggressive
            # For now, use the same basic text sanitization
            return self._sanitize_text(response)
        return response
            
    def init_app(self, app: FastAPI) -> FastAPI:
        """
        Initialize the FastAPI application with security middlewares.
        
        Args:
            app: FastAPI application
            
        Returns:
            The initialized FastAPI application
        """
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Add security middleware for request sanitization
        if self.request_sanitization:
            @app.middleware("http")
            async def sanitize_request_middleware(request: Request, call_next: Callable):
                if request.headers.get("content-type") == "application/json":
                    try:
                        # Read and sanitize request body
                        body = await request.body()
                        if body:
                            json_data = json.loads(body)
                            # Use internal sanitization methods
                            sanitized_data = self._sanitize_nested_dict(json_data)
                            
                            # Create a modified request with sanitized data
                            # This is a workaround since FastAPI requests are immutable
                            setattr(request, "_body", json.dumps(sanitized_data).encode())
                    except Exception as e:
                        logger.error(f"Error during request sanitization: {str(e)}")
                
                # Continue with the middleware chain
                return await call_next(request)
        
        # Add security middleware for response sanitization
        if self.response_sanitization:
            @app.middleware("http")
            async def sanitize_response_middleware(request: Request, call_next: Callable):
                # Get response
                response = await call_next(request)
                
                # Only sanitize JSON responses
                if response.headers.get("content-type") == "application/json":
                    try:
                        # Read response body
                        body = b""
                        async for chunk in response.body_iterator:
                            body += chunk
                        
                        # Sanitize JSON data
                        json_data = json.loads(body)
                        # Use internal sanitization methods
                        sanitized_data = self._sanitize_nested_dict(json_data)
                        
                        # Create new response with sanitized data
                        return Response(
                            content=json.dumps(sanitized_data),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            media_type="application/json"
                        )
                    except Exception as e:
                        logger.error(f"Error during response sanitization: {str(e)}")
                
                # Return original response if no sanitization or error occurred
                return response
        
        # Configure patterns API if enabled
        if self.enable_patterns_api:
            self._register_patterns_api(app)
            
        # Store instance in app state
        app.state.resk_fastapi_protector = self
    
        return app
        
    def _sanitize_text(self, text: str) -> str:
        """
        Internal method to sanitize a single string.
        Applies basic obfuscation checks and configured filters.
        """
        if not isinstance(text, str):
             return text # Return non-strings as is
             
        sanitized_text = text
        try:
            # Check for obfuscation first
            obfuscation = check_for_obfuscation(sanitized_text)
            if obfuscation:
                # Normalize text if obfuscation attempts are detected
                sanitized_text = sanitize_text_from_obfuscation(sanitized_text)
            
            # Apply word list filter (example)
            if self.word_list_filter:
                passed, reason, filtered_text = self.word_list_filter.filter(sanitized_text)
                if not passed:
                    # Decide on action: log, raise, replace? For now, log and keep original.
                    # This behavior might need configuration.
                    self.logger.warning(f"WordListFilter check failed during sanitization: {reason}. Returning original text for now.")
                    # return "[REDACTED]" # Example: Replace if blocked
                else:
                    # Use the text returned by the filter (might be unchanged)
                    sanitized_text = filtered_text 
            
            # TODO: Add other basic sanitization if needed (e.g., HTML escaping?)
            # sanitized_text = html.escape(sanitized_text)
            
        except Exception as e:
            self.logger.error(f"Error during text sanitization: {str(e)}")
            # Fail open: return original text if sanitization fails
            return text
            
        return sanitized_text
        
    def _sanitize_nested_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize a dictionary.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        result: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Check for emojis and special characters - Handled in _sanitize_text
                # obfuscation = check_for_obfuscation(value)
                # if obfuscation:
                #     value = sanitize_text_from_obfuscation(value)
                
                # Call internal sanitization method
                result[key] = self._sanitize_text(value)
            elif isinstance(value, dict):
                result[key] = self._sanitize_nested_dict(value)
            elif isinstance(value, list):
                result[key] = self._sanitize_list(value)
            else:
                result[key] = value
        return result
        
    def _sanitize_list(self, data: List[Any]) -> List[Any]:
        """
        Recursively sanitize a list.
        
        Args:
            data: List to sanitize
            
        Returns:
            Sanitized list
        """
        result: List[Any] = []
        for item in data:
            if isinstance(item, str):
                # Check for emojis and special characters - Handled in _sanitize_text
                # obfuscation = check_for_obfuscation(item)
                # if obfuscation:
                #     item = sanitize_text_from_obfuscation(item)
                    
                # Call internal sanitization method
                result.append(self._sanitize_text(item))
            elif isinstance(item, dict):
                result.append(self._sanitize_nested_dict(item))
            elif isinstance(item, list):
                result.append(self._sanitize_list(item))
            else:
                result.append(item)
        return result
        
    async def protect_endpoint(self, 
                         request: Request, 
                         check_prompt: bool = True, 
                         check_pii: bool = False, 
                         check_toxicity: bool = False) -> Dict[str, Any]:
        """
        Middleware function to protect an endpoint that interacts with an LLM.
        
        Args:
            request: FastAPI request object
            check_prompt: Check if the prompt contains forbidden words
            check_pii: Check if the prompt contains personal data
            check_toxicity: Check if the prompt contains toxic content
            
        Returns:
            Sanitized request data if checks pass
            
        Raises:
            HTTPException: If any check fails
        """
        try:
            # Get request data
            if request.headers.get("content-type") == "application/json":
                request_data = await request.json()
            else:
                request_data = {}
            
            # Prompt checks
            if "messages" in request_data:
                messages = request_data["messages"]
                for message in messages:
                    if "content" in message and isinstance(message["content"], str):
                        content = message["content"]
                        
                        # Forbidden word check using WordListFilter
                        if check_prompt and self.word_list_filter:
                            passed, reason, _ = self.word_list_filter.filter(content)
                            if not passed:
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail={"error": reason or "Prohibited content detected", "status": "forbidden"}
                                )
                        
                        # Advanced injection check with filtering_patterns
                        injection_results = check_text_for_injections(content)
                        if injection_results:
                            warning = f"Injection detected: {list(injection_results.keys())[0]}"
                            raise HTTPException(
                                status_code=status.HTTP_403_FORBIDDEN,
                                detail={"error": warning, "status": "forbidden"}
                            )
                        
                        # Personal data check
                        if check_pii:
                            pii_results = check_pii_content(content)
                            if pii_results:
                                warning = f"Personal data detected: {list(pii_results.keys())}"
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail={"error": warning, "status": "forbidden"}
                                )
                        
                        # Toxic content check
                        if check_toxicity:
                            moderation_result = moderate_text(content)
                            if not moderation_result["is_approved"]:
                                warning = f"Toxic content detected: {moderation_result['recommendation']}"
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail={"error": warning, "status": "forbidden"}
                                )
            
            # Return sanitized data
            return request_data
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error in protect_endpoint: {str(e)}\n{traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "An error occurred while processing your request", "status": "error"}
            )
    
    def _register_patterns_api(self, app: FastAPI) -> None:
        """
        Register patterns API routes.
        
        Args:
            app: FastAPI application
        """
        patterns_router = APIRouter(prefix=self.patterns_api_prefix)
        
        # Authentication dependency
        async def get_api_key(api_key: str = Security(self.api_key_header)) -> str:
            if self.patterns_api_auth is None:
                # If no auth function configured, allow access (or require API key header presence)
                if not api_key:
                     raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API Key required but not provided",
                        headers={"WWW-Authenticate": "ApiKey"}
                     )
                return api_key # Allow if key is present (even if not validated)
                
            if self.patterns_api_auth(api_key):
                return api_key
                
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # --- Rewritten Patterns API using os/pathlib/json ---
        
        if not self.custom_patterns_dir or not os.path.isdir(self.custom_patterns_dir):
             logger.error(f"Custom patterns API enabled, but directory '{self.custom_patterns_dir}' is not valid.")
             # Optionally raise an error or disable API routes here
             return # Cannot register routes if dir is invalid
             
        base_path = Path(self.custom_patterns_dir)

        @patterns_router.get("", response_model=Dict[str, Any])
        async def list_patterns(api_key: str = Depends(get_api_key)):
            """List available custom pattern files."""
            try:
                pattern_info = []
                for item in base_path.iterdir():
                    if item.is_file() and item.suffix.lower() == '.json':
                        pattern_name = item.stem
                        try:
                            with open(item, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            pattern_info.append({
                                "name": pattern_name,
                                "file": str(item.relative_to(base_path.parent)), # Relative path
                                "word_count": len(data.get("keywords", []) if isinstance(data, dict) else []),
                                "pattern_count": len(data.get("patterns", []) if isinstance(data, dict) else [])
                            })
                        except Exception as load_err:
                            logger.error(f"Error reading pattern file {item}: {load_err}")
                            pattern_info.append({"name": pattern_name, "file": str(item.relative_to(base_path.parent)), "error": "Failed to load"})
                return {"patterns": pattern_info, "status": "success"}
            except Exception as e:
                logger.error(f"Error listing patterns: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error listing patterns: {str(e)}")

        @patterns_router.get("/{pattern_name}", response_model=Dict[str, Any])
        async def get_pattern(pattern_name: str, api_key: str = Depends(get_api_key)):
            """Get the content of a specific pattern file."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                raise HTTPException(status_code=404, detail=f"Pattern '{pattern_name}' not found")
            try:
                with open(pattern_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return {"name": pattern_name, "data": data, "status": "success"}
            except Exception as e:
                logger.error(f"Error getting pattern {pattern_name}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error getting pattern: {str(e)}")

        @patterns_router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
        async def create_pattern(data: Dict[str, Any], api_key: str = Depends(get_api_key)):
            """Create a new pattern file."""
            if "name" not in data:
                raise HTTPException(status_code=400, detail="Pattern name is required")
            
            name = data["name"]
            pattern_file = base_path / f"{name}.json"
            if pattern_file.exists():
                 raise HTTPException(status_code=409, detail=f"Pattern '{name}' already exists")

            # Validate structure (keywords/patterns lists)
            keywords: List[str] = data.get("keywords", [])
            patterns_list: List[Union[str, Dict[str, Any]]] = data.get("patterns", [])
            metadata: Dict[str, Any] = data.get("metadata", {})

            if not isinstance(keywords, list) or not isinstance(patterns_list, list) or not isinstance(metadata, dict):
                 raise HTTPException(status_code=400, detail="Invalid data structure: keywords/patterns must be lists, metadata a dict")

            # Prepare content for FileSystemPatternProvider format
            # Add explicit type hint for file_content and its 'patterns' key
            file_content: Dict[str, Any] = {"metadata": metadata, "keywords": keywords, "patterns": []}
            patterns_in_file: List[Union[str, Dict[str, Any]]] = file_content["patterns"]
            
            # Assume patterns_list contains dicts {"pattern": "...", "flags": [...], ...} or just strings
            for p_entry in patterns_list:
                if isinstance(p_entry, str):
                     # Simple pattern string
                     pattern_str = p_entry
                     flags_list = ["IGNORECASE"] # Default flags?
                elif isinstance(p_entry, dict) and isinstance(p_entry.get("pattern"), str):
                     pattern_str = p_entry["pattern"]
                     flags_list = p_entry.get("flags", ["IGNORECASE"])
                else:
                     raise HTTPException(status_code=400, detail=f"Invalid pattern entry format: {p_entry}")
                
                # Validate regex
                try:
                    re.compile(pattern_str)
                except re.error as e:
                    raise HTTPException(status_code=400, detail=f"Invalid regex '{pattern_str}': {str(e)}")
                # Append to the explicitly typed list
                patterns_in_file.append(p_entry)

            try:
                with open(pattern_file, 'w', encoding='utf-8') as f:
                    json.dump(file_content, f, indent=2)
                
                # Reload provider patterns? Optional, might impact performance.
                # if self.pattern_provider: self.pattern_provider.load_patterns()
                
                return {
                    "name": name,
                    "file": str(pattern_file.relative_to(base_path.parent)),
                    "word_count": len(keywords),
                    "pattern_count": len(patterns_list),
                    "status": "success"
                }
            except Exception as e:
                logger.error(f"Error creating pattern file {name}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error creating pattern: {str(e)}")

        @patterns_router.put("/{pattern_name}", response_model=Dict[str, Any])
        async def update_pattern(pattern_name: str, data: Dict[str, Any], api_key: str = Depends(get_api_key)):
            """Update an existing pattern file (overwrite)."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                raise HTTPException(status_code=404, detail=f"Pattern '{pattern_name}' not found")
            
            # Use the same validation and structure logic as create
            keywords: List[str] = data.get("keywords", [])
            patterns_list: List[Union[str, Dict[str, Any]]] = data.get("patterns", [])
            metadata: Dict[str, Any] = data.get("metadata", {})

            if not isinstance(keywords, list) or not isinstance(patterns_list, list) or not isinstance(metadata, dict):
                 raise HTTPException(status_code=400, detail="Invalid data structure")

            # Add explicit type hint for file_content and its 'patterns' key
            file_content: Dict[str, Any] = {"metadata": metadata, "keywords": keywords, "patterns": []}
            patterns_in_file: List[Union[str, Dict[str, Any]]] = file_content["patterns"]
            
            for p_entry in patterns_list:
                if isinstance(p_entry, str):
                    pattern_str = p_entry
                elif isinstance(p_entry, dict) and isinstance(p_entry.get("pattern"), str):
                    pattern_str = p_entry["pattern"]
                else:
                    raise HTTPException(status_code=400, detail=f"Invalid pattern entry format: {p_entry}")
                try:
                    re.compile(pattern_str)
                except re.error as e:
                    raise HTTPException(status_code=400, detail=f"Invalid regex '{pattern_str}': {str(e)}")
                # Append to the explicitly typed list
                patterns_in_file.append(p_entry)

            try:
                with open(pattern_file, 'w', encoding='utf-8') as f:
                    json.dump(file_content, f, indent=2)
                # Reload provider patterns? Optional.
                # if self.pattern_provider: self.pattern_provider.load_patterns()
                return {
                    "name": pattern_name,
                    "file": str(pattern_file.relative_to(base_path.parent)),
                    "word_count": len(keywords),
                    "pattern_count": len(patterns_list),
                    "status": "success"
                }
            except Exception as e:
                logger.error(f"Error updating pattern file {pattern_name}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error updating pattern: {str(e)}")

        @patterns_router.delete("/{pattern_name}", response_model=Dict[str, Any])
        async def delete_pattern(pattern_name: str, api_key: str = Depends(get_api_key)):
            """Delete a pattern file."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                raise HTTPException(status_code=404, detail=f"Pattern '{pattern_name}' not found")
            try:
                os.remove(pattern_file)
                # Reload provider patterns? Optional.
                # if self.pattern_provider: self.pattern_provider.load_patterns()
                return {"message": f"Pattern '{pattern_name}' deleted successfully", "status": "success"}
            except Exception as e:
                logger.error(f"Error deleting pattern {pattern_name}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error deleting pattern: {str(e)}")
        
        # Import a pattern from a JSON file (Placeholder)
        @patterns_router.post("/import", response_model=Dict[str, Any], status_code=status.HTTP_501_NOT_IMPLEMENTED)
        async def import_pattern(api_key: str = Depends(get_api_key)):
            # Implementation requires file upload handling specific to FastAPI (UploadFile)
            # This is left as a placeholder.
             return {"message": "Import functionality not yet implemented.", "status": "not_implemented"}
        
        # Register router
        app.include_router(patterns_router)

    async def rate_limiter(self, request: Request) -> None:
        """
            Rate limiter middleware function.
        
        Args:
                request: FastAPI request object
            
            Raises:
                HTTPException: If rate limit is exceeded
        """
            # Implement rate limiting logic
            # This code is simplified and should be completed with a real rate limiting system
        pass

# --- Utility Functions --- 

def get_fastapi_protector(app: Optional[FastAPI] = None) -> "FastAPIProtector": # Use forward reference and Optional
    """
    Dependency function to get the FastAPI protector instance.
    
    Args:
        app: FastAPI application
        
    Returns:
        FastAPIProtector instance
    """
    if app is None:
        # Cannot reliably get current app context here if used outside request scope
        raise RuntimeError("FastAPI app instance must be provided to get_fastapi_protector")
    
    if not hasattr(app.state, "resk_fastapi_protector") or not isinstance(app.state.resk_fastapi_protector, FastAPIProtector):
        raise RuntimeError("FastAPIProtector not initialized correctly for this application")
    
    return app.state.resk_fastapi_protector

# Utility function to secure a FastAPI app
def secure_fastapi_app(app: FastAPI, config: Optional[FastAPIProtectorConfig] = None) -> FastAPI:
    """
    Utility function to secure a FastAPI application with RESK protection.
    
    Args:
        app: FastAPI application to secure
        config: Configuration for the protector
        
    Returns:
        Secured FastAPI application
    """
    protector = FastAPIProtector(config=config or {'app': app})
    # The init_app method is called internally by the constructor if 'app' is in config
    # protector.init_app(app) # This might be redundant if app is passed in config
    return app # Return the app instance, init_app modifies it in place 