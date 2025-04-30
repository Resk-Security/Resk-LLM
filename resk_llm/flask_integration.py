"""
Flask integration module for securing LLM APIs.

This module provides classes and utilities to secure Flask applications
that interact with LLMs, particularly for protecting against injections,
data leakage, and other security concerns.
"""

from functools import wraps
from flask import request, jsonify, current_app, g, Blueprint, Flask, Response
import re
import logging
import json
from typing import Callable, Dict, Any, List, Optional, Union, TypeVar, Type, cast
import traceback
import os
from pathlib import Path

from resk_llm.providers_integration import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager
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

# Type definitions
FlaskProtectorConfig = Dict[str, Any]
FlaskApp = Union[Flask, Any]  # Flask app or similar WSGI application
FlaskRequest = Any
FlaskResponse = Any

# Logger configuration
logger = logging.getLogger(__name__)

class FlaskProtector(ProtectorBase[Union[FlaskApp, Dict[str, Any], List[Any], str], 
                                  Union[FlaskApp, Dict[str, Any], List[Any], str],
                                  FlaskProtectorConfig]):
    """
    Protector for Flask applications that interact with LLMs.
    
    This class provides protection mechanisms for Flask applications,
    implementing request and response sanitization to prevent prompt injections,
    XSS attacks and data leakage.
    """
    
    def __init__(self, config: Optional[FlaskProtectorConfig] = None):
        """
        Initialize the Flask protector.
        
        Args:
            config: Configuration dictionary which may contain:
                app: Flask application
                model: OpenAI model to use
                rate_limit: Requests per minute limit
                request_sanitization: Enable request sanitization
                response_sanitization: Enable response sanitization
                custom_patterns_dir: Directory for custom patterns
                enable_patterns_api: Enable patterns management API
                patterns_api_prefix: Prefix for patterns API routes
                patterns_api_auth: Authentication function for patterns API
        """
        default_config: FlaskProtectorConfig = {
            'app': None,
            'model': 'gpt-4o',
            'rate_limit': 60,
            'request_sanitization': True,
            'response_sanitization': True,
            'custom_patterns_dir': None,
            'enable_patterns_api': False,
            'patterns_api_prefix': '/api/patterns',
            'patterns_api_auth': None
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        # Initialize properties from config
        self.rate_limit = self.config.get('rate_limit', 60)
        self.request_sanitization = self.config.get('request_sanitization', True)
        self.response_sanitization = self.config.get('response_sanitization', True)
        self.protector = OpenAIProtector(config={'model': self.config.get('model', 'gpt-4o')})
        
        # Initialize components based on config
        self.pattern_provider = self.config.get(
            'pattern_provider', 
            FileSystemPatternProvider(config=self.config.get('pattern_provider_config'))
        )
        self.word_list_filter = self.config.get(
            'word_list_filter', 
            WordListFilter(config={'pattern_provider': self.pattern_provider, **self.config.get('word_list_filter_config', {})})
        )
        
        self.exempt_routes = set(self.config.get('exempt_routes', []))
        
        # Initialize app if provided
        app = self.config.get('app')
        if app is not None:
            self.init_app(app)
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if not isinstance(self.config.get('rate_limit', 60), int):
            raise ValueError("rate_limit must be an integer")
            
        if not isinstance(self.config.get('request_sanitization', True), bool):
            raise ValueError("request_sanitization must be a boolean")
            
        if not isinstance(self.config.get('response_sanitization', True), bool):
            raise ValueError("response_sanitization must be a boolean")
            
        if 'custom_patterns_dir' in self.config and self.config['custom_patterns_dir'] is not None:
            if not isinstance(self.config['custom_patterns_dir'], str):
                raise ValueError("custom_patterns_dir must be a string or None")
            
        if not isinstance(self.config.get('enable_patterns_api', False), bool):
            raise ValueError("enable_patterns_api must be a boolean")
            
        if not isinstance(self.config.get('patterns_api_prefix', '/api/patterns'), str):
            raise ValueError("patterns_api_prefix must be a string")
    
    def update_config(self, config: FlaskProtectorConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values to update
        """
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
        
        if 'enable_patterns_api' in config:
            self.enable_patterns_api = config['enable_patterns_api']
        
        if 'patterns_api_prefix' in config:
            self.patterns_api_prefix = config['patterns_api_prefix']
        
        if 'patterns_api_auth' in config:
            self.patterns_api_auth = config['patterns_api_auth']
        
        # Update components based on new config
        self.pattern_provider = self.config.get(
            'pattern_provider', 
            FileSystemPatternProvider(config=self.config.get('pattern_provider_config'))
        )
        self.word_list_filter = self.config.get(
            'word_list_filter', 
            WordListFilter(config={'pattern_provider': self.pattern_provider, **self.config.get('word_list_filter_config', {})})
        )
        
        self.exempt_routes = set(self.config.get('exempt_routes', []))
    
    def protect(self, data: Union[FlaskApp, Dict[str, Any], List[Any], str]) -> Union[FlaskApp, Dict[str, Any], List[Any], str]:
        """
        Main protection method required by ProtectorBase.
        Determines the type of data and applies the appropriate protection.
        
        Args:
            data: Input data to protect (Flask app, request data, etc.)
            
        Returns:
            Protected version of the input
        """
        try:
            if hasattr(data, '__module__') and hasattr(data.__class__, '__name__'):
                if 'flask' in data.__module__ and data.__class__.__name__ == 'Flask':
                    return self.init_app(cast(FlaskApp, data))
                
            # Apply appropriate sanitization based on data type
            if isinstance(data, dict):
                return self._sanitize_nested_dict(data)
            elif isinstance(data, list):
                return self._sanitize_list(data)
            elif isinstance(data, str):
                return self._sanitize_text(data)
            else:
                # For other types, just return as is
                return data
        except Exception as e:
            logger.error(f"Error in protect method: {str(e)}")
            return data
    
    def protect_input(self, prompt: Any, **kwargs) -> Any:
        """
        Apply security measures to the input before sending to the LLM.
        Implementation of abstract method from ProtectorBase.
        
        Args:
            prompt: The input prompt or data
            **kwargs: Additional arguments
            
        Returns:
            The sanitized input
        """
        return self.protect(prompt)
    
    def protect_output(self, response: Any, **kwargs) -> Any:
        """
        Apply security measures to the output received from the LLM.
        Implementation of abstract method from ProtectorBase.
        
        Args:
            response: The response from the LLM
            **kwargs: Additional arguments
            
        Returns:
            The sanitized response
        """
        return self._sanitize_response(response)
            
    def init_app(self, app: FlaskApp) -> FlaskApp:
        """
        Initialize the Flask application with security middlewares.
        
        Args:
            app: Flask application
            
        Returns:
            The initialized Flask application
        """
        # Add security headers
        @app.after_request
        def add_security_headers(response: Response) -> Response:
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            return response
        
        # Sanitization middleware
        @app.before_request
        def sanitize_request() -> None:
            if not self.request_sanitization:
                return
                
            # Sanitize query parameters
            if request.args:
                g.sanitized_args = {}
                for key, value in request.args.items():
                    if isinstance(value, str):
                        g.sanitized_args[key] = self._sanitize_text(value)
                    else:
                        g.sanitized_args[key] = value
            
            # Sanitize JSON body
            if request.is_json:
                try:
                    json_data = request.get_json()
                    if json_data:
                        g.sanitized_json = self._sanitize_nested_dict(json_data)
                except Exception as e:
                    logger.error(f"Error during JSON sanitization: {str(e)}")
        
        # Configure patterns API if enabled
        if self.enable_patterns_api:
            self._register_patterns_api(app)

        # Store instance in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['resk_flask_protector'] = self
        
        return app
    
    def _sanitize_text(self, text: str) -> str:
        """
        Sanitize text input.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text
        """
        # Return non-strings as is
        if not isinstance(text, str):
            return text
            
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
                    # Log and return original text (or potentially modify/raise)
                    logger.warning(f"WordListFilter check failed during sanitization: {reason}. Returning original text.")
                    # return "[REDACTED]" # Option: Replace if blocked
                else:
                     # Use text returned by filter (potentially unchanged)
                    sanitized_text = filtered_text
            
            # TODO: Add other basic sanitization if needed (e.g., HTML escaping)
            # sanitized_text = html.escape(sanitized_text)
            
        except Exception as e:
            logger.error(f"Error during text sanitization: {str(e)}")
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
                result.append(self._sanitize_text(item))
            elif isinstance(item, dict):
                result.append(self._sanitize_nested_dict(item))
            elif isinstance(item, list):
                result.append(self._sanitize_list(item))
            else:
                result.append(item)
        return result
        
    def protect_route(self, check_prompt: bool = True, check_pii: bool = False, check_toxicity: bool = False):
        """
        Decorator to protect a Flask route that interacts with an LLM.
        
        Args:
            check_prompt: Check if the prompt contains forbidden words
            check_pii: Check if the prompt contains personal data
            check_toxicity: Check if the prompt contains toxic content
            
        Returns:
            Decorator
        """
        def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(f)
            def decorated_function(*args: Any, **kwargs: Any) -> Any:
                try:
                    # Use sanitized data if available
                    if hasattr(g, 'sanitized_json'):
                        request_data = g.sanitized_json
                    elif request.is_json:
                        request_data = request.get_json()
                    else:
                        request_data = {}
                    
                    # Prompt checks
                    if "messages" in request_data:
                        messages = request_data["messages"]
                        for message in messages:
                            if "content" in message and isinstance(message["content"], str):
                                content = message["content"]
                                
                                # Forbidden word check using WordListFilter
                                if check_prompt:
                                    # Use self.word_list_filter which is initialized
                                    if self.word_list_filter:
                                        passed, reason, _ = self.word_list_filter.filter(content)
                                        if not passed:
                                            return jsonify({"error": reason or "Prohibited content detected", "status": "forbidden"}), 403
                                    else:
                                         logger.warning("WordListFilter not available for check_prompt in protect_route")
                                
                                # Advanced injection check with filtering_patterns
                                injection_results = check_text_for_injections(content)
                                if injection_results:
                                    warning = f"Injection detected: {list(injection_results.keys())[0]}"
                                    return jsonify({"error": warning, "status": "forbidden"}), 403
                                
                                # Personal data check
                                if check_pii:
                                    pii_results = check_pii_content(content)
                                    if pii_results:
                                        warning = f"Personal data detected: {list(pii_results.keys())}"
                                        return jsonify({"error": warning, "status": "forbidden"}), 403
                                
                                # Toxic content check
                                if check_toxicity:
                                    moderation_result = moderate_text(content)
                                    if not moderation_result["is_approved"]:
                                        warning = f"Toxic content detected: {moderation_result['recommendation']}"
                                        return jsonify({"error": warning, "status": "forbidden"}), 403
                    
                    # Execute route function
                    result = f(*args, **kwargs)
                    
                    # Sanitize response if necessary
                    if self.response_sanitization:
                        if isinstance(result, tuple) and len(result) >= 1:
                            # Handle (response, status_code) tuple
                            resp = result[0]
                            if isinstance(resp, dict):
                                sanitized_resp = self._sanitize_response(resp)
                                return (sanitized_resp,) + result[1:]
                        elif isinstance(result, dict):
                            return self._sanitize_response(result)
                        
                    return result
                except Exception as e:
                    logger.error(f"Error in protect_route: {str(e)}\n{traceback.format_exc()}")
                    return jsonify({
                        "error": "An error occurred while processing your request",
                        "status": "error"
                    }), 500
            
            return decorated_function
        return decorator
    
    def _sanitize_response(self, response: Any) -> Any:
        """
        Sanitize the response before sending it to the client.
        
        Args:
            response: Response to sanitize
            
        Returns:
            Sanitized response
        """
        if isinstance(response, dict):
            return self._sanitize_nested_dict(response)
        elif isinstance(response, list):
            return [self._sanitize_response(item) for item in response]
        elif isinstance(response, str):
            return self._sanitize_text(response)
        else:
            return response
    
    def _register_patterns_api(self, app: FlaskApp) -> None:
        """
        Register patterns API routes.
        
        Args:
            app: Flask application
        """
        patterns_bp = Blueprint('resk_patterns', __name__, url_prefix=self.patterns_api_prefix)
        
        # --- Rewritten Patterns API using os/pathlib/json ---        
        if not self.custom_patterns_dir or not os.path.isdir(self.custom_patterns_dir):
             logger.error(f"Custom patterns API enabled, but directory '{self.custom_patterns_dir}' is not valid.")
             # Optionally raise an error or disable API routes here
             return # Cannot register blueprint if dir is invalid
             
        base_path = Path(self.custom_patterns_dir)

        # Function to secure API routes
        def secure_patterns_api(f: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Check authentication if a function is provided
                if self.patterns_api_auth and not self.patterns_api_auth():
                    return jsonify({"error": "Unauthorized", "status": "unauthorized"}), 401
                return f(*args, **kwargs)
            return wrapper
        
        @patterns_bp.route('', methods=['GET'])
        @secure_patterns_api
        def list_patterns():
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
                return jsonify({"patterns": pattern_info, "status": "success"})
            except Exception as e:
                logger.error(f"Error listing patterns: {str(e)}")
                return jsonify({"error": f"Error listing patterns: {str(e)}", "status": "error"}), 500

        @patterns_bp.route('/<pattern_name>', methods=['GET'])
        @secure_patterns_api
        def get_pattern(pattern_name: str):
            """Get the content of a specific pattern file."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                return jsonify({"error": f"Pattern '{pattern_name}' not found", "status": "not_found"}), 404
            try:
                with open(pattern_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return jsonify({"name": pattern_name, "data": data, "status": "success"})
            except Exception as e:
                logger.error(f"Error getting pattern {pattern_name}: {str(e)}")
                return jsonify({"error": f"Error getting pattern: {str(e)}", "status": "error"}), 500

        @patterns_bp.route('', methods=['POST'])
        @secure_patterns_api
        def create_pattern():
            """Create a new pattern file."""
            try:
                data = request.get_json()
                if not data or "name" not in data:
                    return jsonify({"error": "Pattern name is required", "status": "bad_request"}), 400
                
                name = data["name"]
                pattern_file = base_path / f"{name}.json"
                if pattern_file.exists():
                     return jsonify({"error": f"Pattern '{name}' already exists", "status": "conflict"}), 409

                # Validate structure (keywords/patterns lists)
                keywords = data.get("keywords", [])
                patterns_list = data.get("patterns", [])
                metadata = data.get("metadata", {})

                if not isinstance(keywords, list) or not isinstance(patterns_list, list) or not isinstance(metadata, dict):
                     return jsonify({"error": "Invalid data structure: keywords/patterns must be lists, metadata a dict", "status": "bad_request"}), 400

                # Prepare content for FileSystemPatternProvider format
                file_content = {"metadata": metadata, "keywords": keywords, "patterns": []}
                for p_entry in patterns_list:
                    if isinstance(p_entry, str):
                         pattern_str = p_entry
                    elif isinstance(p_entry, dict) and isinstance(p_entry.get("pattern"), str):
                         pattern_str = p_entry["pattern"]
                    else:
                         return jsonify({"error": f"Invalid pattern entry format: {p_entry}", "status": "bad_request"}), 400
                    
                    # Validate regex
                    try:
                        re.compile(pattern_str)
                    except re.error as e:
                        return jsonify({"error": f"Invalid regex '{pattern_str}': {str(e)}", "status": "bad_request"}), 400
                    # Add type assertion for append
                    cast(list, file_content["patterns"]).append(p_entry)

                with open(pattern_file, 'w', encoding='utf-8') as f:
                    json.dump(file_content, f, indent=2)
                
                return jsonify({
                    "name": name,
                    "file": str(pattern_file.relative_to(base_path.parent)),
                    "word_count": len(keywords),
                    "pattern_count": len(patterns_list),
                    "status": "success"
                }), 201
            except Exception as e:
                logger.error(f"Error creating pattern: {str(e)}")
                return jsonify({"error": f"Error creating pattern: {str(e)}", "status": "error"}), 500

        @patterns_bp.route('/<pattern_name>', methods=['PUT'])
        @secure_patterns_api
        def update_pattern(pattern_name: str):
            """Update an existing pattern file (overwrite)."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                return jsonify({"error": f"Pattern '{pattern_name}' not found", "status": "not_found"}), 404
            
            try:
                data = request.get_json()
                if not data:
                    return jsonify({"error": "No data provided", "status": "bad_request"}), 400
                
                # Use the same validation and structure logic as create
                keywords = data.get("keywords", [])
                patterns_list = data.get("patterns", [])
                metadata = data.get("metadata", {})

                if not isinstance(keywords, list) or not isinstance(patterns_list, list) or not isinstance(metadata, dict):
                     return jsonify({"error": "Invalid data structure", "status": "bad_request"}), 400

                file_content = {"metadata": metadata, "keywords": keywords, "patterns": []}
                for p_entry in patterns_list:
                    if isinstance(p_entry, str):
                        pattern_str = p_entry
                    elif isinstance(p_entry, dict) and isinstance(p_entry.get("pattern"), str):
                        pattern_str = p_entry["pattern"]
                    else:
                         return jsonify({"error": f"Invalid pattern entry format: {p_entry}", "status": "bad_request"}), 400
                    try:
                        re.compile(pattern_str)
                    except re.error as e:
                        return jsonify({"error": f"Invalid regex '{pattern_str}': {str(e)}", "status": "bad_request"}), 400
                    # Add type assertion for append
                    cast(list, file_content["patterns"]).append(p_entry)

                with open(pattern_file, 'w', encoding='utf-8') as f:
                    json.dump(file_content, f, indent=2)
                
                return jsonify({
                    "name": pattern_name,
                    "file": str(pattern_file.relative_to(base_path.parent)),
                    "word_count": len(keywords),
                    "pattern_count": len(patterns_list),
                    "status": "success"
                })
            except Exception as e:
                logger.error(f"Error updating pattern {pattern_name}: {str(e)}")
                return jsonify({"error": f"Error updating pattern: {str(e)}", "status": "error"}), 500

        @patterns_bp.route('/<pattern_name>', methods=['DELETE'])
        @secure_patterns_api
        def delete_pattern(pattern_name: str):
            """Delete a pattern file."""
            pattern_file = base_path / f"{pattern_name}.json"
            if not pattern_file.is_file():
                return jsonify({"error": f"Pattern '{pattern_name}' not found", "status": "not_found"}), 404
            try:
                os.remove(pattern_file)
                return jsonify({"message": f"Pattern '{pattern_name}' deleted successfully", "status": "success"})
            except Exception as e:
                logger.error(f"Error deleting pattern {pattern_name}: {str(e)}")
                return jsonify({"error": f"Error deleting pattern: {str(e)}", "status": "error"}), 500
        
        # Import a pattern from a JSON file (Placeholder - requires file upload handling)
        @patterns_bp.route('/import', methods=['POST'])
        @secure_patterns_api
        def import_pattern():
             return jsonify({"message": "Import functionality not implemented yet.", "status": "not_implemented"}), 501

        # Register Blueprint
        app.register_blueprint(patterns_bp)
            
    def rate_limiter(self, key_func: Optional[Callable[..., str]] = None, limit: Optional[int] = None) -> Callable:
        """
        Decorator to limit the rate of requests to LLMs.
        
        Args:
            key_func: Function that returns a key to identify the user
            limit: Requests per minute limit (overrides default value)
            
        Returns:
            Decorator
        """
        limit = limit or self.rate_limit
        
        def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(f)
            def decorated_function(*args: Any, **kwargs: Any) -> Any:
                # Implement rate limiting logic
                # This code is simplified and should be completed with a real rate limiting system
                return f(*args, **kwargs)
            return decorated_function
        return decorator


def get_flask_protector(app: Optional[FlaskApp] = None) -> FlaskProtector:
    """
    Get the Flask protector instance.
    
    Args:
        app: Flask application (uses current_app if None)
        
    Returns:
        FlaskProtector instance
        
    Raises:
        RuntimeError: If FlaskProtector not initialized for the application
    """
    if app is None:
        app = current_app
        
    if not hasattr(app, 'extensions') or 'resk_flask_protector' not in app.extensions:
        raise RuntimeError("FlaskProtector not initialized for this application")
        
    return app.extensions['resk_flask_protector']


def secure_flask_app(app: FlaskApp, config: Optional[FlaskProtectorConfig] = None) -> FlaskApp:
    """
    Secure a Flask application with RESK protection.
    
    Args:
        app: Flask application to secure
        config: Configuration for the protector
        
    Returns:
        Secured Flask application
    """
    protector = FlaskProtector(config=config or {'app': app})
    return protector.protect(app) 