"""
Flask integration module for securing LLM APIs.
"""

from functools import wraps
from flask import request, jsonify, current_app, g, Blueprint
import re
import logging
import json
from typing import Callable, Dict, Any, List, Optional, Union
import traceback
import os
from pathlib import Path

from resk_llm.providers_integration import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager
from resk_llm.tokenizer_protection import ReskWordsLists, CustomPatternManager
from resk_llm.filtering_patterns import (
    check_for_obfuscation, 
    sanitize_text_from_obfuscation,
    check_text_for_injections,
    check_pii_content,
    moderate_text
)

# Logger configuration
logger = logging.getLogger(__name__)

class FlaskProtector:
    """
    Protector for Flask applications that interact with LLMs.
    Protects against injections, XSS attacks and data leakage.
    """
    def __init__(self, 
                 app=None, 
                 model: str = "gpt-4o", 
                 rate_limit: int = 60,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 custom_patterns_dir: Optional[str] = None,
                 enable_patterns_api: bool = False,
                 patterns_api_prefix: str = "/api/patterns",
                 patterns_api_auth: Optional[Callable] = None):
        """
        Initialize the Flask protector.
        
        Args:
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
        self.rate_limit = rate_limit
        self.request_sanitization = request_sanitization
        self.response_sanitization = response_sanitization
        self.protector = OpenAIProtector(model=model)
        
        # Custom patterns management
        self.custom_patterns_dir = custom_patterns_dir
        if custom_patterns_dir:
            self.pattern_manager = CustomPatternManager(base_directory=custom_patterns_dir)
        else:
            self.pattern_manager = CustomPatternManager()
        
        # Patterns API options
        self.enable_patterns_api = enable_patterns_api
        self.patterns_api_prefix = patterns_api_prefix
        self.patterns_api_auth = patterns_api_auth
        
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app):
        """
        Initialize the Flask application with security middlewares.
        
        Args:
            app: Flask application
        """
        # Add security headers
        @app.after_request
        def add_security_headers(response):
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            return response
        
        # Sanitization middleware
        @app.before_request
        def sanitize_request():
            if not self.request_sanitization:
                return
                
            # Sanitize query parameters
            if request.args:
                g.sanitized_args = {}
                for key, value in request.args.items():
                    if isinstance(value, str):
                        # Check for emojis and special characters
                        obfuscation = check_for_obfuscation(value)
                        if obfuscation:
                            # Normalize text if obfuscation attempts are detected
                            value = sanitize_text_from_obfuscation(value)
                        
                        g.sanitized_args[key] = self.protector.sanitize_input(value)
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

        # Store statistics
        app.extensions['resk_flask_protector'] = self
        
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
                # Check for emojis and special characters
                obfuscation = check_for_obfuscation(value)
                if obfuscation:
                    # Normalize text if obfuscation attempts are detected
                    value = sanitize_text_from_obfuscation(value)
                
                result[key] = self.protector.sanitize_input(value)
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
                # Check for emojis and special characters
                obfuscation = check_for_obfuscation(item)
                if obfuscation:
                    # Normalize text if obfuscation attempts are detected
                    item = sanitize_text_from_obfuscation(item)
                    
                result.append(self.protector.sanitize_input(item))
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
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
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
                                
                                # Forbidden word check
                                if check_prompt:
                                    warning = self.protector.ReskWordsLists.check_input(content)
                                    if warning:
                                        return jsonify({"error": warning, "status": "forbidden"}), 403
                                
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
                    if self.response_sanitization and isinstance(result, dict):
                        result = self._sanitize_response(result)
                        
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
            # Check for emojis and special characters
            obfuscation = check_for_obfuscation(response)
            if obfuscation:
                # Normalize text if obfuscation attempts are detected
                response = sanitize_text_from_obfuscation(response)
            
            return self.protector.sanitize_input(response)
        else:
            return response
    
    def _register_patterns_api(self, app):
        """
        Register patterns API routes.
        
        Args:
            app: Flask application
        """
        patterns_bp = Blueprint('resk_patterns', __name__, url_prefix=self.patterns_api_prefix)
        
        # Function to secure API routes
        def secure_patterns_api(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # Check authentication if a function is provided
                if self.patterns_api_auth and not self.patterns_api_auth():
                    return jsonify({"error": "Unauthorized", "status": "unauthorized"}), 401
                return f(*args, **kwargs)
            return wrapper
        
        # List all available patterns
        @patterns_bp.route('', methods=['GET'])
        @secure_patterns_api
        def list_patterns():
            try:
                patterns = self.pattern_manager.list_custom_pattern_files()
                pattern_info = []
                
                for pattern_file in patterns:
                    try:
                        # Get just the filename
                        pattern_name = Path(pattern_file).stem
                        
                        # Load file to get information
                        data = self.pattern_manager.load_custom_pattern_file(pattern_name)
                        
                        # Add information to result
                        pattern_info.append({
                            "name": pattern_name,
                            "file": pattern_file,
                            "word_count": len(data.get("prohibited_words", [])),
                            "pattern_count": len(data.get("prohibited_patterns", []))
                        })
                    except Exception as e:
                        logger.error(f"Error loading pattern {pattern_file}: {str(e)}")
                
                return jsonify({
                    "patterns": pattern_info,
                    "status": "success"
                })
            except Exception as e:
                logger.error(f"Error listing patterns: {str(e)}")
                return jsonify({
                    "error": f"Error listing patterns: {str(e)}",
                    "status": "error"
                }), 500
        
        # Get a specific pattern
        @patterns_bp.route('/<pattern_name>', methods=['GET'])
        @secure_patterns_api
        def get_pattern(pattern_name):
            try:
                try:
                    data = self.pattern_manager.load_custom_pattern_file(pattern_name)
                    return jsonify({
                        "name": pattern_name,
                        "data": data,
                        "status": "success"
                    })
                except FileNotFoundError:
                    return jsonify({
                        "error": f"Pattern '{pattern_name}' not found",
                        "status": "not_found"
                    }), 404
            except Exception as e:
                logger.error(f"Error getting pattern {pattern_name}: {str(e)}")
                return jsonify({
                    "error": f"Error getting pattern: {str(e)}",
                    "status": "error"
                }), 500
        
        # Create a new pattern
        @patterns_bp.route('', methods=['POST'])
        @secure_patterns_api
        def create_pattern():
            try:
                data = request.get_json()
                if not data or "name" not in data:
                    return jsonify({
                        "error": "Pattern name is required",
                        "status": "bad_request"
                    }), 400
                
                name = data["name"]
                words = data.get("prohibited_words", [])
                patterns = data.get("prohibited_patterns", [])
                
                # Validate regex patterns to avoid errors
                for pattern in patterns:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        return jsonify({
                            "error": f"Invalid regex pattern '{pattern}': {str(e)}",
                            "status": "bad_request"
                        }), 400
                
                # Create pattern file
                file_path = self.pattern_manager.create_custom_pattern_file(
                    name, 
                    words=words, 
                    patterns=patterns
                )
                
                return jsonify({
                    "name": name,
                    "file": file_path,
                    "word_count": len(words),
                    "pattern_count": len(patterns),
                    "status": "success"
                }), 201
            except Exception as e:
                logger.error(f"Error creating pattern: {str(e)}")
                return jsonify({
                    "error": f"Error creating pattern: {str(e)}",
                    "status": "error"
                }), 500
        
        # Update an existing pattern
        @patterns_bp.route('/<pattern_name>', methods=['PUT'])
        @secure_patterns_api
        def update_pattern(pattern_name):
            try:
                # Check if pattern exists
                try:
                    self.pattern_manager.load_custom_pattern_file(pattern_name)
                except FileNotFoundError:
                    return jsonify({
                        "error": f"Pattern '{pattern_name}' not found",
                        "status": "not_found"
                    }), 404
                
                # Get new data
                data = request.get_json()
                if not data:
                    return jsonify({
                        "error": "No data provided",
                        "status": "bad_request"
                    }), 400
                
                words = data.get("prohibited_words", [])
                patterns = data.get("prohibited_patterns", [])
                
                # Validate regex patterns to avoid errors
                for pattern in patterns:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        return jsonify({
                            "error": f"Invalid regex pattern '{pattern}': {str(e)}",
                            "status": "bad_request"
                        }), 400
                
                # Delete old file
                self.pattern_manager.delete_custom_pattern_file(pattern_name)
                
                # Create new file with same data
                file_path = self.pattern_manager.create_custom_pattern_file(
                    pattern_name, 
                    words=words, 
                    patterns=patterns
                )
                
                return jsonify({
                    "name": pattern_name,
                    "file": file_path,
                    "word_count": len(words),
                    "pattern_count": len(patterns),
                    "status": "success"
                })
            except Exception as e:
                logger.error(f"Error updating pattern {pattern_name}: {str(e)}")
                return jsonify({
                    "error": f"Error updating pattern: {str(e)}",
                    "status": "error"
                }), 500
        
        # Delete a pattern
        @patterns_bp.route('/<pattern_name>', methods=['DELETE'])
        @secure_patterns_api
        def delete_pattern(pattern_name):
            try:
                success = self.pattern_manager.delete_custom_pattern_file(pattern_name)
                if success:
                    return jsonify({
                        "message": f"Pattern '{pattern_name}' deleted successfully",
                        "status": "success"
                    })
                else:
                    return jsonify({
                        "error": f"Pattern '{pattern_name}' not found",
                        "status": "not_found"
                    }), 404
            except Exception as e:
                logger.error(f"Error deleting pattern {pattern_name}: {str(e)}")
                return jsonify({
                    "error": f"Error deleting pattern: {str(e)}",
                    "status": "error"
                }), 500
        
        # Import a pattern from a JSON file
        @patterns_bp.route('/import', methods=['POST'])
        @secure_patterns_api
        def import_pattern():
            try:
                if 'file' not in request.files:
                    return jsonify({
                        "error": "No file provided",
                        "status": "bad_request"
                    }), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({
                        "error": "Empty file name",
                        "status": "bad_request"
                    }), 400
                
                # Check extension
                if not file.filename.endswith('.json'):
                    return jsonify({
                        "error": "File must be in JSON format",
                        "status": "bad_request"
                    }), 400
                
                # Create temporary file
                temp_dir = Path(self.pattern_manager.base_directory) / "temp"
                temp_dir.mkdir(exist_ok=True)
                temp_file = temp_dir / file.filename
                
                file.save(temp_file)
                
                # Load and validate file
                try:
                    with open(temp_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    if not isinstance(data, dict) or "prohibited_words" not in data or "prohibited_patterns" not in data:
                        os.remove(temp_file)
                        return jsonify({
                            "error": "Invalid pattern file format",
                            "status": "bad_request"
                        }), 400
                    
                    # Validate regex patterns
                    for pattern in data.get("prohibited_patterns", []):
                        try:
                            re.compile(pattern)
                        except re.error as e:
                            os.remove(temp_file)
                            return jsonify({
                                "error": f"Invalid regex pattern '{pattern}': {str(e)}",
                                "status": "bad_request"
                            }), 400
                    
                    # Create pattern
                    name = Path(file.filename).stem
                    file_path = self.pattern_manager.create_custom_pattern_file(
                        name, 
                        words=data.get("prohibited_words", []), 
                        patterns=data.get("prohibited_patterns", [])
                    )
                    
                    # Delete temporary file
                    os.remove(temp_file)
                    
                    return jsonify({
                        "name": name,
                        "file": file_path,
                        "word_count": len(data.get("prohibited_words", [])),
                        "pattern_count": len(data.get("prohibited_patterns", [])),
                        "status": "success"
                    }), 201
                    
                except json.JSONDecodeError:
                    os.remove(temp_file)
                    return jsonify({
                        "error": "Invalid JSON file",
                        "status": "bad_request"
                    }), 400
                    
            except Exception as e:
                logger.error(f"Error importing pattern: {str(e)}")
                return jsonify({
                    "error": f"Error importing pattern: {str(e)}",
                    "status": "error"
                }), 500
        
        # Register Blueprint
        app.register_blueprint(patterns_bp)
            
    def rate_limiter(self, key_func=None, limit: Optional[int] = None):
        """
        Decorator to limit the rate of requests to LLMs.
        
        Args:
            key_func: Function that returns a key to identify the user
            limit: Requests per minute limit (overrides default value)
            
        Returns:
            Decorator
        """
        limit = limit or self.rate_limit
        
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Implement rate limiting logic
                # This code is simplified and should be completed with a real rate limiting system
                return f(*args, **kwargs)
            return decorated_function
        return decorator 