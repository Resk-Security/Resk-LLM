import logging
import random
import string
import hashlib
import re
import uuid
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from datetime import datetime

from resk_llm.core.abc import SecurityComponent, DetectorBase

class CanaryTokenManager(SecurityComponent[Dict[str, Any]]):
    """
    Manages canary tokens for detecting data leaks in LLM prompts.
    Inserts unique tokens into prompts and checks if they appear in LLM responses.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the canary token manager.
        
        Args:
            config: Configuration dictionary with options:
                - token_length: Length of the canary tokens if random string is used
                - use_uuid: Whether to use UUIDs instead of random strings
                - token_prefix: Prefix for the canary tokens
                - token_suffix: Suffix for the canary tokens
        """
        default_config = {
            'token_length': 10,
            'use_uuid': True,
            'token_prefix': 'CT',
            'token_suffix': 'ZZ'
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        self.logger = logging.getLogger(__name__)
        
        # Track active tokens and their context
        self.active_tokens: Dict[str, Dict[str, Any]] = {}  # Dict[token_id, token_data]
        self.leaked_tokens: Dict[str, Dict[str, Any]] = {}  # Dict[token_id, leak_data]
        
        # Tracking metrics
        self.tokens_generated = 0
        self.tokens_leaked = 0
        self.creation_time = datetime.now()
    
    def _validate_config(self) -> None:
        """Validate the provided configuration."""
        if 'token_length' in self.config and not isinstance(self.config['token_length'], int):
            raise ValueError("token_length must be an integer")
        
        if 'use_uuid' in self.config and not isinstance(self.config['use_uuid'], bool):
            raise ValueError("use_uuid must be a boolean")
            
        if 'token_prefix' in self.config and not isinstance(self.config['token_prefix'], str):
            raise ValueError("token_prefix must be a string")
            
        if 'token_suffix' in self.config and not isinstance(self.config['token_suffix'], str):
            raise ValueError("token_suffix must be a string")
    
    def update_config(self, config: Dict[str, Any]) -> None:
        """Update the component's configuration."""
        self.config.update(config)
        self._validate_config()
    
    def _generate_random_token(self) -> str:
        """Generate a random string token."""
        characters = string.ascii_letters + string.digits
        random_part = ''.join(random.choice(characters) for _ in range(self.config['token_length']))
        return f"{self.config['token_prefix']}{random_part}{self.config['token_suffix']}"
    
    def _generate_uuid_token(self) -> str:
        """Generate a UUID-based token."""
        # Use a UUID and keep only the first part to make it shorter
        uuid_str = str(uuid.uuid4()).split('-')[0]
        return f"{self.config['token_prefix']}{uuid_str}{self.config['token_suffix']}"
    
    def generate_token(self, context_info: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a new canary token and register it.
        
        Args:
            context_info: Optional context information about where the token is used
            
        Returns:
            The generated token string
        """
        # Generate a new token
        if self.config['use_uuid']:
            token = self._generate_uuid_token()
        else:
            token = self._generate_random_token()
        
        # Create a unique ID for this token instance
        token_id = hashlib.md5(token.encode()).hexdigest()
        
        # Register the token
        self.active_tokens[token_id] = {
            'token': token,
            'created_at': datetime.now(),
            'context_info': context_info or {},
            'is_active': True
        }
        
        self.tokens_generated += 1
        self.logger.debug(f"Generated canary token: {token_id}")
        
        return token
    
    def create_token(self, context_info: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a new canary token (alias for generate_token).
        
        Args:
            context_info: Optional context information about where the token is used
            
        Returns:
            The generated token string
        """
        return self.generate_token(context_info)
    
    def insert_canary_token(self, text: str, context_info: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """
        Insert a canary token into the text.
        
        Args:
            text: The text to insert the token into
            context_info: Optional context information
            
        Returns:
            Tuple of (modified_text, token)
        """
        token = self.generate_token(context_info)
        
        # Simple insertion at the end as a comment, using different formats based on context
        if context_info and context_info.get('format') == 'json':
            # For JSON, add as a hidden field
            text = text.rstrip()
            if text.endswith('}'):
                # Insert as a property in the JSON
                modified_text = text[:-1] + f', "__ct": "{token}"}}'
            else:
                # Just append as text if not proper JSON
                modified_text = text + f' /* {token} */'
        elif context_info and context_info.get('format') == 'markdown':
            # For markdown, add as a hidden comment
            modified_text = text + f'\n<!-- {token} -->'
        elif context_info and context_info.get('format') == 'html':
            # For HTML, add as a hidden comment
            modified_text = text + f'\n<!-- {token} -->'
        elif context_info and context_info.get('format') == 'code':
            # For code, add as a comment (assuming a C-like language)
            modified_text = text + f'\n// {token}'
        else:
            # Default format: add as "invisible" text
            modified_text = text + f'\n[This prompt contains security identifier: {token}]'
        
        return modified_text, token
    
    def check_for_leaks(self, text: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check text for leaked canary tokens.
        
        Args:
            text: Text to check for leaked tokens
            
        Returns:
            Tuple of (tokens_found, leaked_tokens_list)
        """
        tokens_found = False
        leaked_tokens = []
        
        # Check all active tokens
        for token_id, token_data in self.active_tokens.items():
            if not token_data.get('is_active', True):
                continue
            
            token = token_data['token']
            
            # Check if the token appears in the text
            if token in text:
                tokens_found = True
                leak_time = datetime.now()
                
                # Record the leak
                leak_id = f"{token_id}_{int(leak_time.timestamp())}"
                leak_info = {
                    'token': token,
                    'leaked_at': leak_time.isoformat(),
                    'context': token_data['context_info'],
                    'time_to_leak': (leak_time - token_data['created_at']).total_seconds(),
                    'leak_id': leak_id
                }
                
                # Store in both the manager's leak record and return list
                self.leaked_tokens[leak_id] = leak_info
                leaked_tokens.append(leak_info)
                
                # Update metrics
                self.tokens_leaked += 1
                
                # Mark token as inactive
                token_data['is_active'] = False
                
                # Log the leak
                self.logger.warning(f"Canary token leak detected! Token: {token}, Context: {token_data['context_info']}")
        
        return tokens_found, leaked_tokens
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a canary token (mark as inactive).
        
        Args:
            token: The token to revoke
            
        Returns:
            bool: True if token was found and revoked, False otherwise
        """
        # Calculate the token ID
        token_id = hashlib.md5(token.encode()).hexdigest()
        
        if token_id in self.active_tokens:
            self.active_tokens[token_id]['is_active'] = False
            self.logger.info(f"Canary token revoked: {token}")
            return True
        
        return False
    
    def get_active_tokens(self) -> Dict[str, Dict[str, Any]]:
        """Get all active canary tokens."""
        return {k: v for k, v in self.active_tokens.items() if v['is_active']}
    
    def get_leaked_tokens(self) -> Dict[str, Dict[str, Any]]:
        """Get all leaked canary tokens."""
        return self.leaked_tokens
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the canary token manager."""
        return {
            'tokens_generated': self.tokens_generated,
            'active_tokens': len(self.get_active_tokens()),
            'tokens_leaked': self.tokens_leaked,
            'leak_ratio': self.tokens_leaked / self.tokens_generated if self.tokens_generated > 0 else 0,
            'creation_time': self.creation_time.isoformat(),
            'uptime_seconds': (datetime.now() - self.creation_time).total_seconds()
        }

class CanaryTokenDetector(DetectorBase[str, Dict[str, Any]]):
    """
    Specialized detector for finding canary tokens in text.
    Can be used to detect tokens from other systems.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the canary token detector.
        
        Args:
            config: Configuration dictionary with options:
                - additional_patterns: List of additional regex patterns to look for
        """
        # Add type annotation for default_config
        default_config: Dict[str, List[str]] = {
            'additional_patterns': []
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        self.logger = logging.getLogger(__name__)
        
        # Common canary token patterns
        self.token_patterns = [
            # Basic pattern for our tokens
            re.compile(r'CT[A-Za-z0-9]{10,}ZZ'),
            
            # UUID-based pattern
            re.compile(r'CT[a-f0-9]{8}ZZ'),
            
            # Other common patterns
            re.compile(r'canarytokens\.com/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+'),
            re.compile(r'CANARY[A-Za-z0-9\-_]+'),
            
            # Generic patterns that might catch other implementations
            re.compile(r'(?:CANARY|CT|HONEYPOT|HONEYTOKEN)[A-Za-z0-9\-_]{6,}')
        ]
        
        # Add any additional patterns from config
        if self.config.get('additional_patterns'):
            for pattern in self.config['additional_patterns']:
                if isinstance(pattern, str):
                    self.token_patterns.append(re.compile(pattern))
    
    def _validate_config(self) -> None:
        """Validate the provided configuration."""
        if 'additional_patterns' in self.config and not isinstance(self.config['additional_patterns'], list):
            raise ValueError("additional_patterns must be a list of regex patterns")
            
    def update_config(self, config: Dict[str, Any]) -> None:
        """Update the component's configuration."""
        self.config.update(config)
        self._validate_config()
        
        # Update patterns if needed
        if 'additional_patterns' in config:
            # Clear existing additional patterns
            self.token_patterns = self.token_patterns[:5]  # Keep default patterns
            
            # Add new patterns
            for pattern in self.config['additional_patterns']:
                if isinstance(pattern, str):
                    self.token_patterns.append(re.compile(pattern))
    
    def detect(self, data: str) -> Dict[str, Any]:
        """
        Detect canary tokens in the given text.
        
        Args:
            data: The text to check for canary tokens
            
        Returns:
            Dict with detection results including found tokens
        """
        detected_tokens = self.detect_tokens(data)
        
        return {
            'tokens_detected': len(detected_tokens) > 0,
            'detected_tokens': detected_tokens,
            'count': len(detected_tokens)
        }
    
    def detect_tokens(self, text: str) -> List[str]:
        """
        Detect canary tokens in the given text.
        
        Args:
            text: The text to check for canary tokens
            
        Returns:
            List of unique detected token strings
        """
        all_matches = []
        for pattern in self.token_patterns:
            matches = pattern.findall(text)
            all_matches.extend(matches)

        # Return only unique tokens found
        detected_tokens = list(set(all_matches))
        
        if detected_tokens:
            self.logger.info(f"Detected {len(detected_tokens)} unique potential canary tokens (from {len(all_matches)} total matches)")
            
        return detected_tokens 