import logging
import random
import string
import hashlib
import re
import uuid
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from datetime import datetime

class CanaryTokenManager:
    """
    Manages canary tokens for detecting data leaks in LLM prompts.
    Inserts unique tokens into prompts and checks if they appear in LLM responses.
    """
    
    def __init__(self, token_length: int = 10, use_uuid: bool = True):
        """
        Initialize the canary token manager.
        
        Args:
            token_length: Length of the canary tokens if random string is used
            use_uuid: Whether to use UUIDs instead of random strings
        """
        self.logger = logging.getLogger(__name__)
        self.token_length = token_length
        self.use_uuid = use_uuid
        
        # Track active tokens and their context
        self.active_tokens: Dict[str, Dict[str, Any]] = {}  # Dict[token_id, token_data]
        self.leaked_tokens: Dict[str, Dict[str, Any]] = {}  # Dict[token_id, leak_data]
        
        # Configure token format
        self.token_prefix = "CT"
        self.token_suffix = "ZZ"
        
        # Tracking metrics
        self.tokens_generated = 0
        self.tokens_leaked = 0
        self.creation_time = datetime.now()
    
    def _generate_random_token(self) -> str:
        """Generate a random string token."""
        characters = string.ascii_letters + string.digits
        random_part = ''.join(random.choice(characters) for _ in range(self.token_length))
        return f"{self.token_prefix}{random_part}{self.token_suffix}"
    
    def _generate_uuid_token(self) -> str:
        """Generate a UUID-based token."""
        # Use a UUID and keep only the first part to make it shorter
        uuid_str = str(uuid.uuid4()).split('-')[0]
        return f"{self.token_prefix}{uuid_str}{self.token_suffix}"
    
    def generate_token(self, context_info: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a new canary token and register it.
        
        Args:
            context_info: Optional context information about where the token is used
            
        Returns:
            The generated token string
        """
        # Generate a new token
        if self.use_uuid:
            token = self._generate_uuid_token()
        else:
            token = self._generate_random_token()
        
        # Create a unique ID for this token instance
        token_id = hashlib.md5(token.encode()).hexdigest()
        
        # Register the token with context and timestamp
        self.active_tokens[token_id] = {
            'token': token,
            'created_at': datetime.now().isoformat(),
            'context': context_info or {},
            'is_active': True
        }
        
        self.tokens_generated += 1
        return token
    
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
        Check if any active canary tokens appear in the given text.
        
        Args:
            text: The text to check for leaked tokens
            
        Returns:
            Tuple of (tokens_found, leak_details)
        """
        leaked_tokens = []
        tokens_found = False
        
        for token_id, token_data in self.active_tokens.items():
            token = token_data['token']
            
            # Check if the token appears in the text
            if token in text:
                tokens_found = True
                leak_time = datetime.now()
                
                # Record the leak
                leak_id = f"{token_id}_{int(leak_time.timestamp())}"
                leak_info = {
                    'token_id': token_id,
                    'token': token,
                    'leaked_at': leak_time.isoformat(),
                    'context': token_data['context'],
                    'time_to_leak': (leak_time - datetime.fromisoformat(token_data['created_at'])).total_seconds(),
                    'leak_id': leak_id
                }
                
                # Store the leak information
                self.leaked_tokens[leak_id] = leak_info
                leaked_tokens.append(leak_info)
                
                # Update metrics
                self.tokens_leaked += 1
                
                # Log the leak
                self.logger.warning(f"Canary token leak detected! Token: {token}, Context: {token_data['context']}")
        
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

class CanaryTokenDetector:
    """
    Specialized detector for finding canary tokens in text.
    Can be used to detect tokens from other systems.
    """
    
    def __init__(self):
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
    
    def detect_tokens(self, text: str) -> List[str]:
        """
        Detect canary tokens in the given text.
        
        Args:
            text: The text to check for canary tokens
            
        Returns:
            List of detected token strings
        """
        detected_tokens = []
        
        for pattern in self.token_patterns:
            matches = pattern.findall(text)
            detected_tokens.extend(matches)
        
        if detected_tokens:
            self.logger.info(f"Detected {len(detected_tokens)} potential canary tokens")
            
        return detected_tokens 