import logging
import numpy as np
from typing import Dict, List, Set, Optional, Tuple, Any, Union, Callable
import json
import os
from datetime import datetime

from resk_llm.heuristic_filter import HeuristicFilter
from resk_llm.vector_db import VectorDatabase
from resk_llm.canary_tokens import CanaryTokenManager, CanaryTokenDetector

class PromptSecurityManager:
    """
    A comprehensive security manager for LLM prompts that integrates:
    1. Heuristic-based filtering to detect and block malicious inputs
    2. Vector database for storing embeddings of previous attacks and detecting similar ones
    3. Canary token mechanism to detect prompt/data leaks
    """
    
    def __init__(
        self, 
        embedding_function: Optional[Callable[[str], np.ndarray]] = None,
        embedding_dim: int = 1536,
        similarity_threshold: float = 0.85,
        use_canary_tokens: bool = True,
        enable_heuristic_filter: bool = True,
        vector_db_path: Optional[str] = None
    ):
        """
        Initialize the prompt security manager.
        
        Args:
            embedding_function: Function to convert text to embeddings, required for vector db
            embedding_dim: Dimension of the embeddings
            similarity_threshold: Threshold for considering two embeddings similar
            use_canary_tokens: Whether to enable canary tokens
            enable_heuristic_filter: Whether to enable heuristic filtering
            vector_db_path: Path to load/save the vector database
        """
        self.logger = logging.getLogger(__name__)
        
        # Set up components based on configuration
        self.embedding_function = embedding_function
        self.embedding_dim = embedding_dim
        self.similarity_threshold = similarity_threshold
        self.use_canary_tokens = use_canary_tokens
        self.enable_heuristic_filter = enable_heuristic_filter
        
        # Initialize components with proper Optional types
        self.heuristic_filter: Optional[HeuristicFilter] = None
        self.vector_db: Optional[VectorDatabase] = None
        self.canary_manager: Optional[CanaryTokenManager] = None
        self.canary_detector: Optional[CanaryTokenDetector] = None
        
        # Initialize components
        if self.enable_heuristic_filter:
            self.heuristic_filter = HeuristicFilter()
            self.logger.info("Initialized heuristic filter")
            
        if self.embedding_function is not None:
            self.vector_db = VectorDatabase(
                embedding_dim=self.embedding_dim,
                similarity_threshold=self.similarity_threshold
            )
            self.logger.info(f"Initialized vector database with embedding dimension {self.embedding_dim}")
            
            # Load existing vector database if path provided
            if vector_db_path and os.path.exists(vector_db_path):
                success = self.vector_db.load_from_disk(vector_db_path)
                if success:
                    self.logger.info(f"Loaded vector database from {vector_db_path}")
                else:
                    self.logger.warning(f"Failed to load vector database from {vector_db_path}")
        else:
            self.logger.warning("No embedding function provided, vector database features disabled")
            
        if self.use_canary_tokens:
            self.canary_manager = CanaryTokenManager()
            self.canary_detector = CanaryTokenDetector()
            self.logger.info("Initialized canary token manager")
        
        # Statistics tracking
        self.requests_processed = 0
        self.requests_blocked = 0
        self.requests_flagged = 0
        self.creation_time = datetime.now()
        
    def secure_prompt(
        self, 
        prompt: str, 
        context_info: Optional[Dict[str, Any]] = None,
        check_only: bool = False
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply security measures to a prompt.
        
        Args:
            prompt: The prompt to secure
            context_info: Additional context about the prompt
            check_only: If True, only check the prompt without modifying it
            
        Returns:
            Tuple of (secured_prompt, security_info)
        """
        self.requests_processed += 1
        
        # Initialize result container with explicit typing for lists
        security_info: Dict[str, Any] = {
            'original_length': len(prompt),
            'is_blocked': False,
            'is_suspicious': False,
            'risk_score': 0.0,
            'actions_taken': [],  # This is a list
            'canary_token': None,
            'similar_attacks': []  # This is a list
        }
        
        # Explicitly ensure actions_taken is a list for type checker
        actions_taken: List[str] = security_info['actions_taken']
        similar_attacks: List[Dict[str, Any]] = security_info['similar_attacks']
        
        modified_prompt = prompt
        
        # Step 1: Apply heuristic filtering first (fast rejection)
        if self.enable_heuristic_filter and self.heuristic_filter:
            passed_filter, reason, _ = self.heuristic_filter.filter_input(prompt)
            
            if not passed_filter:
                security_info['is_blocked'] = True
                security_info['block_reason'] = reason
                security_info['risk_score'] = 1.0
                actions_taken.append('blocked_by_heuristic')
                
                self.requests_blocked += 1
                self.logger.warning(f"Prompt blocked by heuristic filter: {reason}")
                
                # If check_only is False, we return immediately for blocked prompts
                if not check_only:
                    return "[BLOCKED] This prompt has been blocked due to security concerns.", security_info
        
        # Step 2: Check for similarity to known attacks (if embedding function available)
        if self.vector_db and self.embedding_function:
            try:
                # Generate embedding for the prompt
                prompt_embedding = self.embedding_function(prompt)
                
                # Check for similarity to known attacks
                is_similar, match_info = self.vector_db.is_similar_to_known_attack(prompt_embedding)
                
                if is_similar and match_info:
                    security_info['is_suspicious'] = True
                    similar_attacks.append(match_info)
                    # Safely access similarity with a default value if it doesn't exist
                    similarity = match_info.get('similarity', 0.0)
                    security_info['risk_score'] = max(security_info['risk_score'], similarity)
                    actions_taken.append('similar_to_known_attack')
                    
                    self.requests_flagged += 1
                    self.logger.warning(f"Prompt similar to known attack: {similarity:.2f} similarity")
                    
                    # Optionally block if above threshold
                    if similarity > 0.95:  # Very high similarity
                        security_info['is_blocked'] = True
                        security_info['block_reason'] = f"Very similar to known attack ({similarity:.2f} similarity)"
                        self.requests_blocked += 1
                        
                        if not check_only:
                            return "[BLOCKED] This prompt has been blocked due to similarity to known attacks.", security_info
                
                # Store the embedding for future reference if not in check_only mode
                if not check_only:
                    # Add context information
                    metadata = {
                        'timestamp': datetime.now().isoformat(),
                        'is_blocked': security_info['is_blocked'],
                        'is_suspicious': security_info['is_suspicious'],
                        'risk_score': security_info['risk_score'],
                        'prompt_preview': prompt[:100] + ('...' if len(prompt) > 100 else '')
                    }
                    if context_info:
                        metadata.update({f"context_{k}": v for k, v in context_info.items()})
                        
                    self.vector_db.add_embedding(prompt_embedding, metadata)
                
            except Exception as e:
                self.logger.error(f"Error during vector database check: {str(e)}")
                actions_taken.append('vector_db_error')
        
        # Step 3: Insert canary token if enabled and not in check_only mode
        if self.use_canary_tokens and self.canary_manager and not check_only and not security_info['is_blocked']:
            try:
                # Add canary token based on content type
                token_context = {'timestamp': datetime.now().isoformat()}
                if context_info:
                    token_context.update(context_info)
                
                modified_prompt, token = self.canary_manager.insert_canary_token(modified_prompt, token_context)
                security_info['canary_token'] = token
                actions_taken.append('canary_token_added')
                
                self.logger.info(f"Added canary token to prompt: {token}")
                
            except Exception as e:
                self.logger.error(f"Error inserting canary token: {str(e)}")
                actions_taken.append('canary_token_error')
        
        # Finalize security information
        security_info['final_length'] = len(modified_prompt)
        security_info['processing_time'] = datetime.now().isoformat()
        
        if not check_only and security_info['is_blocked']:
            return "[BLOCKED] This prompt has been blocked due to security concerns.", security_info
        
        return modified_prompt, security_info
    
    def check_response(self, response: str, associated_tokens: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Check a response from an LLM for security issues, including token leaks.
        
        Args:
            response: The response text to check
            associated_tokens: Optional list of canary tokens expected to be associated with this response
            
        Returns:
            Dict with security information
        """
        result: Dict[str, Any] = {
            'has_leaked_tokens': False,
            'leaked_tokens': [],
            'detected_canary_tokens': [],
            'other_issues': []
        }
        
        # Extract lists with proper typing for type checker
        leaked_tokens: List[Dict[str, Any]] = result['leaked_tokens']
        detected_canary_tokens: List[str] = result['detected_canary_tokens']
        other_issues: List[str] = result['other_issues']
        
        # Check for canary token leaks if enabled
        if self.use_canary_tokens and self.canary_manager:
            try:
                # Check if any active tokens appear in the response
                tokens_found, leak_details = self.canary_manager.check_for_leaks(response)
                
                if tokens_found:
                    result['has_leaked_tokens'] = True
                    # Extend the list instead of assigning to avoid type issues
                    leaked_tokens.extend(leak_details)
                    
                    self.logger.warning(f"Response contains leaked canary tokens: {len(leak_details)}")
                
                # If specific tokens were provided, check specifically for those
                if associated_tokens:
                    for token in associated_tokens:
                        if token in response:
                            self.logger.critical(f"Response leaked associated canary token: {token}")
                            # Make sure this leak is recorded (might be redundant, but ensures it's captured)
                            if not result['has_leaked_tokens']:
                                result['has_leaked_tokens'] = True
                                # We don't have the metadata here, so just record the token
                                leaked_tokens.append({'token': token, 'context': {'associated': True}})
            
            except Exception as e:
                self.logger.error(f"Error checking for canary token leaks: {str(e)}")
                other_issues.append(f"Error checking for token leaks: {str(e)}")
        
        # Use the generic detector to find any canary tokens, even from other systems
        if self.canary_detector:
            try:
                detector_tokens = self.canary_detector.detect_tokens(response)
                if detector_tokens:
                    detected_canary_tokens.extend(detector_tokens)
                    self.logger.warning(f"Response contains potential canary tokens: {detector_tokens}")
            except Exception as e:
                self.logger.error(f"Error detecting canary tokens: {str(e)}")
                other_issues.append(f"Error detecting canary tokens: {str(e)}")
        
        return result
    
    def add_attack_pattern(self, pattern_text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Add a known attack pattern to the vector database
        
        Args:
            pattern_text: The prompt injection text pattern to add
            metadata: Optional metadata to store with the pattern
            
        Returns:
            Dict with status information
        """
        result: Dict[str, Any] = {
            'success': False,
            'errors': [],
            'embedding_generated': False,
            'added_to_db': False
        }
        
        # Extract list with proper typing for type checker
        errors: List[str] = result['errors']
        
        # We need both the vector database and embedding function to be available
        if not self.vector_db:
            errors.append("Vector database not initialized")
            return result
            
        if not self.embedding_function:
            errors.append("Embedding function not initialized")
            return result
            
        try:
            # Clean and normalize the pattern
            pattern = self._normalize_text(pattern_text)
            
            # Generate an embedding for the pattern
            embedding = self.embedding_function(pattern)
            if embedding is None:
                errors.append("Failed to generate embedding - returned None")
                return result
                
            result['embedding_generated'] = True
            
            # Create metadata if not provided
            if metadata is None:
                metadata = {}
                
            # Add some standard metadata fields
            metadata.update({
                'source': 'manual_addition',
                'added_at': datetime.now().isoformat(),
                'type': 'attack_pattern'
            })
            
            # Add to the vector database
            if self.vector_db:  # Extra check to satisfy type checker
                self.vector_db.add_embedding(embedding, metadata)
                result['added_to_db'] = True
                result['success'] = True
                self.logger.info(f"Added attack pattern to vector database: '{pattern[:30]}...'")
            
        except Exception as e:
            self.logger.error(f"Error adding attack pattern: {str(e)}")
            errors.append(f"Exception: {str(e)}")
            
        return result
    
    def _normalize_text(self, text: str) -> str:
        """
        Clean and normalize text for consistent processing.
        
        Args:
            text: The text to normalize
            
        Returns:
            Normalized text
        """
        if not text:
            return ""
            
        # Basic normalization steps
        normalized = text.strip()
        
        # Remove excessive whitespace
        import re
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Convert to lowercase for case-insensitive matching
        normalized = normalized.lower()
        
        return normalized
    
    def save_state(self, base_path: str) -> Dict[str, bool]:
        """
        Save the state of all components to disk.
        
        Args:
            base_path: Base directory to save files
            
        Returns:
            Dict with success status for each component
        """
        os.makedirs(base_path, exist_ok=True)
        results = {}
        
        # Save vector database if available
        if self.vector_db:
            vector_db_path = os.path.join(base_path, 'vector_db.json')
            results['vector_db'] = self.vector_db.save_to_disk(vector_db_path)
        
        # No specific state saving needed for heuristic filter or canary detector
        
        self.logger.info(f"Saved security manager state to {base_path}")
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the security manager and its components."""
        stats = {
            'requests_processed': self.requests_processed,
            'requests_blocked': self.requests_blocked,
            'requests_flagged': self.requests_flagged,
            'block_rate': self.requests_blocked / self.requests_processed if self.requests_processed > 0 else 0,
            'creation_time': self.creation_time.isoformat(),
            'uptime_seconds': (datetime.now() - self.creation_time).total_seconds(),
            'components': {
                'heuristic_filter': self.enable_heuristic_filter,
                'vector_db': self.vector_db is not None,
                'canary_tokens': self.use_canary_tokens
            }
        }
        
        # Add component-specific statistics
        if self.vector_db:
            stats['vector_db'] = self.vector_db.get_statistics()
            
        if self.use_canary_tokens and self.canary_manager:
            stats['canary_tokens'] = self.canary_manager.get_statistics()
            
        return stats 