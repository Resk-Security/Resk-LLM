import logging
import numpy as np
from typing import Dict, List, Set, Optional, Tuple, Any, Union, Callable, cast
import json
import os
from datetime import datetime

from resk_llm.heuristic_filter import HeuristicFilter
from resk_llm.vector_db import VectorDatabase
from resk_llm.core.canary_tokens import CanaryTokenManager, CanaryTokenDetector
from resk_llm.core.abc import SecurityManagerBase, FilterBase, DetectorBase

# Type definition for the security manager configuration
SecurityManagerConfig = Dict[str, Any]

# Rename class to match expected name
class PromptSecurityManager(SecurityManagerBase[str, str, SecurityManagerConfig]):
    """
    A comprehensive security manager for LLM interactions that integrates various
    security components like filters and detectors.

    It can coordinate components such as:
    1. Heuristic-based filtering to detect and block malicious inputs.
    2. Vector database for storing embeddings of previous attacks and detecting similar ones (if configured).
    3. Canary token mechanism to detect prompt/data leaks (if configured).
    4. Other custom filters and detectors added via `add_component`.
    """
    
    def __init__(
        self, 
        embedding_function: Optional[Callable[[str], np.ndarray]] = None,
        embedding_dim: int = 1536,
        similarity_threshold: float = 0.85,
        use_canary_tokens: bool = True,
        enable_heuristic_filter: bool = True,
        vector_db_path: Optional[str] = None,
        config: Optional[SecurityManagerConfig] = None
    ):
        """
        Initialize the RESK security manager.
        
        Args:
            embedding_function: Function to convert text to embeddings, required for vector db.
            embedding_dim: Dimension of the embeddings.
            similarity_threshold: Threshold for considering two embeddings similar.
            use_canary_tokens: Whether to enable canary tokens.
            enable_heuristic_filter: Whether to enable the default heuristic filter.
            vector_db_path: Path to load/save the vector database.
            config: Additional configuration parameters for the manager and its components.
        """
        # Initialize configuration
        merged_config: SecurityManagerConfig = config or {}
        # Store explicit parameters in config if not already present
        if 'embedding_dim' not in merged_config:
            merged_config['embedding_dim'] = embedding_dim
        if 'similarity_threshold' not in merged_config:
            merged_config['similarity_threshold'] = similarity_threshold
        if 'use_canary_tokens' not in merged_config:
            merged_config['use_canary_tokens'] = use_canary_tokens
        if 'enable_heuristic_filter' not in merged_config:
            merged_config['enable_heuristic_filter'] = enable_heuristic_filter
        if 'vector_db_path' not in merged_config:
            merged_config['vector_db_path'] = vector_db_path

        # Initialize the base class
        super().__init__(merged_config)

        self.logger = logging.getLogger(__name__)
        
        # Set up components based on configuration
        self.embedding_function = embedding_function
        self.embedding_dim = self.config['embedding_dim']
        self.similarity_threshold = self.config['similarity_threshold']
        self.use_canary_tokens = self.config['use_canary_tokens']
        self.enable_heuristic_filter = self.config['enable_heuristic_filter']
        
        # Initialize components with proper Optional types
        self.heuristic_filter: Optional[HeuristicFilter] = None
        self.vector_db: Optional[VectorDatabase] = None
        self.canary_manager: Optional[CanaryTokenManager] = None
        self.canary_detector: Optional[CanaryTokenDetector] = None
        
        # Initialize components and add them to the appropriate collections
        if self.enable_heuristic_filter:
            # Pass relevant part of config if available
            heuristic_config = self.config.get('heuristic_filter_config', {})
            self.heuristic_filter = HeuristicFilter(config=heuristic_config)
            self.add_component(self.heuristic_filter)
            self.logger.info("Initialized heuristic filter")
            
        if self.embedding_function is not None:
            # Pass relevant part of config if available
            vector_db_config = self.config.get('vector_db_config', {})
            self.vector_db = VectorDatabase(
                embedding_dim=self.embedding_dim,
                similarity_threshold=self.similarity_threshold,
                config=vector_db_config
            )
            # Add vector_db to the detectors list
            self.add_component(self.vector_db)
            self.logger.info(f"Initialized vector database with embedding dimension {self.embedding_dim}")
            
            # Load existing vector database if path provided
            db_path = self.config.get('vector_db_path')
            if db_path and os.path.exists(db_path):
                success = self.vector_db.load_from_disk(db_path)
                if success:
                    self.logger.info(f"Loaded vector database from {db_path}")
                else:
                    self.logger.warning(f"Failed to load vector database from {db_path}")
        else:
            self.logger.warning("No embedding function provided, vector database features disabled")
            
        if self.use_canary_tokens:
            canary_manager_config = self.config.get('canary_manager_config', {})
            canary_detector_config = self.config.get('canary_detector_config', {})
            self.canary_manager = CanaryTokenManager(config=canary_manager_config)
            self.canary_detector = CanaryTokenDetector(config=canary_detector_config)
            # CanaryTokenDetector inherits from DetectorBase
            # self.add_component(self.canary_detector) # REMOVED: Don't run detector on input automatically
            # CanaryTokenManager does not inherit from Filter/Detector currently
            self.logger.info("Initialized canary token manager and detector")
        
        # Statistics tracking
        self.requests_processed = 0
        self.requests_blocked = 0
        self.requests_flagged = 0
        self.creation_time = datetime.now()
    
    def _validate_config(self) -> None:
        """Validate the provided configuration."""
        # Basic validation from config dictionary
        if 'embedding_dim' in self.config and not isinstance(self.config['embedding_dim'], int):
            raise ValueError("embedding_dim must be an integer")

        if 'similarity_threshold' in self.config and not isinstance(self.config['similarity_threshold'], float):
            raise ValueError("similarity_threshold must be a float")

        if 'use_canary_tokens' in self.config and not isinstance(self.config['use_canary_tokens'], bool):
            raise ValueError("use_canary_tokens must be a boolean")

        if 'enable_heuristic_filter' in self.config and not isinstance(self.config['enable_heuristic_filter'], bool):
            raise ValueError("enable_heuristic_filter must be a boolean")

    def update_config(self, config: SecurityManagerConfig) -> None:
        """Update the component's configuration and propagate to children."""
        self.config.update(config)
        self._validate_config() # Re-validate after update

        # Update core attributes derived from config
        self.embedding_dim = self.config.get('embedding_dim', self.embedding_dim)
        self.similarity_threshold = self.config.get('similarity_threshold', self.similarity_threshold)
        self.use_canary_tokens = self.config.get('use_canary_tokens', self.use_canary_tokens)
        self.enable_heuristic_filter = self.config.get('enable_heuristic_filter', self.enable_heuristic_filter)
        # Note: Re-initialization of components based on enable flags might be needed here,
        # or handle dynamically in processing methods. Current implementation updates existing components.

        # Update individual component configurations if they exist
        if self.heuristic_filter and 'heuristic_filter_config' in config:
            self.heuristic_filter.update_config(config['heuristic_filter_config'])

        if self.canary_detector and 'canary_detector_config' in config:
            self.canary_detector.update_config(config['canary_detector_config'])

        if self.canary_manager and 'canary_manager_config' in config:
            self.canary_manager.update_config(config['canary_manager_config'])

        # Update Vector DB parameters if it exists
        if self.vector_db:
            # Assuming VectorDatabase might get an update_config method later
            if 'vector_db_config' in config:
                # self.vector_db.update_config(config['vector_db_config'])
                pass # Placeholder until VectorDatabase is refactored
            if 'embedding_dim' in config:
                self.vector_db.embedding_dim = config['embedding_dim']
            if 'similarity_threshold' in config:
                self.vector_db.similarity_threshold = config['similarity_threshold']

    def add_component(self, component: Union[FilterBase, DetectorBase, Any]) -> None:
        """
        Add a security component (filter or detector) to the manager.

        Args:
            component: The security component instance to add.
        """
        if isinstance(component, FilterBase):
            if component not in self.filters:
                self.filters.append(component)
                self.logger.info(f"Added filter component: {type(component).__name__}")
            else:
                self.logger.warning(f"Filter component {type(component).__name__} already added.")
        elif isinstance(component, DetectorBase):
             if component not in self.detectors:
                self.detectors.append(component)
                self.logger.info(f"Added detector component: {type(component).__name__}")
             else:
                 self.logger.warning(f"Detector component {type(component).__name__} already added.")
        else:
            # Handle other types if necessary, e.g., specific managers like CanaryTokenManager
            # For now, just log a warning for unknown types.
            self.logger.warning(f"Attempted to add component of unmanaged type: {type(component).__name__}")

    def process_input(self, data: str) -> str:
        """
        Process input data through configured filters.
        Primarily intended for simple pre-processing or blocking based on filters.
        For more detailed analysis and actions, use `secure_prompt`.

        Args:
            data: The input string to process.

        Returns:
            The potentially modified input string. Returns a blocked message if a filter blocks it.
        """
        modified_data = data
        for filter_component in self.filters:
            filter_result = filter_component.filter(modified_data)
            # Assuming filters return (passed: bool, reason: Optional[str], processed_data: OutputType)
            if isinstance(filter_result, tuple) and len(filter_result) >= 1:
                passed = filter_result[0]
                if not passed:
                    reason = filter_result[1] if len(filter_result) > 1 else "Filter blocked input"
                    self.logger.warning(f"Input blocked by {type(filter_component).__name__}: {reason}")
                    return "[BLOCKED] Input did not pass security filters." # Or raise an exception
            else:
                 self.logger.error(f"Filter {type(filter_component).__name__} returned unexpected result: {filter_result}")
            # Filters might modify data even if passed, update for next filter
            if isinstance(filter_result, tuple) and len(filter_result) >= 3 and isinstance(filter_result[2], str):
                 modified_data = filter_result[2]


        # Note: This basic process_input doesn't run detectors or vector DB checks.
        # Use secure_prompt for the full suite.
        return modified_data

    def process_output(self, data: str) -> str:
        """
        Process output data through configured security components (mainly detectors for now).
        Primarily intended for simple post-processing or checks like canary token leaks.
        For more detailed analysis, use `check_response`.

        Args:
            data: The output string to process.

        Returns:
            The processed output string (currently returns original).
        """
        processed_data = data
        # Run through detectors (e.g., CanaryTokenDetector)
        for detector in self.detectors:
            try:
                # Detectors return bool, float, or dict. We need to interpret this.
                detection_result = detector.detect(processed_data)
                if isinstance(detector, CanaryTokenDetector):
                    if isinstance(detection_result, dict) and detection_result.get('canary_tokens_found'):
                        self.logger.warning(f"Canary tokens detected in output by {type(detector).__name__}: {detection_result.get('details')}")
                        # Decide action: redact, block, log only? For now, just log.
                        # processed_data = "[REDACTED] Output contained sensitive tokens."
                # Add logic for other detector types if needed
                elif detection_result is True or (isinstance(detection_result, (float, int)) and detection_result > 0.5): # Example threshold
                     self.logger.warning(f"Potential issue detected in output by {type(detector).__name__}. Result: {detection_result}")

            except Exception as e:
                self.logger.error(f"Error during output detection with {type(detector).__name__}: {e}")


        # Run through filters if output filtering is desired (e.g., PII redaction)
        # for filter_component in self.filters:
        #     filter_result = filter_component.filter(processed_data)
        #     # Handle result... update processed_data if modified

        return processed_data

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a report summarizing the security checks performed and statistics.

        Returns:
            Dictionary with report data including operational statistics.
        """
        # Combine stats with potential summaries from components if they offer report methods
        report = self.get_statistics()
        # Example: Add component-specific info if available
        # if self.heuristic_filter:
        #     report['heuristic_filter_stats'] = self.heuristic_filter.get_stats() # If method exists
        return report
        
    def secure_prompt(
        self, 
        prompt: str, 
        context_info: Optional[Dict[str, Any]] = None,
        check_only: bool = False # Kept for compatibility, but logic might change
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply a comprehensive suite of security measures to a prompt, including
        filters, detectors, and optional vector database checks.
        
        Args:
            prompt: The prompt string to secure.
            context_info: Additional context about the prompt (optional).
            check_only: If True, perform checks but do not modify the prompt or block. (Currently logs actions).
            
        Returns:
            Tuple of (processed_prompt, security_info_dict).
            The processed_prompt might be the original, modified, or a blocked message.
            The security_info_dict contains details about the checks performed.
        """
        self.requests_processed += 1
        start_time = datetime.now()
        
        security_info: Dict[str, Any] = {
            'request_id': f"req_{self.requests_processed}", # Simple request ID
            'timestamp': start_time.isoformat(),
            'original_length': len(prompt),
            'is_blocked': False,
            'block_reason': None,
            'is_suspicious': False,
            'suspicion_reasons': [], # List[str]
            'risk_score': 0.0, # Aggregate risk score
            'actions_taken': [], # List[str] detailing modifications or findings
            'canary_token': None, # Token added, if any
            'similar_attacks': [], # List[Dict] from vector DB
            'component_results': {} # Dict[str, Any] storing results from each component
        }
        # Ensure list types are correctly inferred or explicitly typed if needed elsewhere
        suspicion_reasons: List[str] = security_info['suspicion_reasons']
        actions_taken: List[str] = security_info['actions_taken']
        similar_attacks: List[Dict[str, Any]] = security_info['similar_attacks']
        component_results: Dict[str, Any] = security_info['component_results']
        
        modified_prompt = prompt
        risk_contributors = []

        # 1. Insert Canary Token (if enabled and manager exists)
        if self.use_canary_tokens and self.canary_manager and not check_only:
            try:
                modified_prompt, token = self.canary_manager.insert_canary_token(modified_prompt)
                if token:
                    security_info['canary_token'] = token
                    actions_taken.append(f"Inserted canary token: {token}")
                    self.logger.debug(f"Inserted canary token {token}")
            except Exception as e:
                 self.logger.error(f"Error inserting canary token: {e}")


        # 2. Apply Filters
        for filter_component in self.filters:
            comp_name = type(filter_component).__name__
            try:
                filter_result = filter_component.filter(modified_prompt)
                component_results[comp_name] = filter_result # Store raw result

                # Standardize handling based on expected (passed, reason, processed_data) tuple
                if isinstance(filter_result, tuple) and len(filter_result) >= 1:
                    passed = filter_result[0]
                    reason = filter_result[1] if len(filter_result) > 1 else "Filter check failed"
                    processed_data = filter_result[2] if len(filter_result) > 2 and isinstance(filter_result[2], str) else modified_prompt

                    if not passed:
                        security_info['is_blocked'] = True
                        security_info['block_reason'] = f"{comp_name}: {reason}"
                        actions_taken.append(f"Blocked by {comp_name}: {reason}")
                        risk_contributors.append(1.0) # Max risk contribution for block
                        self.requests_blocked += 1
                        self.logger.warning(f"Prompt blocked by {comp_name}. Reason: {reason}")
                        # Return immediately if blocked
                        if not check_only:
                             security_info['processing_time_ms'] = (datetime.now() - start_time).total_seconds() * 1000
                             return "[BLOCKED] Input did not pass security filters.", security_info
                        else:
                             # If check_only, log but continue analysis
                             self.logger.info(f"[Check Only] Prompt would be blocked by {comp_name}. Reason: {reason}")


                    # Update prompt for next component if modified
                    modified_prompt = processed_data
                else:
                     self.logger.error(f"Filter {comp_name} returned unexpected result format: {filter_result}")

            except Exception as e:
                self.logger.error(f"Error during filtering with {comp_name}: {e}")
                component_results[comp_name] = {"error": str(e)}


        # 3. Run Detectors
        for detector in self.detectors:
            comp_name = type(detector).__name__
            try:
                detect_result: Union[bool, float, Dict[str, Any], Any] = detector.detect(modified_prompt)
                
                # Store result consistently as a dictionary
                result_to_store: Dict[str, Any] = {} # Initialize here
                if isinstance(detect_result, dict):
                    result_to_store = detect_result
                elif isinstance(detect_result, bool):
                    result_to_store = {"detected": detect_result}
                elif isinstance(detect_result, (float, int)):
                    result_to_store = {"score": float(detect_result)} # Store score as float
                else:
                    result_to_store = {"raw_result": str(detect_result)} # Convert any unexpected type to string
                    
                component_results[f"{comp_name}_output"] = result_to_store
                
                # Interpret result and log/flag if needed
                detected = False
                # Rename variable to avoid conflict with outer scope
                detector_details: Optional[str] = None
                score_contribution = 0.0

                if isinstance(detect_result, bool) and detect_result:
                    detected = True
                    detector_details = "Detection positive"
                    score_contribution = 0.7 # Assign arbitrary score contribution
                elif isinstance(detect_result, (float, int)):
                    # Assuming score indicates likelihood/severity (0-1)
                    if detect_result > 0.5: # Example threshold
                        detected = True
                        detector_details = f"Score: {detect_result:.2f}"
                        score_contribution = float(detect_result)
                elif isinstance(detect_result, dict):
                     # Check common patterns for detection flags/scores in dicts
                     dict_details = detect_result.get('reason') or detect_result.get('details')
                     if detect_result.get('detected') or detect_result.get('is_detected'):
                         detected = True
                         detector_details = str(dict_details) if dict_details is not None else "Details in dict"
                     elif any(v for k, v in detect_result.items() if isinstance(v, bool) and v): # Check if any boolean flag is True
                        detected = True
                        detector_details = f"Flags: {[k for k, v in detect_result.items() if isinstance(v, bool) and v]}"
                        score_contribution = 0.6 # Assign score if flags are set

                if detected:
                    security_info['is_suspicious'] = True
                    reason = f"{comp_name}: {detector_details}"
                    suspicion_reasons.append(reason)
                    actions_taken.append(f"Flagged by {comp_name}: {detector_details}")
                    risk_contributors.append(score_contribution)
                    self.requests_flagged += 1 # Count flagged requests
                    self.logger.info(f"Prompt flagged by {comp_name}. Details: {detector_details}")
                
            except Exception as e:
                self.logger.error(f"Error during detection with {comp_name}: {e}")
                component_results[f"{comp_name}_output"] = {"error": str(e)}

        # 4. Vector Database Check (if enabled and embedding function available)
        if self.vector_db and self.embedding_function:
            comp_name = "VectorDatabaseCheck"
            try:
                # Embed the *original* prompt to avoid interference from inserted tokens
                text_to_embed = self._normalize_text(prompt) # Use original prompt here
                embedding = self.embedding_function(text_to_embed)

                # Use detect() instead of directly calling search_similar
                detect_result = self.vector_db.detect(embedding)
                component_results[comp_name] = detect_result

                if detect_result['detected']:
                    security_info['is_suspicious'] = True
                    similar_entries = detect_result['similar_entries']
                    max_similarity = detect_result['max_similarity']
                    reason = f"VectorDB: Similarity to known patterns ({max_similarity:.2f})"
                    suspicion_reasons.append(reason)
                    actions_taken.append(f"Flagged by {comp_name}: Similarity above threshold ({max_similarity:.2f})")
                    # Add similarity score to risk
                    risk_contributors.append(max_similarity * 0.8) # Weight similarity score contribution
                    # Store details of similar attacks
                    security_info['similar_attacks'] = similar_entries
                    self.requests_flagged += 1
                    self.logger.info(f"Prompt flagged by Vector DB check. Max similarity: {max_similarity:.2f}")
                
            except Exception as e:
                self.logger.error(f"Error during vector database check: {e}")
                component_results[comp_name] = {"error": str(e)}


        # Calculate final risk score (simple average for now, could be more complex)
        if risk_contributors:
             security_info['risk_score'] = np.mean(risk_contributors)
        else:
             security_info['risk_score'] = 0.0


        # Final decision based on check_only flag
        final_prompt = modified_prompt
        if security_info['is_blocked'] and not check_only:
            final_prompt = "[BLOCKED] Input did not pass security filters."

        # Log final outcome
        if security_info['is_blocked']:
             log_level = logging.WARNING if not check_only else logging.INFO
             self.logger.log(log_level, f"Request {security_info['request_id']} outcome: BLOCKED. Reason: {security_info['block_reason']}")
        elif security_info['is_suspicious']:
             self.logger.info(f"Request {security_info['request_id']} outcome: FLAGGED. Reasons: {'; '.join(suspicion_reasons)}")
        else:
             self.logger.info(f"Request {security_info['request_id']} outcome: PASSED.")

        security_info['processing_time_ms'] = (datetime.now() - start_time).total_seconds() * 1000
        return final_prompt, security_info
    
    def check_response(self, response: str, associated_tokens: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Check the LLM's response for potential issues like leaked canary tokens.
        Uses configured detectors, especially CanaryTokenDetector.

        Args:
            response: The response string from the LLM.
            associated_tokens: Optional list of canary tokens specifically associated
                               with the input prompt that generated this response.
                               Used for more targeted leak detection.

        Returns:
            A dictionary containing the results of the checks.
            {
                'passed': bool, # Overall assessment (True if no critical issues)
                'issues_found': List[str], # Descriptions of detected issues
                'canary_tokens_leaked': List[str], # List of detected canary tokens
                'component_results': Dict[str, Any] # Raw results from each detector run
            }
        """
        self.logger.debug("Checking response...")
        issues_found: List[str] = []
        canary_leaks: List[str] = []
        component_results: Dict[str, Any] = {} # Added type hint

        # 1. Check for canary tokens leakage
        canary_detector_found = False
        for detector in self.detectors:
             if isinstance(detector, CanaryTokenDetector):
                 comp_name = type(detector).__name__
                 canary_detector_found = True
                 try:
                     detect_result = detector.detect(response)
                     component_results[comp_name] = detect_result
                     if isinstance(detect_result, dict) and detect_result.get('tokens_detected'): 
                         leaked = detect_result.get('detected_tokens', [])
                         if leaked:
                              issue = f"CanaryTokenDetector: Found leaked tokens: {leaked}"
                              issues_found.append(issue)
                              canary_leaks.extend(leaked)
                              self.logger.warning(issue)
                              # Optionally, check against associated_tokens if provided
                              if associated_tokens:
                                   matched_leaks = [t for t in leaked if t in associated_tokens]
                                   if matched_leaks:
                                        self.logger.critical(f"CRITICAL: Confirmed leak of associated canary tokens: {matched_leaks}")


                 except Exception as e:
                      self.logger.error(f"Error during canary token detection in response: {e}")
                      component_results[comp_name] = {"error": str(e)}
                 break # Assume only one CanaryTokenDetector

        # Fallback or primary check using CanaryTokenManager if detector not used/found
        if not canary_detector_found and self.use_canary_tokens and self.canary_manager:
             comp_name = "CanaryTokenManagerCheck"
             try:
                  tokens_found, details = self.canary_manager.check_for_leaks(response)
                  component_results[comp_name] = {"tokens_found": tokens_found, "details": details}
                  if tokens_found:
                      issue = f"CanaryTokenManager: Found leaked tokens: {details}"
                      issues_found.append(issue)
                      # Extract token strings from details (list of dicts)
                      leaked_tokens = [d.get('token', '') for d in details if isinstance(d, dict)]
                      canary_leaks.extend([t for t in leaked_tokens if t]) # Extend with non-empty tokens
                      self.logger.warning(issue)
                      if associated_tokens:
                           # Check against the extracted tokens
                           matched_leaks = [t for t in leaked_tokens if t and t in associated_tokens]
                           if matched_leaks:
                                self.logger.critical(f"CRITICAL: Confirmed leak of associated canary tokens: {matched_leaks}")
            
             except Exception as e:
                  self.logger.error(f"Error during canary token manager leak check in response: {e}")
                  component_results[comp_name] = {"error": str(e)}

        # 2. Optionally run other detectors or filters on the response
        # Example: Run all detectors (excluding CanaryTokenDetector again)
        for detector in self.detectors:
             if not isinstance(detector, CanaryTokenDetector): # Avoid re-running
                comp_name = type(detector).__name__
                try:
                    # Utiliser une variable différente pour éviter la redéfinition
                    detector_result: Union[bool, float, Dict[str, Any], Any] = detector.detect(response)
                    
                    # Store result consistently as a dictionary
                    result_to_store: Dict[str, Any] = {} # Initialize here
                    if isinstance(detector_result, dict):
                        result_to_store = detector_result
                    elif isinstance(detector_result, bool):
                        result_to_store = {"detected": detector_result}
                    elif isinstance(detector_result, (float, int)):
                        result_to_store = {"score": float(detector_result)} # Store score as float
                    else:
                        result_to_store = {"raw_result": str(detector_result)} # Convert any unexpected type to string
                        
                    component_results[f"{comp_name}_output"] = result_to_store
                    
                    # Interpret result and log/flag if needed
                    detected = False
                    # Rename variable to avoid conflict with outer scope
                    detector_details: Optional[str] = None 
                    
                    if isinstance(detector_result, bool) and detector_result:
                        detected = True; detector_details = "Detection positive"
                    elif isinstance(detector_result, (float, int)) and detector_result > 0.5: # Example threshold
                        detected = True; detector_details = f"Score: {detector_result:.2f}"
                    elif isinstance(detector_result, dict):
                         # Ensure we get a string or None for details
                         dict_details_val = detector_result.get('reason') or detector_result.get('details')
                         if detector_result.get('detected') or detector_result.get('is_detected'):
                              detected = True
                              detector_details = str(dict_details_val) if dict_details_val is not None else "Details in dict"

                    if detected:
                         issue = f"{comp_name} (Output Check): Detected potential issue. Details: {detector_details}"
                         issues_found.append(issue)
                         self.logger.info(f"Issue detected in response by {comp_name}. Details: {detector_details}")

                except Exception as e:
                        self.logger.error(f"Error during output detection with {comp_name}: {e}")
                        component_results[f"{comp_name}_output"] = {"error": str(e)}


        # Example: Run filters on output (e.g., for PII redaction)
        # modified_response = response
        # for filter_component in self.filters:
        #     comp_name = type(filter_component).__name__
        #     try:
        #         filter_result = filter_component.filter(modified_response)
        #         component_results[f"{comp_name}_output"] = filter_result
        #         # Handle result, potentially update modified_response, log actions
        #         passed, reason, processed_data = filter_result # Assuming tuple format
        #         if isinstance(processed_data, str) and processed_data != modified_response:
        #              issues_found.append(f"{comp_name} (Output Filter): Modified response. Reason: {reason}")
        #              modified_response = processed_data
        #     except Exception as e:
        #         self.logger.error(f"Error during output filtering with {comp_name}: {e}")
        #         component_results[f"{comp_name}_output"] = {"error": str(e)}
        # response_info['processed_response'] = modified_response # If modification occurs

        response_info: Dict[str, Any] = {}
        response_info['component_results'] = component_results
        response_info['issues_found'] = issues_found
        response_info['canary_tokens_leaked'] = canary_leaks # Add the list of leaked tokens
        
        # Additional processing or actions based on results
        if issues_found:
            self.logger.warning(f"Issues detected during response check: {issues_found}")
            # Example: Raise an exception, modify response, etc.
            # if config.get('block_on_response_issue'):
            #     raise SecurityException("Response blocked due to detected issues.")
            
        return response_info
    
    def add_attack_pattern(self, pattern_text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Add a new attack pattern to the vector database for future similarity checks.
        Requires the embedding function and vector DB to be initialized.
        
        Args:
            pattern_text: The text content of the attack pattern.
            metadata: Optional metadata associated with the pattern (e.g., attack type, source).
            
        Returns:
            Dictionary indicating success or failure, and the ID of the added pattern.
        """
        if not self.vector_db or not self.embedding_function:
            self.logger.error("Cannot add attack pattern: Vector database or embedding function not initialized.")
            return {"success": False, "error": "Vector DB not initialized"}
            
        try:
            # Normalize text before embedding
            normalized_text = self._normalize_text(pattern_text)
            embedding = self.embedding_function(normalized_text)

            # Prepare metadata, ensuring it's serializable if needed by the DB implementation
            entry_metadata = metadata or {}
            entry_metadata['original_text'] = pattern_text # Store original text for reference
            entry_metadata['added_time'] = datetime.now().isoformat()

            pattern_id = self.vector_db.add_entry(embedding, entry_metadata)
            self.logger.info(f"Added new attack pattern to vector database with ID: {pattern_id}")
            return {"success": True, "id": pattern_id}
            
        except Exception as e:
            self.logger.exception(f"Failed to add attack pattern: {e}")
            return {"success": False, "error": str(e)}
    
    def _normalize_text(self, text: str) -> str:
        """
        Basic text normalization for embedding and comparison.
        (e.g., lowercase, remove excessive whitespace).
        Can be expanded.
        
        Args:
            text: The input text.
            
        Returns:
            The normalized text.
        """
        text = text.lower()
        text = ' '.join(text.split()) # Remove excessive whitespace
        # Add more normalization steps if needed (e.g., remove punctuation, stemming)
        return text
    
    def save_state(self, base_path: str) -> Dict[str, bool]:
        """
        Save the state of components that support it (e.g., VectorDatabase).
        
        Args:
            base_path: The directory path where state files should be saved.
            
        Returns:
            A dictionary indicating the success status for each component saved.
        """
        os.makedirs(base_path, exist_ok=True)
        save_status: Dict[str, bool] = {}
        
        # Save Vector Database
        if self.vector_db:
            db_file_path = os.path.join(base_path, self.config.get("vector_db_filename", "vector_db.pkl"))
            try:
                success = self.vector_db.save_to_disk(db_file_path)
                save_status['vector_database'] = success
                if success:
                    self.logger.info(f"Vector database saved to {db_file_path}")
                else:
                    self.logger.warning(f"Failed to save vector database to {db_file_path}")
            except Exception as e:
                 self.logger.error(f"Error saving vector database: {e}")
                 save_status['vector_database'] = False


        # Add saving logic for other stateful components if necessary
        # e.g., if CanaryTokenManager tracked used tokens persistently
        # if self.canary_manager:
        #    manager_file_path = os.path.join(base_path, "canary_manager_state.json")
        #    # ... save logic ...
        #    save_status['canary_manager'] = success

        return save_status
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retrieve performance and operational statistics for the manager.

        Returns:
            A dictionary containing statistics.
        """
        stats = {
            "manager_uptime_seconds": (datetime.now() - self.creation_time).total_seconds(),
            "total_requests_processed": self.requests_processed,
            "requests_blocked_by_filters": self.requests_blocked,
            "requests_flagged_suspicious": self.requests_flagged, # Counts prompts flagged by detectors or VDB
            "active_filters": [type(f).__name__ for f in self.filters],
            "active_detectors": [type(d).__name__ for d in self.detectors],
            "vector_db_enabled": self.vector_db is not None,
            "canary_tokens_enabled": self.use_canary_tokens,
            }
        if self.vector_db:
            stats["vector_db_size"] = self.vector_db.get_size()
            
        return stats 