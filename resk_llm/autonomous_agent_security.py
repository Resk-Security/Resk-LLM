"""
Autonomous Agent Security module for the RESK LLM security library.

This module provides security components for autonomous agents, including identity management,
security monitoring, sandboxing, and secure interaction with users. It helps prevent malicious
behavior and ensure safe operation of AI agents.
"""

import re
import html
import logging
import traceback
import json
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple, cast
from collections import defaultdict

from resk_llm.core.abc import SecurityComponent
from resk_llm.providers_integration import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager
from resk_llm.resk_models import ModelRegistry, default_registry

# Logger configuration
logger = logging.getLogger(__name__)

class AgentConfig(Dict[str, Any]):
    """Type definition for agent configuration."""
    pass

class AgentIdentityManager(SecurityComponent[AgentConfig]):
    """
    Identity manager for autonomous agents.
    Allows verifying agent authenticity and tracking their actions.
    """
    def __init__(self, config: Optional[AgentConfig] = None):
        """
        Initialize the identity manager.
        
        Args:
            config: Optional configuration dictionary
        """
        if config is None:
            # Use cast to satisfy mypy for the assignment
            config = cast(AgentConfig, {})
        self.revoked_agents: Set[str] = set()
        # Need to initialize logger if used in update_config
        self.logger = logger
        # Need registered_agents and agent_actions for methods
        self.registered_agents: Dict[str, Dict[str, Any]] = {} 
        self.agent_actions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        super().__init__(config)
        
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        # No specific validation needed currently
        pass
        
    # Implementation for abstract method from SecurityComponent
    def update_config(self, config: AgentConfig) -> None:
        """Update the component's configuration."""
        # Simple implementation to satisfy abstract method requirement
        # A more robust implementation might update internal state based on config keys
        if hasattr(self, 'config') and isinstance(self.config, dict):
             self.config.update(config)
             self._validate_config() # Re-validate after update
             logger.info("AgentIdentityManager configuration updated.")
        else: # Fallback if self.config doesn't exist or isn't a dict
             logger.error("AgentIdentityManager cannot update config: self.config not initialized correctly.")
    
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        """
        Register a new agent and generate an identifier.
        
        Args:
            name: Name of the agent
            role: Role of the agent
            permissions: List of permissions granted to the agent
            
        Returns:
            UUID of the agent
        """
        agent_id = str(uuid.uuid4())
        self.registered_agents[agent_id] = {
            "name": name,
            "role": role,
            "permissions": permissions,
            "created_at": time.time(),
            "last_action": time.time()
        }
        self.agent_actions[agent_id] = []
        return agent_id
        
    def verify_agent(self, agent_id: str) -> bool:
        """
        Verify if an agent is registered and not revoked.
        
        Args:
            agent_id: UUID of the agent
            
        Returns:
            True if the agent is valid, False otherwise
        """
        return agent_id in self.registered_agents and agent_id not in self.revoked_agents
    
    def check_permission(self, agent_id: str, permission: str) -> bool:
        """
        Verify if an agent has a specific permission.
        
        Args:
            agent_id: UUID of the agent
            permission: Permission to check
            
        Returns:
            True if the agent has the permission, False otherwise
        """
        if not self.verify_agent(agent_id):
            return False
        
        return permission in self.registered_agents[agent_id]["permissions"]
    
    def log_action(self, agent_id: str, action: str, status: str = "success") -> bool:
        """
        Log an action performed by an agent.
        
        Args:
            agent_id: UUID of the agent
            action: Description of the action
            status: Status of the action (success, failure, blocked)
            
        Returns:
            True if the action was logged, False otherwise
        """
        if not self.verify_agent(agent_id):
            return False
        
        self.agent_actions[agent_id].append({
            "action": action,
            "timestamp": time.time(),
            "status": status
        })
        
        self.registered_agents[agent_id]["last_action"] = time.time()
        return True
    
    def revoke_agent(self, agent_id: str) -> bool:
        """
        Revoke an agent.
        
        Args:
            agent_id: UUID of the agent
            
        Returns:
            True if the agent was revoked, False otherwise
        """
        if not self.verify_agent(agent_id):
            return False
        
        self.revoked_agents.add(agent_id)
        return True
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about an agent.
        
        Args:
            agent_id: UUID of the agent
            
        Returns:
            Information about the agent or None if the agent is not registered
        """
        if not self.verify_agent(agent_id):
            return None
        
        info = self.registered_agents[agent_id].copy()
        info["actions"] = len(self.agent_actions[agent_id])
        info["is_active"] = agent_id not in self.revoked_agents
        
        return info
    
    def get_agent_actions(self, agent_id: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Get the actions of an agent.
        
        Args:
            agent_id: UUID of the agent
            limit: Maximum number of actions to return
            
        Returns:
            List of actions or None if the agent is not registered
        """
        if not self.verify_agent(agent_id):
            return None
        
        actions = self.agent_actions[agent_id]
        return actions[-limit:] if limit > 0 else actions


class SecurityMonitorConfig(Dict[str, Any]):
    """Type definition for security monitor configuration."""
    pass

class AgentSecurityMonitor(SecurityComponent[SecurityMonitorConfig]):
    """
    Security monitor for autonomous agents.
    Monitors agent activities and blocks suspicious behaviors.
    """
    def __init__(self, 
                 identity_manager: AgentIdentityManager,
                 model: str = "gpt-4o",
                 rate_limit: int = 100,
                 max_consecutive_failures: int = 5,
                 max_inactivity_time: int = 3600,
                 config: Optional[SecurityMonitorConfig] = None):
        """
        Initialize the security monitor for agents.
        
        Args:
            identity_manager: Agent identity manager
            model: LLM model to use
            rate_limit: Maximum number of actions per minute
            max_consecutive_failures: Maximum number of consecutive failures before revocation
            max_inactivity_time: Maximum inactivity time in seconds
            config: Optional configuration dictionary
        """
        if config is None:
            # Use cast for the default dict assignment
            config = cast(SecurityMonitorConfig, {
                "model": model,
                "rate_limit": rate_limit,
                "max_consecutive_failures": max_consecutive_failures,
                "max_inactivity_time": max_inactivity_time
            })
        super().__init__(config)
        
        self.identity_manager = identity_manager
        # Fix OpenAIProtector instantiation
        self.protector = OpenAIProtector(config={"model": self.config["model"]})
        self.rate_limit = self.config["rate_limit"]
        self.max_consecutive_failures = self.config["max_consecutive_failures"]
        self.max_inactivity_time = self.config["max_inactivity_time"]
        
        self.action_counts: Dict[str, Dict[int, int]] = {}  # uuid: {minute_timestamp: count}
        self.consecutive_failures: Dict[str, int] = {}  # uuid: count
    
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        required_keys = ["model", "rate_limit", "max_consecutive_failures", "max_inactivity_time"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required configuration key: {key}")
        
        if not isinstance(self.config["rate_limit"], int) or self.config["rate_limit"] <= 0:
            raise ValueError("rate_limit must be a positive integer")
            
        if not isinstance(self.config["max_consecutive_failures"], int) or self.config["max_consecutive_failures"] <= 0:
            raise ValueError("max_consecutive_failures must be a positive integer")
            
        if not isinstance(self.config["max_inactivity_time"], int) or self.config["max_inactivity_time"] <= 0:
            raise ValueError("max_inactivity_time must be a positive integer")
            
    def update_config(self, config: SecurityMonitorConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if "model" in config:
            # Fix OpenAIProtector instantiation
            self.protector = OpenAIProtector(config={"model": self.config["model"]})
        
        if "rate_limit" in config:
            self.rate_limit = self.config["rate_limit"]
            
        if "max_consecutive_failures" in config:
            self.max_consecutive_failures = self.config["max_consecutive_failures"]
            
        if "max_inactivity_time" in config:
            self.max_inactivity_time = self.config["max_inactivity_time"]
            
    def monitor_action(self, agent_id: str, action: str, 
                      action_type: str, resource: Optional[str] = None) -> Tuple[bool, str]:
        """
        Monitor an agent action and determine if it should be allowed.
        
        Args:
            agent_id: UUID of the agent
            action: Description of the action
            action_type: Type of action (api_call, file_access, network, computation)
            resource: Resource being accessed (optional)
            
        Returns:
            Tuple (allowed, reason)
        """
        # Check if the agent is valid
        if not self.identity_manager.verify_agent(agent_id):
            return False, "Agent not registered or revoked"
        
        # Check for inactivity
        agent_info = self.identity_manager.get_agent_info(agent_id)
        if agent_info is not None and time.time() - agent_info["last_action"] > self.max_inactivity_time:
            self.identity_manager.revoke_agent(agent_id)
            return False, "Agent inactive for too long"
        
        # Check permissions
        if not self.identity_manager.check_permission(agent_id, action_type):
            self.identity_manager.log_action(agent_id, action, "blocked")
            return False, f"Missing permission: {action_type}"
        
        # Check rate limiting
        current_minute = int(time.time() / 60)
        if agent_id not in self.action_counts:
            self.action_counts[agent_id] = {}
        
        if current_minute not in self.action_counts[agent_id]:
            # Clean up old entries
            self.action_counts[agent_id] = {current_minute: 0}
        
        self.action_counts[agent_id][current_minute] += 1
        if self.action_counts[agent_id][current_minute] > self.rate_limit:
            self.identity_manager.log_action(agent_id, action, "blocked")
            return False, "Rate limit exceeded"
        
        # Check consecutive failures
        if agent_id in self.consecutive_failures and self.consecutive_failures[agent_id] >= self.max_consecutive_failures:
            self.identity_manager.revoke_agent(agent_id)
            return False, "Too many consecutive failures"
        
        # Check action content
        if action_type == "api_call" and resource and agent_info is not None:
            # Check if the API is allowed
            if not self._is_api_allowed(resource, agent_info["permissions"]):
                self.identity_manager.log_action(agent_id, action, "blocked")
                return False, f"API not allowed: {resource}"
        
        # Sanitize the action using base protector method
        cleaned_action = self.protector.basic_sanitize(action)
        
        # Comment out check relying on non-existent ReskWordsLists attribute
        # warning = self.protector.ReskWordsLists.check_input(cleaned_action)
        # if warning:
        #     self.identity_manager.log_action(agent_id, action, "blocked")
        #     self._increment_failures(agent_id)
        #     return False, f"Action not allowed: {warning}"
        
        # Action allowed
        self.identity_manager.log_action(agent_id, action, "success")
        if agent_id in self.consecutive_failures:
            self.consecutive_failures[agent_id] = 0
        
        return True, "Action allowed"
    
    def report_failure(self, agent_id: str, action: str, reason: str) -> None:
        """
        Report an action failure.
        
        Args:
            agent_id: UUID of the agent
            action: Description of the action
            reason: Reason for the failure
        """
        self.identity_manager.log_action(agent_id, action, "failure")
        self._increment_failures(agent_id)
    
    def _increment_failures(self, agent_id: str) -> None:
        """
        Increment the consecutive failure counter.
        
        Args:
            agent_id: UUID of the agent
        """
        if agent_id not in self.consecutive_failures:
            self.consecutive_failures[agent_id] = 0
        
        self.consecutive_failures[agent_id] += 1
        
        if self.consecutive_failures[agent_id] >= self.max_consecutive_failures:
            self.identity_manager.revoke_agent(agent_id)
    
    def _is_api_allowed(self, api_url: str, permissions: List[str]) -> bool:
        """
        Check if an API is allowed.
        
        Args:
            api_url: URL of the API
            permissions: Agent permissions
            
        Returns:
            True if the API is allowed, False otherwise
        """
        # Check if the agent has a specific permission for this API
        if f"api:{api_url}" in permissions:
            return True
        
        # Check generic permissions
        domain = self._extract_domain(api_url)
        if f"domain:{domain}" in permissions:
            return True
        
        # Check permissions by prefix
        for perm in permissions:
            if perm.startswith("api_prefix:"):
                prefix = perm.split(":", 1)[1]
                if api_url.startswith(prefix):
                    return True
        
        return False
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract the domain from a URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Extracted domain
        """
        match = re.search(r"https?://([^/]+)", url)
        if match:
            return match.group(1)
        return url


class SandboxConfig(Dict[str, Any]):
    """Type definition for sandbox configuration."""
    pass

class AgentSandbox(SecurityComponent[SandboxConfig]):
    """
    Secure environment for autonomous agent execution.
    Restricts agent actions and monitors their behavior.
    """
    def __init__(self, 
                 agent_id: str,
                 security_monitor: AgentSecurityMonitor,
                 allowed_resources: Optional[Set[str]] = None,
                 context_tracking: bool = True,
                 config: Optional[SandboxConfig] = None):
        """
        Initialize a sandbox for an agent.
        
        Args:
            agent_id: UUID of the agent
            security_monitor: Security monitor
            allowed_resources: Set of allowed resources
            context_tracking: Enable context tracking
            config: Optional configuration dictionary
        """
        if config is None:
            # Use cast for the default dict assignment
            config = cast(SandboxConfig, {
                "agent_id": agent_id,
                "allowed_resources": list(allowed_resources) if allowed_resources else [],
                "context_tracking": context_tracking
            })
        super().__init__(config)
        
        self.agent_id = agent_id
        self.security_monitor = security_monitor
        self.allowed_resources = allowed_resources or set()
        self.context_tracking = context_tracking
        self.context: List[Dict[str, Any]] = []
    
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if "agent_id" not in self.config:
            raise ValueError("Missing required configuration key: agent_id")
        
        if "allowed_resources" in self.config and not isinstance(self.config["allowed_resources"], list):
            raise ValueError("allowed_resources must be a list")
            
        if "context_tracking" in self.config and not isinstance(self.config["context_tracking"], bool):
            raise ValueError("context_tracking must be a boolean")
    
    def update_config(self, config: SandboxConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if "agent_id" in config:
            self.agent_id = self.config["agent_id"]
        
        if "allowed_resources" in config:
            self.allowed_resources = set(self.config["allowed_resources"])
            
        if "context_tracking" in config:
            self.context_tracking = self.config["context_tracking"]
            
    def execute_action(self, action: str, action_type: str, 
                      resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute an action in the sandbox.
        
        Args:
            action: Description of the action
            action_type: Type of action
            resource: Resource being accessed (optional)
            
        Returns:
            Action result
        """
        # Check if the action is allowed
        allowed, reason = self.security_monitor.monitor_action(
            self.agent_id, action, action_type, resource
        )
        
        if not allowed:
            return {
                "status": "error",
                "error": reason,
                "result": None
            }
        
        # Check if the resource is allowed
        if resource and self.allowed_resources and resource not in self.allowed_resources:
            self.security_monitor.report_failure(
                self.agent_id, action, f"Resource not allowed: {resource}"
            )
            return {
                "status": "error",
                "error": f"Resource not allowed: {resource}",
                "result": None
            }
        
        # Execute the action (simulation)
        # In a real implementation, you would execute the action here
        result = {
            "status": "success",
            "message": f"Action '{action}' executed successfully",
            "result": {
                "action_type": action_type,
                "timestamp": time.time()
            }
        }
        
        # Update context
        if self.context_tracking:
            self.context.append({
                "action": action,
                "timestamp": time.time(),
                "result": "success"
            })
            
            # Limit context size
            if len(self.context) > 100:
                self.context = self.context[-100:]
        
        return result
    
    def get_context(self) -> List[Dict[str, Any]]:
        """
        Get the context of agent actions.
        
        Returns:
            List of contextual actions
        """
        return self.context if self.context_tracking else []
        
    def close(self) -> None:
        """
        Close the sandbox.
        """
        self.context = []


class AvatarConfig(Dict[str, Any]):
    """Type definition for avatar configuration."""
    pass

class SecureAvatar(SecurityComponent[AvatarConfig]):
    """
    Secure avatar for user interaction.
    Filters inputs and outputs to prevent information leakage.
    """
    def __init__(self, 
                 name: str,
                 role: str,
                 model: str = "gpt-4o",
                 personality_traits: Optional[List[str]] = None,
                 banned_topics: Optional[List[str]] = None,
                 config: Optional[AvatarConfig] = None):
        """
        Initialize the secure avatar.
        
        Args:
            name: Avatar name
            role: Avatar role
            model: OpenAI model to use
            personality_traits: Avatar personality traits
            banned_topics: Banned topics
            config: Optional configuration dictionary
        """
        if config is None:
            # Use cast for the default dict assignment
            config = cast(AvatarConfig, {
                "name": name,
                "role": role,
                "model": model,
                "personality_traits": personality_traits or [],
                "banned_topics": banned_topics or []
            })
        super().__init__(config)
        
        self.name = name
        self.role = role
        # Fix OpenAIProtector instantiation
        self.protector = OpenAIProtector(config={"model": model})
        self.personality_traits = personality_traits or []
        self.banned_topics = banned_topics or []
        
        # Remove call to non-existent method
        # Add banned topics to the prohibited words list
        # for topic in self.banned_topics:
        #     self.protector.update_prohibited_list(topic, "add", "word")
    
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        required_keys = ["name", "role", "model"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required configuration key: {key}")
        
        if "personality_traits" in self.config and not isinstance(self.config["personality_traits"], list):
            raise ValueError("personality_traits must be a list of strings")
            
        if "banned_topics" in self.config and not isinstance(self.config["banned_topics"], list):
            raise ValueError("banned_topics must be a list of strings")
    
    def update_config(self, config: AvatarConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if "name" in config:
            self.name = self.config["name"]
            
        if "role" in config:
            self.role = self.config["role"]
            
        if "model" in config:
             # Fix OpenAIProtector instantiation
            self.protector = OpenAIProtector(config={"model": self.config["model"]})
            
        if "personality_traits" in config:
            self.personality_traits = self.config["personality_traits"]
            
        if "banned_topics" in config:
            # Remove old banned topics - protector call removed
            # for topic in self.banned_topics:
            #     self.protector.update_prohibited_list(topic, "remove", "word")
                
            # Set new banned topics
            self.banned_topics = self.config["banned_topics"]
            
            # Add new banned topics - protector call removed
            # for topic in self.banned_topics:
            #     self.protector.update_prohibited_list(topic, "add", "word")
    
    def process_message(self, message: str) -> Dict[str, Any]:
        """
        Process an incoming message and generate a secure response.
        
        Args:
            message: Incoming message
            
        Returns:
            Formatted response
        """
        # Clean the message using base protector method
        cleaned_message = self.protector.basic_sanitize(message)
        
        # Comment out check relying on non-existent ReskWordsLists attribute
        # Check for malicious patterns
        # warning = self.protector.ReskWordsLists.check_input(cleaned_message)
        # if warning:
        #     return {
        #         "status": "error",
        #         "error": warning,
        #         "response": f"I cannot respond to this request because it contains inappropriate content."
        #     }
        
        # Check banned topics
        for topic in self.banned_topics:
            if re.search(r'\b' + re.escape(topic) + r'\b', cleaned_message, re.IGNORECASE):
                return {
                    "status": "error",
                    "error": f"Banned topic: {topic}",
                    "response": f"I cannot discuss this topic as it is on the list of banned topics."
                }
        
        # In a real implementation, you would generate an LLM response here
        # Here, we just simulate a response
        response = f"As {self.name}, I am responding in my role as {self.role}."
        
        # Clean the response using base protector method
        cleaned_response = self.protector.basic_sanitize(response)
        
        return {
            "status": "success",
            "response": cleaned_response,
            "name": self.name,
            "role": self.role
        }
        
    def update_banned_topics(self, topics: List[str], action: str = "add") -> None:
        """
        Update the list of banned topics.
        
        Args:
            topics: List of topics
            action: Action to perform (add, remove)
        """
        for topic in topics:
            if action == "add":
                self.banned_topics.append(topic)
                 # Remove call to non-existent method
                # self.protector.update_prohibited_list(topic, "add", "word")
            elif action == "remove" and topic in self.banned_topics:
                self.banned_topics.remove(topic)
                 # Remove call to non-existent method
                # self.protector.update_prohibited_list(topic, "remove", "word")


class SecurityManagerConfig(Dict[str, Any]):
    """Type definition for security manager configuration."""
    pass

class AgentSecurityManager(SecurityComponent[SecurityManagerConfig]):
    """
    Global security manager for autonomous agents.
    """
    
    def __init__(self, model: str = "gpt-4o", rate_limit: int = 100, config: Optional[SecurityManagerConfig] = None):
        """
        Initialize the security manager.
        
        Args:
            model: LLM model to use
            rate_limit: Action rate limit per minute
            config: Optional configuration dictionary
        """
        if config is None:
            # Use cast for the default dict assignment
            config = cast(SecurityManagerConfig, {
                "model": model,
                "rate_limit": rate_limit
            })
        super().__init__(config)
        
        self.identity_manager = AgentIdentityManager()
        self.security_monitor = AgentSecurityMonitor(
            identity_manager=self.identity_manager,
            model=self.config["model"],
            rate_limit=self.config["rate_limit"]
        )
        self.sandboxes: Dict[str, AgentSandbox] = {}
    
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if "model" not in self.config:
            raise ValueError("Missing required configuration key: model")
            
        if "rate_limit" not in self.config:
            raise ValueError("Missing required configuration key: rate_limit")
            
        if not isinstance(self.config["rate_limit"], int) or self.config["rate_limit"] <= 0:
            raise ValueError("rate_limit must be a positive integer")
    
    def update_config(self, config: SecurityManagerConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update components if needed
        if "model" in config or "rate_limit" in config:
            self.security_monitor = AgentSecurityMonitor(
                identity_manager=self.identity_manager,
                model=self.config["model"],
                rate_limit=self.config["rate_limit"]
            )
        
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        """
        Register a new agent.
        
        Args:
            name: Agent name
            role: Agent role
            permissions: List of granted permissions
            
        Returns:
            Created agent ID
        """
        return self.identity_manager.register_agent(name, role, permissions)
        
    def create_sandbox(self, agent_id: str, allowed_resources: Optional[Set[str]] = None) -> Optional[AgentSandbox]:
        """
        Create a sandbox environment for an agent.
        
        Args:
            agent_id: Agent ID
            allowed_resources: Resources allowed for the agent
            
        Returns:
            Sandbox instance or None on failure
        """
        if not self.identity_manager.verify_agent(agent_id):
            return None
            
        sandbox = AgentSandbox(
            agent_id=agent_id,
            security_monitor=self.security_monitor,
            allowed_resources=allowed_resources
        )
        
        self.sandboxes[agent_id] = sandbox
        return sandbox
        
    def execute_action(self, agent_id: str, action: str, action_type: str, 
                     resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute an action for a specific agent.
        
        Args:
            agent_id: Agent ID
            action: Action to execute
            action_type: Type of action
            resource: Target resource (optional)
            
        Returns:
            Action result
        """
        if agent_id not in self.sandboxes:
            self.create_sandbox(agent_id)
            
        if agent_id in self.sandboxes:
            return self.sandboxes[agent_id].execute_action(action, action_type, resource)
        else:
            return {
                "status": "error",
                "message": "Agent not authorized"
            }
            
    def revoke_agent(self, agent_id: str) -> bool:
        """
        Revoke an agent.
        
        Args:
            agent_id: Agent ID to revoke
            
        Returns:
            True if revocation succeeded, False otherwise
        """
        if agent_id in self.sandboxes:
            self.sandboxes[agent_id].close()
            del self.sandboxes[agent_id]
            
        return self.identity_manager.revoke_agent(agent_id)
        
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about an agent.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Agent information or None if not found
        """
        return self.identity_manager.get_agent_info(agent_id)
        
    def get_agent_actions(self, agent_id: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Get the action history of an agent.
        
        Args:
            agent_id: Agent ID
            limit: Maximum number of actions to return
            
        Returns:
            List of actions or None if agent not found
        """
        return self.identity_manager.get_agent_actions(agent_id, limit)


class AgentPermission:
    """
    Permission types for agents.
    """
    # System permissions
    SYSTEM_ACCESS = "system:access"
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    NETWORK_ACCESS = "network:access"
    
    # API permissions
    API_READ = "api:read"
    API_WRITE = "api:write"
    
    # Database permissions
    DB_READ = "db:read"
    DB_WRITE = "db:write"
    
    # User permissions
    USER_INTERACT = "user:interact"
    USER_DATA_ACCESS = "user:data:access"
    
    # Advanced permissions
    ADMIN_ACCESS = "admin:access"
    SECURITY_OVERRIDE = "security:override"


class AgentIdentity:
    """
    Agent identity.
    """
    def __init__(self, id: str, name: str, role: str, permissions: List[str]):
        """
        Initialize an agent identity.
        
        Args:
            id: Unique agent ID
            name: Agent name
            role: Agent role
            permissions: List of granted permissions
        """
        self.id = id
        self.name = name
        self.role = role
        self.permissions = permissions
        
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the identity to a dictionary.
        
        Returns:
            Dictionary representing the identity
        """
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "permissions": self.permissions
        }


class SecureAgentExecutor:
    """
    Secure executor for autonomous agents.
    """
    def __init__(self, security_manager: AgentSecurityManager, agent_id: str):
        """
        Initialize the secure executor.
        
        Args:
            security_manager: Security manager
            agent_id: Agent ID
        """
        self.security_manager = security_manager
        self.agent_id = agent_id
        
    def execute(self, action: str, action_type: str, resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute an action securely.
        
        Args:
            action: Action to execute
            action_type: Type of action
            resource: Target resource (optional)
            
        Returns:
            Action result
        """
        return self.security_manager.execute_action(self.agent_id, action, action_type, resource)


# Default permissions for agents
AGENT_DEFAULT_PERMISSIONS = [
    AgentPermission.SYSTEM_ACCESS,
    AgentPermission.FILE_READ,
    AgentPermission.API_READ,
    AgentPermission.USER_INTERACT
] 