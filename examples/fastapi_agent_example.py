"""
Example of using FastAPI integration to secure LLM agents.

This example demonstrates how to set up a FastAPI application that securely exposes LLM agents,
with features like:
- Protection against prompt injections
- Agent permission and identity management
- Content moderation
- Rate limiting
- Custom pattern management
"""

import os
import json
import uvicorn
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, Depends, Request, HTTPException, Header, status
from pydantic import BaseModel, Field

# Import RESK-LLM components
from resk_llm.fastapi_integration import (
    FastAPIProtector, 
    AgentSecurityConfig,
    agent_permission_required,
    get_fastapi_protector
)
from resk_llm.filtering_patterns import (
    check_for_obfuscation,
    sanitize_text_from_obfuscation,
    check_text_for_injections,
    check_pii_content
)
from resk_llm.providers_integration import AnthropicProtector, CohereProtector
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider

# Configuration
API_KEY = os.environ.get("OPENAI_API_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "secure_admin_key_change_me")
PATTERNS_DIR = os.path.join(os.path.dirname(__file__), "agent_patterns")
os.makedirs(PATTERNS_DIR, exist_ok=True)

# Create FastAPI application
app = FastAPI(
    title="RESK-LLM Agent API",
    description="Secure API for interacting with LLM agents",
    version="0.3.0"
)

# Initialize pattern provider
pattern_provider = FileSystemPatternProvider(patterns_dir=PATTERNS_DIR)

# Create word list filter with our pattern provider
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

# Configure FastAPI protector
protector = FastAPIProtector(
    app=app,
    default_model="gpt-4o",
    rate_limit=60,
    custom_patterns_dir=PATTERNS_DIR,
    enable_patterns_api=True,
    patterns_api_prefix="/api/patterns",
    agent_security_enabled=True,
    api_key_header="X-API-Key",
    agent_id_header="X-Agent-ID",
    cors_origins=["*"],  # In production, specify exact origins
    request_sanitization=True,
    response_sanitization=True,
    filters=[word_list_filter]  # Use our customized filter
)

# Protectors for different LLM providers
anthropic_protector = AnthropicProtector(filters=[word_list_filter])
cohere_protector = CohereProtector(filters=[word_list_filter])

# Initialize some agents for our example
@app.on_event("startup")
async def startup_event():
    # General assistance agent with limited permissions
    protector.agent_configs["agent-assistant"] = AgentSecurityConfig(
        agent_id="agent-assistant",
        permissions=["chat", "moderate"],
        rate_limit=100,
        max_tokens=8192,
        allowed_models=["gpt-3.5-turbo", "gpt-4o", "claude-3-opus"],
        api_keys=["assistant_api_key_123", ADMIN_API_KEY]
    )
    
    # Research agent with extended permissions
    protector.agent_configs["agent-researcher"] = AgentSecurityConfig(
        agent_id="agent-researcher",
        permissions=["chat", "moderate", "search", "web_access", "file_access"],
        rate_limit=200,
        max_tokens=16384,
        allowed_models=["*"],  # All models
        api_keys=["researcher_api_key_456", ADMIN_API_KEY]
    )
    
    # Moderation agent that checks content
    protector.agent_configs["agent-moderator"] = AgentSecurityConfig(
        agent_id="agent-moderator",
        permissions=["moderate", "pattern_management"],
        rate_limit=500,
        max_tokens=4096,
        allowed_models=["gpt-4o", "claude-3-haiku"],
        api_keys=["moderator_api_key_789", ADMIN_API_KEY]
    )

# Data models for our APIs
class ChatMessage(BaseModel):
    role: str = Field(..., description="Role of the sender (system, user, assistant)")
    content: str = Field(..., description="Message content")

class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., description="Conversation history")
    model: str = Field("gpt-4o", description="Model to use")
    max_tokens: Optional[int] = Field(None, description="Maximum number of tokens for response")

class ChatResponse(BaseModel):
    response: str = Field(..., description="Agent response")
    model: str = Field(..., description="Model used")
    agent_id: str = Field(..., description="ID of the responding agent")
    safe_level: str = Field("standard", description="Applied security level")

class ModerationRequest(BaseModel):
    text: str = Field(..., description="Text to moderate")
    check_pii: bool = Field(True, description="Check for personal information")
    check_toxicity: bool = Field(True, description="Check for toxic content")

class ModerationResponse(BaseModel):
    text: str = Field(..., description="Original text")
    is_safe: bool = Field(..., description="Is the text safe?")
    sanitized_text: Optional[str] = Field(None, description="Sanitized version of the text")
    warnings: List[str] = Field(default=[], description="Detected warnings")
    details: Dict[str, Any] = Field(default={}, description="Moderation details")

class AgentActionRequest(BaseModel):
    action: str = Field(..., description="Action to perform")
    parameters: Dict[str, Any] = Field(default={}, description="Action parameters")
    context: Optional[str] = Field(None, description="Action context")

class AgentActionResponse(BaseModel):
    success: bool = Field(..., description="Did the action succeed?")
    result: Optional[Any] = Field(None, description="Action result")
    error: Optional[str] = Field(None, description="Error message if failure")

# API Routes
@app.get("/")
async def root():
    """API home page."""
    return {
        "name": "RESK-LLM Agent API",
        "version": "0.3.0",
        "description": "Secure API for interacting with LLM agents",
        "documentation": "/docs"
    }

# Secure chat endpoint
@app.post("/api/chat", response_model=ChatResponse)
@protector.secure_endpoint(check_prompt=True, check_pii=True, check_toxicity=True, agent_permission="chat")
async def chat(
    request: Request,
    chat_data: ChatRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint for securely chatting with an LLM agent.
    Protected against injections and verifies agent permissions.
    """
    # Check if the requested model is allowed for this agent
    agent_config = protector.agent_configs.get(agent_id)
    if not agent_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with ID '{agent_id}' not found"
        )
    
    if "*" not in agent_config.allowed_models and chat_data.model not in agent_config.allowed_models:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Model '{chat_data.model}' not allowed for this agent"
        )
    
    # Simulate an LLM response (replace with actual API call to provider)
    try:
        # Example routing logic to the right protector based on model
        if "claude" in chat_data.model:
            # Use Anthropic protector for Claude models
            model_response = f"Secure response from Claude for agent {agent_id}. Model {chat_data.model} " \
                            f"has processed your request securely."
        elif "command" in chat_data.model:
            # Use Cohere protector for Command models
            model_response = f"Secure response from Cohere for agent {agent_id}. Model {chat_data.model} " \
                            f"has processed your request securely."
        else:
            # Use base protector for other models
            model_response = f"Secure response from model {chat_data.model} for agent {agent_id}. " \
                            f"Your request has been processed following security best practices."
        
        # Build response
        return ChatResponse(
            response=model_response,
            model=chat_data.model,
            agent_id=agent_id,
            safe_level="high"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error calling model: {str(e)}"
        )

# Moderation endpoint
@app.post("/api/moderate", response_model=ModerationResponse)
@protector.secure_endpoint(agent_permission="moderate")
async def moderate_content(
    request: Request,
    moderation_data: ModerationRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint for moderating content and detecting potential issues.
    """
    text = moderation_data.text
    warnings = []
    details = {}
    is_safe = True
    
    # Check for obfuscation attempts
    obfuscation = check_for_obfuscation(text)
    if obfuscation:
        warnings.append("Obfuscation attempt detected")
        details["obfuscation"] = obfuscation
        is_safe = False
    
    # Check for injections
    injections = check_text_for_injections(text)
    if injections:
        warnings.append("Injection attempt detected")
        details["injections"] = list(injections.keys())
        is_safe = False
    
    # Check for personal information if requested
    if moderation_data.check_pii:
        pii_results = check_pii_content(text)
        if pii_results:
            warnings.append("Personal information detected")
            details["pii"] = list(pii_results.keys())
            is_safe = False
    
    # Check for toxic content if requested
    if moderation_data.check_toxicity:
        from resk_llm.filtering_patterns import moderate_text
        moderation_result = moderate_text(text)
        if not moderation_result["is_approved"]:
            warnings.append(f"Inappropriate content: {moderation_result['recommendation']}")
            details["toxicity"] = moderation_result
            is_safe = False
    
    # Sanitize text if issues were detected
    sanitized_text = None
    if not is_safe:
        sanitized_text = sanitize_text_from_obfuscation(text)
    
    return ModerationResponse(
        text=text,
        is_safe=is_safe,
        sanitized_text=sanitized_text,
        warnings=warnings,
        details=details
    )

# Agent action endpoint
@app.post("/api/agent/action", response_model=AgentActionResponse)
@protector.secure_endpoint(check_prompt=True)
async def agent_action(
    request: Request,
    action_data: AgentActionRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint for executing a specific action by an agent.
    Allowed actions depend on agent permissions.
    """
    # Get agent configuration
    agent_config = protector.agent_configs.get(agent_id)
    if not agent_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with ID '{agent_id}' not found"
        )
    
    # Check if agent has permission to execute this action
    action = action_data.action
    
    # Map actions to required permissions
    action_permissions = {
        "search": "search",
        "read_file": "file_access",
        "write_file": "file_access",
        "web_request": "web_access",
        "code_execution": "code_execution",
        "update_patterns": "pattern_management"
    }
    
    required_permission = action_permissions.get(action)
    if required_permission and required_permission not in agent_config.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent doesn't have the '{required_permission}' permission required for '{action}' action"
        )
    
    # Simulate action execution
    try:
        if action == "search":
            # Simulate search
            return AgentActionResponse(
                success=True,
                result={
                    "matches": ["Result 1", "Result 2", "Result 3"],
                    "total": 3
                }
            )
        elif action == "read_file":
            # Simulate file reading
            file_path = action_data.parameters.get("path", "")
            if not file_path:
                return AgentActionResponse(
                    success=False,
                    error="File path not specified"
                )
            return AgentActionResponse(
                success=True,
                result={
                    "content": f"Simulated content of file {file_path}",
                    "size": 1024
                }
            )
        elif action == "web_request":
            # Simulate web request
            url = action_data.parameters.get("url", "")
            if not url:
                return AgentActionResponse(
                    success=False,
                    error="URL not specified"
                )
            return AgentActionResponse(
                success=True,
                result={
                    "status": 200,
                    "content": f"Simulated content from {url}"
                }
            )
        else:
            return AgentActionResponse(
                success=False,
                error=f"Action '{action}' not supported"
            )
    except Exception as e:
        return AgentActionResponse(
            success=False,
            error=f"Error executing action: {str(e)}"
        )

# Endpoint protected by specific permission
@app.get("/api/agent/status")
async def agent_status(
    request: Request,
    _=Depends(agent_permission_required("system_status"))
):
    """
    Endpoint to get agent system status.
    Requires 'system_status' permission.
    """
    # This route is only accessible to agents with system_status permission
    return {
        "status": "operational",
        "uptime": "12h 34m",
        "memory_usage": "256 MB",
        "active_tasks": 5
    }

# Secure admin page
@app.get("/admin")
async def admin_page(
    request: Request,
    api_key: str = Header(...)
):
    """Admin page for managing agents."""
    # Check that user has admin API key
    if api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key"
        )
    
    agents_info = []
    for agent_id, config in protector.agent_configs.items():
        agents_info.append({
            "id": agent_id,
            "permissions": config.permissions,
            "rate_limit": config.rate_limit,
            "models": config.allowed_models
        })
    
    return {
        "title": "Agent Administration",
        "agents": agents_info,
        "patterns_url": "/api/patterns",
        "status": "ok"
    }

# Entry point for direct execution
if __name__ == "__main__":
    uvicorn.run("fastapi_agent_example:app", host="0.0.0.0", port=8000, reload=True) 