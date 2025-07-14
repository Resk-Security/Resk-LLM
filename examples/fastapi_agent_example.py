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
import uvicorn
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

from resk_llm.fastapi_integration import FastAPIProtector
from resk_llm.pattern_provider import FileSystemPatternProvider
from resk_llm.word_list_filter import WordListFilter

API_KEY = os.environ.get("OPENAI_API_KEY", "")
PATTERNS_DIR = os.path.join(os.path.dirname(__file__), "agent_patterns")
os.makedirs(PATTERNS_DIR, exist_ok=True)

app = FastAPI(
    title="RESK-LLM Agent API",
    description="Secure API for interacting with LLM agents",
    version="0.3.0"
)

pattern_provider = FileSystemPatternProvider(config={"patterns_base_dir": PATTERNS_DIR})
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

protector = FastAPIProtector(config={
    "app": app,
    "custom_patterns_dir": PATTERNS_DIR,
    "enable_patterns_api": True,
    "patterns_api_prefix": "/api/patterns",
    "cors_origins": ["*"],
    "request_sanitization": True,
    "response_sanitization": True,
})

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

@app.get("/")
async def root():
    return {
        "name": "RESK-LLM Agent API",
        "version": "0.3.0",
        "description": "Secure API for interacting with LLM agents",
        "documentation": "/docs"
    }

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: Request, chat_data: ChatRequest):
    # Simulate a secure LLM response (replace with actual API call)
    model_response = f"Secure response from model {chat_data.model}. Your request has been processed following security best practices."
    return ChatResponse(
        response=model_response,
        model=chat_data.model,
        safe_level="high"
    )

@app.post("/api/moderate", response_model=ModerationResponse)
async def moderate_content(request: Request, moderation_data: ModerationRequest):
    text = moderation_data.text
    warnings = []
    details: Dict[str, Any] = {}
    is_safe = True
    # Example: Use word_list_filter to check for issues
    passed, reason, _ = word_list_filter.filter(text)
    if not passed:
        warnings.append(f"Blocked: {reason}")
        is_safe = False
    sanitized_text = text if is_safe else "[SANITIZED]"
    return ModerationResponse(
        text=text,
        is_safe=is_safe,
        sanitized_text=sanitized_text,
        warnings=warnings,
        details=details
    )

# Entry point for direct execution
if __name__ == "__main__":
    uvicorn.run("fastapi_agent_example:app", host="0.0.0.0", port=8000, reload=True) 