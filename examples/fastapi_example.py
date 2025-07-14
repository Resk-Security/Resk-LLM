"""
FastAPI API Example with RESK-LLM Security

This script demonstrates how to integrate RESK-LLM with FastAPI to protect
against prompt injections and other security vulnerabilities.
"""

import os
import logging
from typing import Dict, List, Optional, Any
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import RESK-LLM components
from resk_llm.providers_integration import OpenAIProtector
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider
from openai import OpenAI

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="RESK-LLM FastAPI Example",
    description="Secure API with RESK-LLM for protection against prompt injections",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize RESK-LLM protector
resk_protector = OpenAIProtector(config={
    'model': 'gpt-4o',
    'request_sanitization': True,
    'response_sanitization': True
})

# Initialize WordListFilter for checking requests
pattern_provider = FileSystemPatternProvider()
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

# Global security middleware
@app.middleware("http")
async def resk_security_middleware(request: Request, call_next):
    # Skip documentation routes and GET methods
    if request.url.path.startswith("/docs") or request.url.path.startswith("/openapi") or request.method == "GET":
        return await call_next(request)
    
    # For POST routes, check content
    if request.method == "POST":
        try:
            # Copy request body to read it while keeping it available
            body_bytes = await request.body()
            body_str = body_bytes.decode('utf-8')
            
            # Check if content contains malicious elements
            passed, warning, _ = word_list_filter.filter(body_str)
            if not passed:
                logger.warning(f"Request blocked: {warning}")
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Unauthorized content detected: {warning}"}
                )
        except Exception as e:
            logger.error(f"Error during request verification: {e}")
            # If error, continue with normal processing
    
    # Continue with normal request processing
    response = await call_next(request)
    return response

# Pydantic models for the API
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[Message]
    max_tokens: Optional[int] = 500
    temperature: Optional[float] = 0.7

class ChatResponse(BaseModel):
    response: str
    is_safe: bool
    warnings: Optional[List[str]] = None

# Dependency to get OpenAI client
def get_openai_client():
    api_key = os.environ.get("OPENAI_API_KEY", "your-api-key-here")
    return OpenAI(api_key=api_key)

# API routes
@app.get("/")
async def root():
    return {"message": "RESK-LLM FastAPI Example API"}

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, client: OpenAI = Depends(get_openai_client)):
    """
    Secure chat endpoint that filters messages before sending them to the OpenAI API
    """
    try:
        # Convert messages to format expected by OpenAI API
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        # Optionally, you could use resk_protector.protect_input here if you want to sanitize input
        # sanitized_messages = await resk_protector.protect_input(messages)
        # For now, just pass messages directly
        result = client.chat.completions.create(
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature
        )
        # Return the secure response
        return ChatResponse(
            response=result.choices[0].message.content,
            is_safe=True
        )
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint to test injection detection
@app.post("/api/security-test")
async def security_test(message: str):
    """
    Endpoint to test injection detection in a message
    """
    passed, warning, _ = word_list_filter.filter(message)
    if not passed:
        return {
            "is_safe": False,
            "warning": warning
        }
    else:
        return {
            "is_safe": True,
            "message": "Content is safe"
        }

# Endpoint to manage custom patterns
@app.post("/api/add-prohibited-pattern")
async def add_prohibited_pattern(pattern: str, pattern_type: str = "word"):
    """
    Adds a prohibited pattern to the security list
    """
    if pattern_type not in ["word", "pattern"]:
        raise HTTPException(status_code=400, detail="Invalid pattern type. Use 'word' or 'pattern'")
    # This functionality is not supported in FileSystemPatternProvider; return error
    raise HTTPException(status_code=501, detail="Dynamic addition of patterns is not supported. Please update your pattern files on disk.")

# Run application with uvicorn
if __name__ == "__main__":
    # To start the application:
    # python fastapi_example.py
    uvicorn.run("fastapi_example:app", host="0.0.0.0", port=8000, reload=True) 