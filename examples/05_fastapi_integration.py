#!/usr/bin/env python3
"""
RESK-LLM v2.1 - FastAPI integration example

Run with: uvicorn examples.05_fastapi_integration:app --reload
"""

from fastapi import FastAPI
from resk2 import SecurityPipeline
from resk2.detectors import DirectInjectionDetector, BypassDetector, MemoryPoisoningDetector
from resk2.integrations import ReskMiddleware

# Create app
app = FastAPI(title="RESK-LLM Protected API")

# Build security pipeline
pipeline = (
    SecurityPipeline()
    .add(DirectInjectionDetector())
    .add(BypassDetector())
    .add(MemoryPoisoningDetector())
)

# Add middleware (auto-scans all POST/PUT/PATCH bodies)
app.add_middleware(ReskMiddleware, pipeline=pipeline, excluded_paths=["/health"])


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/chat")
async def chat(body: dict):
    """Chat endpoint - only reached if input passes security"""
    message = body.get("message", "")
    return {
        "response": f"Echo: {message}",
        "note": "This response only returned because input passed security checks",
    }
