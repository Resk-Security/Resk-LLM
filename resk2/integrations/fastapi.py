"""FastAPI middleware for RESK-LLM."""
from __future__ import annotations
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from resk2.core import SecurityPipeline, PipelineResult

class ReskMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that scans request bodies through security pipeline.
    
    Usage:
        from fastapi import FastAPI
        from resk2.integrations import ReskMiddleware
        
        app = FastAPI()
        app.add_middleware(ReskMiddleware, 
                          excluded_paths=["/health", "/docs"],
                          on_block=custom_block_handler)
    """
    
    def __init__(self, app, pipeline: SecurityPipeline | None = None,
                 excluded_paths: list[str] | None = None,
                 on_block: Callable | None = None,
                 include_response_check: bool = True):
        super().__init__(app)
        self.pipeline = pipeline or SecurityPipeline()
        self.excluded_paths = excluded_paths or ["/health", "/docs", "/openapi.json", "/redoc"]
        self.on_block = on_block or self._default_block
        self.include_response_check = include_response_check

    @staticmethod
    def _default_block(request: Request, result: PipelineResult) -> JSONResponse:
        threats = ", ".join(t.reason for t in result.threats)
        return JSONResponse(
            status_code=400,
            content={
                "error": "blocked",
                "reason": result.block_reason,
                "threats": [t.to_dict() for t in result.threats],
            },
        )

    async def dispatch(self, request: Request, call_next):
        # Skip excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Only check POST/PUT/PATCH with body
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        # Read and check body
        try:
            body = await request.body()
            if not body:
                return await call_next(request)

            text = body.decode("utf-8", errors="replace")
            
            # Check input through pipeline
            result = self.pipeline.run(text)
            if result.blocked:
                return self.on_block(request, result)

            # Store result for potential response check
            request.state.security_result = result

        except Exception:
            # If we can't read body, pass through (fail open for robustness)
            pass

        response = await call_next(request)

        # Optionally check response
        if self.include_response_check and hasattr(request.state, 'security_result'):
            # Response check placeholder for future implementation
            pass

        return response
