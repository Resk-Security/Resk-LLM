"""
FastAPI integration module for securing LLM agent APIs.

This module provides classes and utilities to secure FastAPI applications
that interact with LLMs, particularly in the context of autonomous agents.
Features include protection against injections, input validation,
rate limiting, and custom pattern management.
"""

import os
import re
import json
import logging
import asyncio
import traceback
from typing import Callable, Dict, List, Any, Optional, Union, Type
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

from fastapi import FastAPI, Request, Response, Depends, HTTPException, APIRouter, status, Header, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from resk_llm.providers_integration import BaseProviderProtector, OpenAIProtector
from resk_llm.filtering_patterns import (
    check_for_obfuscation, 
    sanitize_text_from_obfuscation,
    check_text_for_injections,
    check_pii_content,
    moderate_text
)
from resk_llm.tokenizer_protection import ReskWordsLists, CustomPatternManager

# Logger configuration
logger = logging.getLogger(__name__)

# Pydantic models for data validation
class Message(BaseModel):
    """Message model for chat requests."""
    role: str
    content: str

class ChatRequest(BaseModel):
    """Chat request model with optional model specification."""
    messages: List[Message]
    model: Optional[str] = None
    
class AgentSecurityConfig(BaseModel):
    """Configuration model for agent security settings."""
    agent_id: str
    permissions: List[str] = Field(default_factory=list)
    rate_limit: int = 60
    max_tokens: int = 8192
    allowed_models: List[str] = Field(default_factory=lambda: [])
    api_keys: List[str] = Field(default_factory=lambda: [])
    is_active: bool = True
    temperature: Optional[float] = 0.7
    prohibited_words: Optional[List[str]] = Field(default_factory=lambda: [])
    prohibited_patterns: Optional[List[str]] = Field(default_factory=lambda: [])
    enable_pii_detection: Optional[bool] = True
    enable_moderation: Optional[bool] = True
    moderation_threshold: Optional[float] = 0.8

class Rate:
    """Rate tracking for rate limiting."""
    def __init__(self, limit: int = 60, window: int = 60):
        self.limit = limit  # Requests per window
        self.window = window  # Window in seconds
        self.tokens = limit
        self.last_refill_time = datetime.now()
        
    def request(self, tokens: int = 1) -> bool:
        """
        Request tokens for rate limiting.
        
        Args:
            tokens: Number of tokens to request
            
        Returns:
            True if request can proceed, False otherwise
        """
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
        
    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = datetime.now()
        time_passed = (now - self.last_refill_time).total_seconds()
        
        # Calculate tokens to add
        new_tokens = (time_passed / self.window) * self.limit
        if new_tokens > 0:
            self.tokens = min(self.limit, self.tokens + new_tokens)
            self.last_refill_time = now
                                     
class FastAPIProtector:
    """
    Protector for FastAPI applications that interact with LLMs.
    Provides security features for APIs, particularly for autonomous agents.
    """
    def __init__(self, 
                app: Optional[FastAPI] = None,
                default_model: str = "gpt-4o",
                rate_limit: int = 60,
                request_sanitization: bool = True,
                response_sanitization: bool = True,
                custom_patterns_dir: Optional[str] = None,
                enable_patterns_api: bool = False,
                patterns_api_prefix: str = "/api/patterns",
                api_key_header: str = "X-API-Key",
                agent_id_header: str = "X-Agent-ID",
                cors_origins: Optional[List[str]] = None,
                agent_security_enabled: bool = False,
                agent_configs_file: Optional[str] = None):
        """
        Initialize the FastAPI protector.
        
        Args:
            app: FastAPI application
            default_model: Default LLM model to use
            rate_limit: Requests per minute limit
            request_sanitization: Enable request sanitization
            response_sanitization: Enable response sanitization
            custom_patterns_dir: Directory for custom patterns
            enable_patterns_api: Enable patterns management API
            patterns_api_prefix: Prefix for patterns API routes
            api_key_header: Header name for API key
            agent_id_header: Header name for agent ID
            cors_origins: List of allowed CORS origins
            agent_security_enabled: Enable agent security features
            agent_configs_file: Path to agent configurations file
        """
        # Core settings
        self.default_model = default_model
        self.rate_limit = rate_limit
        self.request_sanitization = request_sanitization
        self.response_sanitization = response_sanitization
        
        # API settings
        self.api_key_header = api_key_header
        self.agent_id_header = agent_id_header
        self.cors_origins = cors_origins or ["*"]
        
        # Provider protector for LLM calls
        self._provider_protector = OpenAIProtector(model=default_model)
        
        # Custom patterns management
        self.custom_patterns_dir = custom_patterns_dir
        if custom_patterns_dir:
            self.pattern_manager = CustomPatternManager(base_directory=custom_patterns_dir)
        else:
            self.pattern_manager = CustomPatternManager()
            
        # Patterns API settings
        self.enable_patterns_api = enable_patterns_api
        self.patterns_api_prefix = patterns_api_prefix
        
        # Agent security
        self.agent_security_enabled = agent_security_enabled
        self.agent_configs_file = agent_configs_file
        self.agent_configs: Dict[str, AgentSecurityConfig] = {}
        self._rate_limiters: Dict[str, Rate] = {}
        
        # Load agent configurations if enabled
        if agent_security_enabled and agent_configs_file:
            self._load_agent_configs()
        
        # Initialize app if provided
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: FastAPI):
        """
        Initialize the FastAPI application with security features.
        
        Args:
            app: FastAPI application
        """
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Add request sanitization middleware if enabled
        if self.request_sanitization:
            @app.middleware("http")
            async def sanitize_request_middleware(request: Request, call_next):
                # Implement request sanitization before processing
                sanitized_request = self._sanitize_request(request)
                response = await call_next(sanitized_request)
                return response
        
        # Add response sanitization middleware if enabled
        if self.response_sanitization:
            @app.middleware("http")
            async def sanitize_response_middleware(request: Request, call_next):
                response = await call_next(request)
                
                # Check if JSON response
                if response.headers.get("content-type") == "application/json":
                    body = b""
                    async for chunk in response.body_iterator:
                        body += chunk
                    
                    # Parse and sanitize
                    try:
                        data = json.loads(body.decode())
                        sanitized_data = self._sanitize_response_data(data)
                        
                        # Create new response
                        return JSONResponse(
                            content=sanitized_data,
                            status_code=response.status_code,
                            headers=dict(response.headers)
                        )
                    except Exception as e:
                        logger.error(f"Error sanitizing response: {str(e)}")
                        # Return original response if error
                        return Response(
                            content=body,
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            media_type=response.media_type
                        )
                
                return response
        
        # Register patterns API if enabled
        if self.enable_patterns_api:
            self._register_patterns_api(app)
            
        # Add reference to protector
        app.state.resk_fastapi_protector = self
    
    def _sanitize_request(self, request: Request) -> Request:
        # Implement request sanitization logic here
        return request
    
    def _sanitize_response_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Implement response sanitization logic here
        return data
    
    def _load_agent_configs(self):
        # Implement loading agent configurations logic here
        pass
    
    def _register_patterns_api(self, app: FastAPI):
        """
        Enregistre les routes de l'API de gestion des patterns.
        
        Args:
            app: Application FastAPI
        """
        patterns_router = APIRouter(prefix=self.patterns_api_prefix, tags=["Patterns"])
        
        # Endpoint pour lister tous les patterns
        @patterns_router.get("/", response_model=Dict[str, Any])
        async def list_patterns(api_key: str = Header(None)):
            """Liste tous les patterns personnalisés disponibles."""
            # Vérifier l'authentification (implémentation simplifiée)
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentification requise")
            
            try:
                patterns = self.pattern_manager.list_custom_pattern_files()
                pattern_info = []
                
                for pattern_file in patterns:
                    try:
                        pattern_name = Path(pattern_file).stem
                        data = self.pattern_manager.load_custom_pattern_file(pattern_name)
                        
                        pattern_info.append({
                            "name": pattern_name,
                            "file": pattern_file,
                            "word_count": len(data.get("prohibited_words", [])),
                            "pattern_count": len(data.get("prohibited_patterns", []))
                        })
                    except Exception as e:
                        logger.error(f"Erreur lors du chargement du pattern {pattern_file}: {str(e)}")
                
                return {"patterns": pattern_info, "status": "success"}
            except Exception as e:
                logger.error(f"Erreur lors de la liste des patterns: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Erreur lors de la liste des patterns: {str(e)}"
                )
        
        # Endpoint pour récupérer un pattern spécifique
        @patterns_router.get("/{pattern_name}", response_model=Dict[str, Any])
        async def get_pattern(pattern_name: str, api_key: str = Header(None)):
            """Récupère un pattern spécifique par son nom."""
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentification requise")
            
            try:
                try:
                    data = self.pattern_manager.load_custom_pattern_file(pattern_name)
                    return {"name": pattern_name, "data": data, "status": "success"}
                except FileNotFoundError:
                    raise HTTPException(
                        status_code=404, 
                        detail=f"Pattern '{pattern_name}' non trouvé"
                    )
            except Exception as e:
                logger.error(f"Erreur lors de la récupération du pattern {pattern_name}: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Erreur lors de la récupération du pattern: {str(e)}"
                )
        
        # Endpoint pour créer un nouveau pattern
        @patterns_router.post("/", response_model=Dict[str, Any], status_code=201)
        async def create_pattern(pattern: PatternCreateRequest, api_key: str = Header(None)):
            """Crée un nouveau pattern personnalisé."""
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentification requise")
            
            try:
                # Valider les patterns regex
                for regex_pattern in pattern.prohibited_patterns:
                    try:
                        re.compile(regex_pattern)
                    except re.error as e:
                        raise HTTPException(
                            status_code=400, 
                            detail=f"Pattern regex invalide '{regex_pattern}': {str(e)}"
                        )
                
                # Créer le pattern
                file_path = self.pattern_manager.create_custom_pattern_file(
                    pattern.name,
                    words=pattern.prohibited_words,
                    patterns=pattern.prohibited_patterns
                )
                
                return {
                    "name": pattern.name,
                    "file": file_path,
                    "word_count": len(pattern.prohibited_words),
                    "pattern_count": len(pattern.prohibited_patterns),
                    "status": "success"
                }
            except Exception as e:
                logger.error(f"Erreur lors de la création du pattern: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Erreur lors de la création du pattern: {str(e)}"
                )
        
        # Endpoint pour mettre à jour un pattern existant
        @patterns_router.put("/{pattern_name}", response_model=Dict[str, Any])
        async def update_pattern(
            pattern_name: str, 
            pattern: PatternCreateRequest, 
            api_key: str = Header(None)
        ):
            """Met à jour un pattern existant."""
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentification requise")
            
            try:
                # Vérifier si le pattern existe
                try:
                    self.pattern_manager.load_custom_pattern_file(pattern_name)
                except FileNotFoundError:
                    raise HTTPException(
                        status_code=404, 
                        detail=f"Pattern '{pattern_name}' non trouvé"
                    )
                
                # Valider les patterns regex
                for regex_pattern in pattern.prohibited_patterns:
                    try:
                        re.compile(regex_pattern)
                    except re.error as e:
                        raise HTTPException(
                            status_code=400, 
                            detail=f"Pattern regex invalide '{regex_pattern}': {str(e)}"
                        )
                
                # Supprimer l'ancien fichier
                self.pattern_manager.delete_custom_pattern_file(pattern_name)
                
                # Créer le nouveau fichier
                file_path = self.pattern_manager.create_custom_pattern_file(
                    pattern_name,
                    words=pattern.prohibited_words,
                    patterns=pattern.prohibited_patterns
                )
                
                return {
                    "name": pattern_name,
                    "file": file_path,
                    "word_count": len(pattern.prohibited_words),
                    "pattern_count": len(pattern.prohibited_patterns),
                    "status": "success"
                }
            except Exception as e:
                logger.error(f"Erreur lors de la mise à jour du pattern {pattern_name}: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Erreur lors de la mise à jour du pattern: {str(e)}"
                )
        
        # Endpoint pour supprimer un pattern
        @patterns_router.delete("/{pattern_name}", response_model=Dict[str, Any])
        async def delete_pattern(pattern_name: str, api_key: str = Header(None)):
            """Supprime un pattern existant."""
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentification requise")
            
            try:
                success = self.pattern_manager.delete_custom_pattern_file(pattern_name)
                if success:
                    return {"message": f"Pattern '{pattern_name}' supprimé avec succès", "status": "success"}
                else:
                    raise HTTPException(
                        status_code=404, 
                        detail=f"Pattern '{pattern_name}' non trouvé"
                    )
            except Exception as e:
                logger.error(f"Erreur lors de la suppression du pattern {pattern_name}: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail=f"Erreur lors de la suppression du pattern: {str(e)}"
                )
        
        # Enregistrer le routeur dans l'application
        app.include_router(patterns_router)

# Fonctions de dépendance pour utiliser facilement le protecteur dans les applications FastAPI

def get_fastapi_protector(request: Request) -> FastAPIProtector:
    """
    Fonction de dépendance pour récupérer l'instance du protecteur FastAPI.
    
    Args:
        request: Requête FastAPI
        
    Returns:
        Instance du protecteur FastAPI
    """
    return request.app.state.resk_fastapi_protector


def agent_permission_required(permission: str):
    """
    Fonction de dépendance pour vérifier qu'un agent a une permission spécifique.
    
    Args:
        permission: Permission requise
        
    Returns:
        Fonction de dépendance
    """
    def check_permission(
        request: Request,
        protector: FastAPIProtector = Depends(get_fastapi_protector)
    ):
        if not protector.agent_security_enabled:
            return True
        
        agent_id = request.headers.get(protector.agent_id_header)
        if not agent_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent ID requis"
            )
        
        config = protector.agent_configs.get(agent_id)
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent avec ID '{agent_id}' non trouvé"
            )
        
        if permission not in config.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"L'agent n'a pas la permission '{permission}'"
            )
        
        return True
    
    return check_permission

class PatternCreateRequest(BaseModel):
    """Request model for creating or updating custom patterns."""
    name: str = Field(..., description="Name of the pattern set")
    description: Optional[str] = Field(None, description="Description of the pattern set")
    prohibited_words: List[str] = Field(default_factory=lambda: [], description="List of prohibited words")
    prohibited_patterns: List[str] = Field(default_factory=lambda: [], description="List of regex patterns")
    is_active: bool = Field(True, description="Whether the pattern set is active")

def create_resk_fastapi_app(
    openai_api_key: Optional[str] = None,
    anthropic_api_key: Optional[str] = None,
    cohere_api_key: Optional[str] = None,
    openrouter_api_key: Optional[str] = None,
    deepseek_api_key: Optional[str] = None,
    cors_origins: Optional[List[str]] = None,
    rate_limit: Optional[int] = None
) -> FastAPI:
    """
    Creates a FastAPI app with RESK-LLM security features.
    
    Args:
        openai_api_key: OpenAI API key
        anthropic_api_key: Anthropic API key
        cohere_api_key: Cohere API key
        openrouter_api_key: OpenRouter API key
        deepseek_api_key: DeepSeek API key
        cors_origins: List of allowed CORS origins
        rate_limit: Rate limit for API calls
        
    Returns:
        FastAPI app
    """
    if cors_origins is None:
        cors_origins = ["*"]

    if rate_limit is None:
        rate_limit = 60

    # Create the FastAPI app
    app = FastAPI()

    # Create the FastAPIProtector
    protector = FastAPIProtector(
        app=app,
        default_model="gpt-4o",
        rate_limit=rate_limit,
        request_sanitization=True,
        response_sanitization=True,
        custom_patterns_dir=None,
        enable_patterns_api=False,
        patterns_api_prefix="/api/patterns",
        api_key_header="X-API-Key",
        agent_id_header="X-Agent-ID",
        cors_origins=cors_origins,
        agent_security_enabled=False,
        agent_configs_file=None
    )

    # Add the protector to the app state
    app.state.resk_fastapi_protector = protector

    return app 