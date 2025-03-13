"""
Exemple d'utilisation de l'intégration FastAPI pour sécuriser des agents LLM.

Cet exemple montre comment configurer une API FastAPI qui expose en toute sécurité 
des agents LLM, avec des fonctionnalités comme:
- La protection contre les injections de prompts
- La gestion des permissions et identités des agents
- La modération de contenu
- La limitation de débit
- La gestion des patterns personnalisés
"""

import os
import json
import uvicorn
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, Depends, Request, HTTPException, Header, status
from pydantic import BaseModel, Field

# Importer les composants RESK-LLM
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


# Configuration
API_KEY = os.environ.get("OPENAI_API_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "secure_admin_key_change_me")
PATTERNS_DIR = os.path.join(os.path.dirname(__file__), "agent_patterns")
os.makedirs(PATTERNS_DIR, exist_ok=True)

# Créer l'application FastAPI
app = FastAPI(
    title="RESK-LLM Agent API",
    description="API sécurisée pour interagir avec des agents LLM",
    version="0.3.0"
)

# Configuration du protecteur FastAPI
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
    cors_origins=["*"],  # En production, spécifiez les origines exactes
    request_sanitization=True,
    response_sanitization=True
)

# Protecteurs pour différents fournisseurs d'IA
anthropic_protector = AnthropicProtector()
cohere_protector = CohereProtector()

# Initialiser quelques agents pour notre exemple
@app.on_event("startup")
async def startup_event():
    # Agent d'assistance générale avec des permissions limitées
    protector.agent_configs["agent-assistant"] = AgentSecurityConfig(
        agent_id="agent-assistant",
        permissions=["chat", "moderate"],
        rate_limit=100,
        max_tokens=8192,
        allowed_models=["gpt-3.5-turbo", "gpt-4o", "claude-3-opus"],
        api_keys=["assistant_api_key_123", ADMIN_API_KEY]
    )
    
    # Agent de recherche avec des permissions étendues
    protector.agent_configs["agent-researcher"] = AgentSecurityConfig(
        agent_id="agent-researcher",
        permissions=["chat", "moderate", "search", "web_access", "file_access"],
        rate_limit=200,
        max_tokens=16384,
        allowed_models=["*"],  # Tous les modèles
        api_keys=["researcher_api_key_456", ADMIN_API_KEY]
    )
    
    # Agent de modération qui vérifie le contenu
    protector.agent_configs["agent-moderator"] = AgentSecurityConfig(
        agent_id="agent-moderator",
        permissions=["moderate", "pattern_management"],
        rate_limit=500,
        max_tokens=4096,
        allowed_models=["gpt-4o", "claude-3-haiku"],
        api_keys=["moderator_api_key_789", ADMIN_API_KEY]
    )

# Modèles de données pour nos API
class ChatMessage(BaseModel):
    role: str = Field(..., description="Rôle de l'émetteur (system, user, assistant)")
    content: str = Field(..., description="Contenu du message")

class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., description="Historique de la conversation")
    model: str = Field("gpt-4o", description="Modèle à utiliser")
    max_tokens: Optional[int] = Field(None, description="Nombre maximum de tokens de la réponse")

class ChatResponse(BaseModel):
    response: str = Field(..., description="Réponse de l'agent")
    model: str = Field(..., description="Modèle utilisé")
    agent_id: str = Field(..., description="ID de l'agent qui a répondu")
    safe_level: str = Field("standard", description="Niveau de sécurité appliqué")

class ModerationRequest(BaseModel):
    text: str = Field(..., description="Texte à modérer")
    check_pii: bool = Field(True, description="Vérifier les informations personnelles")
    check_toxicity: bool = Field(True, description="Vérifier le contenu toxique")

class ModerationResponse(BaseModel):
    text: str = Field(..., description="Texte original")
    is_safe: bool = Field(..., description="Le texte est-il sûr?")
    sanitized_text: Optional[str] = Field(None, description="Version nettoyée du texte")
    warnings: List[str] = Field(default=[], description="Avertissements détectés")
    details: Dict[str, Any] = Field(default={}, description="Détails de la modération")

class AgentActionRequest(BaseModel):
    action: str = Field(..., description="Action à effectuer")
    parameters: Dict[str, Any] = Field(default={}, description="Paramètres de l'action")
    context: Optional[str] = Field(None, description="Contexte de l'action")

class AgentActionResponse(BaseModel):
    success: bool = Field(..., description="L'action a-t-elle réussi?")
    result: Optional[Any] = Field(None, description="Résultat de l'action")
    error: Optional[str] = Field(None, description="Message d'erreur si échec")

# Routes API
@app.get("/")
async def root():
    """Page d'accueil de l'API."""
    return {
        "name": "RESK-LLM Agent API",
        "version": "0.3.0",
        "description": "API sécurisée pour interagir avec des agents LLM",
        "documentation": "/docs"
    }

# Endpoint de chat sécurisé
@app.post("/api/chat", response_model=ChatResponse)
@protector.secure_endpoint(check_prompt=True, check_pii=True, check_toxicity=True, agent_permission="chat")
async def chat(
    request: Request,
    chat_data: ChatRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint pour discuter avec un agent LLM de manière sécurisée.
    Protégé contre les injections et vérifie les permissions de l'agent.
    """
    # Vérifier si le modèle demandé est autorisé pour cet agent
    agent_config = protector.agent_configs.get(agent_id)
    if not agent_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent avec ID '{agent_id}' non trouvé"
        )
    
    if "*" not in agent_config.allowed_models and chat_data.model not in agent_config.allowed_models:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Le modèle '{chat_data.model}' n'est pas autorisé pour cet agent"
        )
    
    # Simuler une réponse d'un LLM (à remplacer par l'appel réel à l'API du fournisseur)
    try:
        # Exemple de logique de routage vers le bon protecteur selon le modèle
        if "claude" in chat_data.model:
            # Utiliser le protecteur Anthropic pour les modèles Claude
            model_response = f"Réponse sécurisée de Claude pour l'agent {agent_id}. Le modèle {chat_data.model} " \
                            f"a traité votre demande en toute sécurité."
        elif "command" in chat_data.model:
            # Utiliser le protecteur Cohere pour les modèles Command
            model_response = f"Réponse sécurisée de Cohere pour l'agent {agent_id}. Le modèle {chat_data.model} " \
                            f"a traité votre demande en toute sécurité."
        else:
            # Utiliser le protecteur de base pour les autres modèles
            model_response = f"Réponse sécurisée du modèle {chat_data.model} pour l'agent {agent_id}. " \
                            f"Votre demande a été traitée en respectant les bonnes pratiques de sécurité."
        
        # Construction de la réponse
        return ChatResponse(
            response=model_response,
            model=chat_data.model,
            agent_id=agent_id,
            safe_level="high"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'appel au modèle: {str(e)}"
        )

# Endpoint de modération
@app.post("/api/moderate", response_model=ModerationResponse)
@protector.secure_endpoint(agent_permission="moderate")
async def moderate_content(
    request: Request,
    moderation_data: ModerationRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint pour modérer du contenu et détecter les problèmes potentiels.
    """
    text = moderation_data.text
    warnings = []
    details = {}
    is_safe = True
    
    # Vérifier les tentatives d'obfuscation
    obfuscation = check_for_obfuscation(text)
    if obfuscation:
        warnings.append("Tentative d'obfuscation détectée")
        details["obfuscation"] = obfuscation
        is_safe = False
    
    # Vérifier les injections
    injections = check_text_for_injections(text)
    if injections:
        warnings.append("Tentative d'injection détectée")
        details["injections"] = list(injections.keys())
        is_safe = False
    
    # Vérifier les informations personnelles si demandé
    if moderation_data.check_pii:
        pii_results = check_pii_content(text)
        if pii_results:
            warnings.append("Informations personnelles détectées")
            details["pii"] = list(pii_results.keys())
            is_safe = False
    
    # Vérifier le contenu toxique si demandé
    if moderation_data.check_toxicity:
        from resk_llm.filtering_patterns import moderate_text
        moderation_result = moderate_text(text)
        if not moderation_result["is_approved"]:
            warnings.append(f"Contenu inapproprié: {moderation_result['recommendation']}")
            details["toxicity"] = moderation_result
            is_safe = False
    
    # Sanitiser le texte si des problèmes ont été détectés
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

# Endpoint pour les actions de l'agent
@app.post("/api/agent/action", response_model=AgentActionResponse)
@protector.secure_endpoint(check_prompt=True)
async def agent_action(
    request: Request,
    action_data: AgentActionRequest,
    api_key: str = Header(...),
    agent_id: str = Header(...)
):
    """
    Endpoint pour exécuter une action spécifique par un agent.
    Les actions permises dépendent des permissions de l'agent.
    """
    # Récupérer la configuration de l'agent
    agent_config = protector.agent_configs.get(agent_id)
    if not agent_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent avec ID '{agent_id}' non trouvé"
        )
    
    # Vérifier si l'agent a la permission d'exécuter cette action
    action = action_data.action
    
    # Cartographie des actions vers les permissions requises
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
            detail=f"L'agent n'a pas la permission '{required_permission}' requise pour l'action '{action}'"
        )
    
    # Simulation de l'exécution de l'action
    try:
        if action == "search":
            # Simuler une recherche
            return AgentActionResponse(
                success=True,
                result={
                    "matches": ["Résultat 1", "Résultat 2", "Résultat 3"],
                    "total": 3
                }
            )
        elif action == "read_file":
            # Simuler la lecture d'un fichier
            file_path = action_data.parameters.get("path", "")
            if not file_path:
                return AgentActionResponse(
                    success=False,
                    error="Chemin de fichier non spécifié"
                )
            return AgentActionResponse(
                success=True,
                result={
                    "content": f"Contenu simulé du fichier {file_path}",
                    "size": 1024
                }
            )
        elif action == "web_request":
            # Simuler une requête web
            url = action_data.parameters.get("url", "")
            if not url:
                return AgentActionResponse(
                    success=False,
                    error="URL non spécifiée"
                )
            return AgentActionResponse(
                success=True,
                result={
                    "status": 200,
                    "content": f"Contenu simulé de {url}"
                }
            )
        else:
            return AgentActionResponse(
                success=False,
                error=f"Action '{action}' non prise en charge"
            )
    except Exception as e:
        return AgentActionResponse(
            success=False,
            error=f"Erreur lors de l'exécution de l'action: {str(e)}"
        )

# Endpoint protégé par une permission spécifique
@app.get("/api/agent/status")
async def agent_status(
    request: Request,
    _=Depends(agent_permission_required("system_status"))
):
    """
    Endpoint pour obtenir le statut système de l'agent.
    Nécessite la permission 'system_status'.
    """
    # Cette route n'est accessible qu'aux agents ayant la permission system_status
    return {
        "status": "operational",
        "uptime": "12h 34m",
        "memory_usage": "256 MB",
        "active_tasks": 5
    }

# Page d'administration sécurisée
@app.get("/admin")
async def admin_page(
    request: Request,
    api_key: str = Header(...)
):
    """Page d'administration pour gérer les agents."""
    # Vérifier que l'utilisateur a la clé d'API d'administration
    if api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API d'administration invalide"
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
        "title": "Administration des agents",
        "agents": agents_info,
        "patterns_url": "/api/patterns",
        "status": "ok"
    }

# Point d'entrée pour l'exécution directe
if __name__ == "__main__":
    uvicorn.run("fastapi_agent_example:app", host="0.0.0.0", port=8000, reload=True) 