"""
Exemple d'API FastAPI sécurisée avec RESK-LLM
Ce script montre comment intégrer RESK-LLM avec FastAPI pour protéger
contre les injections de prompts et autres vulnérabilités de sécurité.
"""

import os
import logging
from typing import Dict, List, Optional, Any
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import des composants RESK-LLM
from resk_llm.providers_integration import OpenAIProtector
from openai import OpenAI

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Création de l'application FastAPI
app = FastAPI(
    title="RESK-LLM FastAPI Example",
    description="API sécurisée avec RESK-LLM pour la protection contre les injections de prompts",
    version="1.0.0"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialisation du protecteur RESK-LLM
resk_protector = OpenAIProtector(
    model="gpt-4o",
    preserved_prompts=2,
    request_sanitization=True,
    response_sanitization=True
)

# Middleware de sécurité global
@app.middleware("http")
async def resk_security_middleware(request: Request, call_next):
    # Ignorer les routes de documentation et les méthodes GET
    if request.url.path.startswith("/docs") or request.url.path.startswith("/openapi") or request.method == "GET":
        return await call_next(request)
    
    # Pour les routes POST, vérifier le contenu
    if request.method == "POST":
        try:
            # Copier le corps de la requête pour pouvoir à la fois le lire et le laisser disponible
            body_bytes = await request.body()
            body_str = body_bytes.decode('utf-8')
            
            # Vérifier si le contenu contient des éléments malveillants
            warning = resk_protector.ReskWordsLists.check_input(body_str)
            if warning:
                logger.warning(f"Requête bloquée: {warning}")
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Contenu non autorisé détecté: {warning}"}
                )
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la requête: {e}")
            # En cas d'erreur, on continue le traitement normal
    
    # Continuer le traitement normal de la requête
    response = await call_next(request)
    return response

# Modèles Pydantic pour l'API
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

# Dépendance pour obtenir le client OpenAI
def get_openai_client():
    api_key = os.environ.get("OPENAI_API_KEY", "your-api-key-here")
    return OpenAI(api_key=api_key)

# Routes de l'API
@app.get("/")
async def root():
    return {"message": "RESK-LLM FastAPI Example API"}

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, client: OpenAI = Depends(get_openai_client)):
    """
    Endpoint chat sécurisé qui filtre les messages avant de les envoyer à l'API OpenAI
    """
    try:
        # Convertir les messages au format attendu par l'API OpenAI
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        
        # Utiliser RESK-LLM pour protéger l'appel à l'API OpenAI
        result = resk_protector.protect_openai_call(
            client.chat.completions.create,
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature
        )
        
        # Vérifier s'il y a une erreur (détection de contenu interdit)
        if isinstance(result, dict) and "error" in result:
            return ChatResponse(
                response="Je ne peux pas répondre à cette demande en raison de restrictions de sécurité.",
                is_safe=False,
                warnings=[result["error"]]
            )
        
        # Retourner la réponse sécurisée
        return ChatResponse(
            response=result.choices[0].message.content,
            is_safe=True
        )
        
    except Exception as e:
        logger.error(f"Erreur lors du traitement de la requête: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint pour tester la détection d'injections
@app.post("/api/security-test")
async def security_test(message: str):
    """
    Endpoint pour tester la détection d'injections dans un message
    """
    warning = resk_protector.ReskWordsLists.check_input(message)
    if warning:
        return {
            "is_safe": False,
            "warning": warning
        }
    else:
        return {
            "is_safe": True,
            "message": "Le contenu est sûr"
        }

# Endpoint pour gérer les patterns personnalisés
@app.post("/api/add-prohibited-pattern")
async def add_prohibited_pattern(pattern: str, pattern_type: str = "word"):
    """
    Ajoute un pattern interdit à la liste de sécurité
    """
    if pattern_type not in ["word", "pattern"]:
        raise HTTPException(status_code=400, detail="Type de pattern invalide. Utilisez 'word' ou 'pattern'")
    
    success = resk_protector.ReskWordsLists.update_prohibited_list(pattern, "add", pattern_type)
    if success:
        return {"status": "success", "message": f"{pattern_type} ajouté avec succès"}
    else:
        raise HTTPException(status_code=500, detail=f"Échec de l'ajout du {pattern_type}")

# Lancer l'application avec uvicorn
if __name__ == "__main__":
    # Pour démarrer l'application:
    # python fastapi_example.py
    uvicorn.run("fastapi_example:app", host="0.0.0.0", port=8000, reload=True) 