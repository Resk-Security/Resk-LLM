#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Exemple d'utilisation asynchrone de RESK-LLM pour des traitements parallèles 
et une meilleure performance avec un grand nombre de requêtes.
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
import logging

from openai import AsyncOpenAI
from resk_llm.protectors.openai_protector import OpenAIProtector
from resk_llm.patterns.pattern_manager import PatternManager

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialisation du protecteur RESK-LLM avec un modèle personnalisé de sécurité
async def setup_protector() -> OpenAIProtector:
    """Initialise et configure un protecteur RESK asynchrone"""
    pattern_manager = PatternManager()
    
    # Ajout de quelques modèles de sécurité personnalisés
    pattern_manager.add_pattern(r"(?i)mot\s*de\s*passe", "PASSWORD_PATTERN")
    pattern_manager.add_pattern(r"(?i)api[-_\s]*key", "API_KEY_PATTERN")
    pattern_manager.add_pattern(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "CREDIT_CARD_PATTERN")
    
    # Création du protecteur avec notre gestionnaire de modèles
    protector = OpenAIProtector(pattern_manager=pattern_manager)
    
    # Ajouter des mots interdits
    protector.add_prohibited_word("hack")
    protector.add_prohibited_word("exploit")
    
    return protector

async def process_prompt(
    client: AsyncOpenAI,
    protector: OpenAIProtector,
    prompt: str,
    system_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Traite un prompt de manière sécurisée avec RESK-LLM
    
    Args:
        client: Client OpenAI asynchrone
        protector: Protecteur RESK-LLM configuré
        prompt: Message utilisateur à traiter
        system_message: Message système optionnel
        
    Returns:
        Réponse sécurisée du modèle ou rapport d'erreur
    """
    try:
        # Vérification de sécurité du prompt
        is_safe, issues = protector.check_input_safe(prompt)
        
        if not is_safe:
            logger.warning(f"Prompt non sécurisé détecté: {issues}")
            return {
                "status": "blocked",
                "reason": "Contenu non sécurisé détecté",
                "details": issues
            }
        
        # Construction des messages pour l'appel à l'API
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})
        
        # Appel protégé à l'API OpenAI
        # La méthode protect_openai_call peut être utilisée directement dans un contexte async
        response = await protector.protect_openai_call(
            client.chat.completions.create,
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )
        
        return {
            "status": "success",
            "response": response.choices[0].message.content,
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            }
        }
        
    except Exception as e:
        logger.error(f"Erreur lors du traitement du prompt: {str(e)}")
        return {
            "status": "error",
            "reason": str(e)
        }

async def process_multiple_prompts(
    prompts: List[str],
    system_message: Optional[str] = None,
    api_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Traite plusieurs prompts en parallèle pour une meilleure performance
    
    Args:
        prompts: Liste des prompts à traiter
        system_message: Message système optionnel
        api_key: Clé API OpenAI (optionnelle si définie dans l'environnement)
        
    Returns:
        Liste des résultats pour chaque prompt
    """
    # Initialisation du client OpenAI avec support async
    client = AsyncOpenAI(api_key=api_key)
    
    # Configuration du protecteur RESK
    protector = await setup_protector()
    
    # Traitement parallèle de tous les prompts
    tasks = [
        process_prompt(client, protector, prompt, system_message)
        for prompt in prompts
    ]
    
    # Attendre que tous les traitements soient terminés
    results = await asyncio.gather(*tasks)
    return results

async def main():
    """Fonction principale pour démontrer l'utilisation asynchrone"""
    # Exemples de prompts à traiter (certains sont sécurisés, d'autres non)
    prompts = [
        "Explique-moi comment fonctionne l'intelligence artificielle.",
        "Voici mon mot de passe: Admin123, peux-tu le rendre plus sécurisé?",
        "Quelle est la capitale de la France?",
        "Comment hack le compte Twitter de quelqu'un?",
        "Peux-tu m'aider à comprendre les fonctions récursives en programmation?",
        "Ma carte de crédit: 1234 5678 9012 3456 a été volée, que dois-je faire?",
    ]
    
    system_message = "Tu es un assistant IA utile et sécurisé qui refuse de répondre aux questions dangereuses."
    
    # Mesure du temps d'exécution
    start_time = time.time()
    
    # Traitement asynchrone de tous les prompts
    results = await process_multiple_prompts(prompts, system_message)
    
    # Affichage des résultats
    for i, result in enumerate(results):
        print(f"\n--- Prompt {i+1} ---")
        print(f"Prompt: {prompts[i]}")
        if result["status"] == "success":
            print(f"Réponse: {result['response'][:100]}...")
            print(f"Tokens: {result['usage']['total_tokens']}")
        else:
            print(f"Statut: {result['status']}")
            print(f"Raison: {result['reason']}")
            if "details" in result:
                print(f"Détails: {result['details']}")
    
    # Affichage du temps total d'exécution
    execution_time = time.time() - start_time
    print(f"\nTemps d'exécution total pour {len(prompts)} prompts: {execution_time:.2f} secondes")
    print(f"Temps moyen par prompt: {execution_time/len(prompts):.2f} secondes")

if __name__ == "__main__":
    # Point d'entrée pour l'exécution du script
    print("Démarrage du traitement asynchrone avec RESK-LLM...")
    asyncio.run(main()) 