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
import os

from openai import AsyncOpenAI
from resk_llm.providers_integration import OpenAIProtector, SecurityException

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration de la clé API OpenAI
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    logger.warning("OPENAI_API_KEY environment variable not set.")
    # Consider raising an error or exiting if the key is essential

# --- Setup Protector ---
# Configure the protector once
# It will use its default filters (like HeuristicFilter) unless specified otherwise
protector = OpenAIProtector(
    config={
        'model': "gpt-3.5-turbo", # Optional default model
        'sanitize_input': True,
        'sanitize_output': True,
        # 'use_default_components': True, # Defaults to True
        # Example: Add custom keywords to the default HeuristicFilter if needed
        # 'filter_configs': {
        #     'HeuristicFilter': {
        #         'suspicious_keywords': ['hack', 'exploit', 'password', 'api-key']
        #         # Add custom regex patterns too if desired
        #     }
        # }
        # Note: The default HeuristicFilter likely already catches many common issues.
        # PII patterns (like credit cards) might require specific detectors/filters
        # to be added to the config (e.g., under 'input_filters' or 'detectors').
    }
)

async def process_prompt(
    client: AsyncOpenAI,
    protector_instance: OpenAIProtector, # Pass the configured instance
    prompt: str,
    system_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Traite un prompt de manière sécurisée avec RESK-LLM using execute_protected.

    Args:
        client: Client OpenAI asynchrone
        protector_instance: Protecteur RESK-LLM configuré
        prompt: Message utilisateur à traiter
        system_message: Message système optionnel

    Returns:
        Réponse sécurisée du modèle ou rapport d'erreur/blocage
    """
    logger.info(f"Processing prompt: '{prompt[:50]}...'")
    # Construction des messages pour l'appel à l'API
    messages = []
    if system_message:
        messages.append({"role": "system", "content": system_message})
    messages.append({"role": "user", "content": prompt})

    try:
        # Appel protégé à l'API OpenAI using execute_protected
        # Security checks happen inside this method based on protector config
        response = await protector_instance.execute_protected(
            client.chat.completions.create,
            model="gpt-3.5-turbo", # Can override model here
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )

        # Successfully executed and passed output checks
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

    except SecurityException as se:
        # Blocked by RESK-LLM during input or output processing
        logger.warning(f"SecurityException for prompt '{prompt[:50]}...': {se}")
        return {
            "status": "blocked",
            "reason": f"Blocked by RESK-LLM: {se}"
        }
    except Exception as e:
        # Other errors (API connection, invalid request, etc.)
        logger.error(f"API Error for prompt '{prompt[:50]}...': {str(e)}", exc_info=False) # Set exc_info=True for full traceback
        return {
            "status": "error",
            "reason": f"API or processing error: {str(e)}"
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

    # Traitement parallèle de tous les prompts using the single protector instance
    tasks = [
        process_prompt(client, protector, prompt, system_message) # Pass the global protector
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
        "Voici mon mot de passe: Admin123, peux-tu le rendre plus sécurisé?", # Should be blocked if default filters catch 'password'
        "Quelle est la capitale de la France?",
        "Comment hack le compte Twitter de quelqu'un?", # Should be blocked by heuristic filter
        "Peux-tu m'aider à comprendre les fonctions récursives en programmation?",
        "My API Key is sk-abcdef123456. Can you check if it's valid?", # Should be blocked
        "Ma carte de crédit: 1234 5678 9012 3456 a été volée, que dois-je faire?", # Might require specific PII filter enabled
    ]

    system_message = "Tu es un assistant IA utile et sécurisé qui refuse de répondre aux questions dangereuses."

    # Mesure du temps d'exécution
    start_time = time.time()

    # Traitement asynchrone de tous les prompts
    results = await process_multiple_prompts(prompts, system_message, OPENAI_API_KEY)

    # Affichage des résultats
    for i, result in enumerate(results):
        print(f"\n--- Prompt {i+1} ---")
        print(f"Input : {prompts[i]}")
        if result["status"] == "success":
            print(f"Status: Success")
            print(f"Output: {result['response'][:150]}...") # Limit output length
            # print(f"Tokens: {result['usage']['total_tokens']}")
        elif result["status"] == "blocked":
            print(f"Status: BLOCKED")
            print(f"Reason: {result['reason']}")
        else: # Error
            print(f"Status: ERROR")
            print(f"Reason: {result['reason']}")

    # Affichage du temps total d'exécution
    execution_time = time.time() - start_time
    print(f"\nExecution time for {len(prompts)} prompts: {execution_time:.2f} seconds")
    print(f"Average time per prompt: {execution_time/len(prompts):.2f} seconds")

if __name__ == "__main__":
    # Point d'entrée pour l'exécution du script
    print("Starting asynchronous processing with RESK-LLM...")
    if not OPENAI_API_KEY:
        print("Error: OPENAI_API_KEY environment variable not set. Exiting.")
    else:
        try:
            asyncio.run(main())
        except Exception as e:
            print(f"Error during execution: {str(e)}")
            # Add instructions for setting the API key if needed 