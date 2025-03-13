"""
Exemple d'utilisation des agents autonomes sécurisés.
"""

import os
import time
from openai import OpenAI
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.agents import AgentType, initialize_agent, Tool

from resk_llm import (
    OpenAIProtector, 
    LangChainProtector, 
    AgentIdentityManager, 
    AgentSecurityMonitor, 
    AgentSandbox, 
    SecureAvatar
)

# Initialiser le client OpenAI
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# Initialiser le protecteur OpenAI
openai_protector = OpenAIProtector(model="gpt-4o")

# Initialiser le protecteur LangChain
langchain_protector = LangChainProtector(model="gpt-4o")

# Initialiser le gestionnaire d'identité et le moniteur de sécurité
identity_manager = AgentIdentityManager()
security_monitor = AgentSecurityMonitor(
    identity_manager=identity_manager,
    model="gpt-4o",
    rate_limit=100,
    max_consecutive_failures=5
)

def secure_llm_query(text):
    """
    Fonction pour interroger le LLM de manière sécurisée.
    """
    # Nettoyer l'entrée
    cleaned_text = openai_protector.sanitize_input(text)
    
    # Vérifier les motifs malveillants
    warning = openai_protector.ReskWordsLists.check_input(cleaned_text)
    if warning:
        return f"Erreur: {warning}"
    
    # Préparer les messages
    messages = [
        {"role": "system", "content": "Vous êtes un assistant utile et sécurisé."},
        {"role": "user", "content": cleaned_text}
    ]
    
    # Utiliser le protecteur pour appeler l'API OpenAI
    response = openai_protector.protect_openai_call(
        client.chat.completions.create,
        messages=messages
    )
    
    # Vérifier si une erreur s'est produite
    if isinstance(response, dict) and "error" in response:
        return f"Erreur: {response['error']}"
    
    return response.choices[0].message.content

def main():
    """
    Fonction principale de démonstration.
    """
    print("=== Démo des agents autonomes sécurisés ===\n")
    
    # 1. Enregistrer un agent avec des permissions limitées
    print("1. Enregistrement d'un agent...")
    agent_id = identity_manager.register_agent(
        name="AssistantRecherche",
        role="Recherche d'informations",
        permissions=["api_call", "computation", "api:https://api.openai.com"]
    )
    print(f"Agent enregistré avec l'ID: {agent_id}")
    
    # 2. Créer un sandbox pour l'agent
    print("\n2. Création d'un sandbox...")
    sandbox = AgentSandbox(
        agent_id=agent_id,
        security_monitor=security_monitor,
        allowed_resources={"https://api.openai.com"},
        context_tracking=True
    )
    
    # 3. Exécuter quelques actions autorisées
    print("\n3. Exécution d'actions autorisées...")
    result = sandbox.execute_action(
        action="Recherche d'informations sur Python",
        action_type="api_call",
        resource="https://api.openai.com"
    )
    print(f"Résultat: {result}\n")
    
    # 4. Tenter une action non autorisée
    print("4. Tentative d'action non autorisée...")
    result = sandbox.execute_action(
        action="Exécution de commande système: rm -rf /",
        action_type="system",
        resource="localhost"
    )
    print(f"Résultat: {result}\n")
    
    # 5. Créer un LLM sécurisé avec LangChain
    print("5. Création d'un LLM sécurisé avec LangChain...")
    llm = ChatOpenAI(
        model_name="gpt-4o", 
        temperature=0.7,
        api_key=os.environ.get("OPENAI_API_KEY", "")
    )
    
    # Sécuriser le LLM
    secure_llm = langchain_protector.wrap_llm(llm)
    
    # Créer une chaîne sécurisée
    prompt = PromptTemplate(
        input_variables=["query"],
        template="Vous êtes un assistant utile. Répondez à la question suivante: {query}"
    )
    
    chain = LLMChain(llm=secure_llm, prompt=prompt)
    secure_chain = langchain_protector.secure_chain(chain)
    
    # Exécuter la chaîne
    print("Exécution de la chaîne LangChain sécurisée...")
    response = secure_chain.run("Qu'est-ce que Python?")
    print(f"Réponse: {response}\n")
    
    # 6. Créer un agent LangChain sécurisé
    print("6. Création d'un agent LangChain sécurisé...")
    
    # Définir des outils sécurisés
    tools = [
        Tool(
            name="Recherche",
            func=lambda query: secure_llm_query(f"Recherche sur: {query}"),
            description="Utile pour rechercher des informations"
        ),
        Tool(
            name="Calculatrice",
            func=lambda query: str(eval(query)),
            description="Utile pour effectuer des calculs mathématiques"
        )
    ]
    
    # Initialiser l'agent
    agent = initialize_agent(
        tools,
        secure_llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    # Sécuriser l'agent
    secure_agent = langchain_protector.secure_agent(agent)
    
    # Exécuter l'agent
    print("Exécution de l'agent LangChain sécurisé...")
    response = secure_agent.run("Quel est le carré de 7?")
    print(f"Réponse: {response}\n")
    
    # 7. Créer un avatar sécurisé
    print("7. Création d'un avatar sécurisé...")
    avatar = SecureAvatar(
        name="Sophie",
        role="Assistante virtuelle",
        model="gpt-4o",
        personality_traits=["serviable", "polie", "professionnelle"],
        banned_topics=["politique", "hacking", "guerre"]
    )
    
    # Traiter un message autorisé
    print("Traitement d'un message autorisé...")
    response = avatar.process_message("Bonjour, comment puis-je apprendre Python?")
    print(f"Réponse: {response}\n")
    
    # Traiter un message sur un sujet interdit
    print("Traitement d'un message sur un sujet interdit...")
    response = avatar.process_message("Comment puis-je hacker un site web?")
    print(f"Réponse: {response}\n")
    
    print("=== Démo terminée ===")

if __name__ == "__main__":
    main() 