import re
import html
import logging
from typing import Any, Dict, List, Optional, Union, Callable
import traceback

from resk_llm.openai_protector import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager
from resk_llm.resk_models import RESK_MODELS

# Configuration du logger
logger = logging.getLogger(__name__)

class LangChainProtector:
    """
    Protecteur pour les applications LangChain qui interagissent avec des LLM.
    Ajoute une couche de sécurité pour protéger contre les injections et les fuites de données.
    """
    def __init__(self, 
                 model: str = "gpt-4o", 
                 protected_chains: bool = True,
                 protected_agents: bool = True):
        """
        Initialise le protecteur LangChain.
        
        Args:
            model: Modèle OpenAI à utiliser
            protected_chains: Activer la protection des chaînes
            protected_agents: Activer la protection des agents
        """
        self.protector = OpenAIProtector(model=model)
        self.protected_chains = protected_chains
        self.protected_agents = protected_agents
        
    def wrap_llm(self, llm):
        """
        Enrobe un LLM LangChain avec une protection RESK.
        
        Args:
            llm: LLM LangChain à protéger
            
        Returns:
            LLM protégé
        """
        # Sauvegarde de la méthode originale
        original_call = llm._call
        
        # Méthode d'appel sécurisée
        def secure_call(prompt: str, stop: Optional[List[str]] = None, **kwargs) -> str:
            try:
                # Nettoyer le prompt
                cleaned_prompt = self.protector.sanitize_input(prompt)
                
                # Vérifier les motifs malveillants
                warning = self.protector.ReskWordsLists.check_input(cleaned_prompt)
                if warning:
                    logger.warning(f"Tentative d'injection détectée: {warning}")
                    return f"Erreur: {warning}"
                
                # Appel sécurisé au LLM original
                response = original_call(cleaned_prompt, stop=stop, **kwargs)
                
                # Nettoyer la réponse
                cleaned_response = self.protector.sanitize_input(response)
                
                return cleaned_response
            except Exception as e:
                logger.error(f"Erreur dans secure_call LLM: {str(e)}\n{traceback.format_exc()}")
                return "Une erreur s'est produite lors du traitement de votre demande."
        
        # Remplacer la méthode originale
        llm._call = secure_call
        
        return llm
    
    def secure_chain(self, chain):
        """
        Sécurise une chaîne LangChain.
        
        Args:
            chain: Chaîne LangChain à sécuriser
            
        Returns:
            Chaîne sécurisée
        """
        if not self.protected_chains:
            return chain
            
        # Sécuriser le LLM si présent
        if hasattr(chain, "llm"):
            chain.llm = self.wrap_llm(chain.llm)
            
        # Sauvegarder la méthode originale
        if hasattr(chain, "__call__"):
            original_call = chain.__call__
            
            # Méthode d'appel sécurisée
            def secure_chain_call(inputs, return_only_outputs=False, callbacks=None, **kwargs):
                try:
                    # Nettoyer les entrées
                    if isinstance(inputs, dict):
                        secure_inputs = {}
                        for key, value in inputs.items():
                            if isinstance(value, str):
                                secure_inputs[key] = self.protector.sanitize_input(value)
                            else:
                                secure_inputs[key] = value
                    else:
                        secure_inputs = inputs
                        
                    # Appel sécurisé
                    outputs = original_call(secure_inputs, return_only_outputs=return_only_outputs, 
                                          callbacks=callbacks, **kwargs)
                    
                    # Nettoyer les sorties
                    if isinstance(outputs, dict):
                        for key, value in outputs.items():
                            if isinstance(value, str):
                                outputs[key] = self.protector.sanitize_input(value)
                    
                    return outputs
                except Exception as e:
                    logger.error(f"Erreur dans secure_chain_call: {str(e)}\n{traceback.format_exc()}")
                    if return_only_outputs:
                        return {"error": "Une erreur s'est produite lors du traitement de votre demande."}
                    return "Une erreur s'est produite lors du traitement de votre demande."
            
            # Remplacer la méthode originale
            chain.__call__ = secure_chain_call
        
        return chain
    
    def secure_agent(self, agent):
        """
        Sécurise un agent LangChain.
        
        Args:
            agent: Agent LangChain à sécuriser
            
        Returns:
            Agent sécurisé
        """
        if not self.protected_agents:
            return agent
            
        # Sécuriser le LLM si présent
        if hasattr(agent, "llm_chain") and hasattr(agent.llm_chain, "llm"):
            agent.llm_chain.llm = self.wrap_llm(agent.llm_chain.llm)
        
        # Sauvegarder la méthode originale
        if hasattr(agent, "__call__"):
            original_call = agent.__call__
            
            # Méthode d'appel sécurisée
            def secure_agent_call(inputs, return_only_outputs=False, callbacks=None, **kwargs):
                try:
                    # Nettoyer les entrées
                    if isinstance(inputs, dict):
                        secure_inputs = {}
                        for key, value in inputs.items():
                            if isinstance(value, str):
                                secure_inputs[key] = self.protector.sanitize_input(value)
                            else:
                                secure_inputs[key] = value
                    else:
                        secure_inputs = inputs
                        
                    # Bloquer les outils potentiellement dangereux
                    if hasattr(agent, "tools"):
                        for tool in agent.tools:
                            # Vérifier et désactiver les outils d'exécution de code et d'accès système
                            if any(dangerous in tool.name.lower() for dangerous in 
                                   ["exec", "system", "command", "shell", "eval"]):
                                logger.warning(f"Outil potentiellement dangereux désactivé: {tool.name}")
                                # Remplacer la fonction par une version sécurisée
                                original_func = tool.func
                                tool.func = lambda *args, **kwargs: "Cet outil a été désactivé pour des raisons de sécurité."
                    
                    # Appel sécurisé
                    outputs = original_call(secure_inputs, return_only_outputs=return_only_outputs, 
                                          callbacks=callbacks, **kwargs)
                    
                    # Nettoyer les sorties
                    if isinstance(outputs, dict):
                        for key, value in outputs.items():
                            if isinstance(value, str):
                                outputs[key] = self.protector.sanitize_input(value)
                    
                    return outputs
                except Exception as e:
                    logger.error(f"Erreur dans secure_agent_call: {str(e)}\n{traceback.format_exc()}")
                    if return_only_outputs:
                        return {"error": "Une erreur s'est produite lors du traitement de votre demande."}
                    return "Une erreur s'est produite lors du traitement de votre demande."
            
            # Remplacer la méthode originale
            agent.__call__ = secure_agent_call
        
        return agent
        
class LangGraphProtector:
    """
    Protecteur pour les applications LangGraph. Ajoute une couche de sécurité
    pour les graphes de traitement LangGraph.
    """
    def __init__(self, 
                 model: str = "gpt-4o", 
                 allow_code_execution: bool = False,
                 allow_web_access: bool = True):
        """
        Initialise le protecteur LangGraph.
        
        Args:
            model: Modèle OpenAI à utiliser
            allow_code_execution: Autoriser l'exécution de code
            allow_web_access: Autoriser l'accès au web
        """
        self.protector = OpenAIProtector(model=model)
        self.allow_code_execution = allow_code_execution
        self.allow_web_access = allow_web_access
        self.langchain_protector = LangChainProtector(model=model)
        
    def secure_node(self, node):
        """
        Sécurise un nœud dans un graphe LangGraph.
        
        Args:
            node: Nœud LangGraph à sécuriser
            
        Returns:
            Nœud sécurisé
        """
        if hasattr(node, "llm"):
            node.llm = self.langchain_protector.wrap_llm(node.llm)
            
        # Sauvegarder le handler original
        if hasattr(node, "handler"):
            original_handler = node.handler
            
            # Handler sécurisé
            def secure_handler(state, config=None):
                try:
                    # Vérifier et nettoyer l'état
                    if isinstance(state, dict):
                        for key, value in state.items():
                            if isinstance(value, str):
                                state[key] = self.protector.sanitize_input(value)
                    
                    # Exécuter le handler original
                    result = original_handler(state, config)
                    
                    # Vérifier et nettoyer le résultat
                    if isinstance(result, dict):
                        for key, value in result.items():
                            if isinstance(value, str):
                                result[key] = self.protector.sanitize_input(value)
                    
                    return result
                except Exception as e:
                    logger.error(f"Erreur dans secure_handler: {str(e)}\n{traceback.format_exc()}")
                    return {"error": "Une erreur s'est produite lors du traitement de votre demande."}
            
            # Remplacer le handler original
            node.handler = secure_handler
            
        return node
    
    def secure_graph(self, graph):
        """
        Sécurise un graphe LangGraph entier.
        
        Args:
            graph: Graphe LangGraph à sécuriser
            
        Returns:
            Graphe sécurisé
        """
        # Sécuriser chaque nœud du graphe
        if hasattr(graph, "nodes"):
            for node_id in graph.nodes:
                node = graph.nodes[node_id]
                graph.nodes[node_id] = self.secure_node(node)
        
        # Bloquer les nœuds dangereux
        for node_id in list(graph.nodes.keys()):
            node_name = node_id.lower()
            if any(dangerous in node_name for dangerous in 
                  ["exec", "system", "command", "shell", "eval"]) and not self.allow_code_execution:
                logger.warning(f"Nœud potentiellement dangereux désactivé: {node_id}")
                # Modifier le comportement pour le rendre sûr
                original_node = graph.nodes[node_id]
                def safe_handler(state, config=None):
                    return {"result": "Ce nœud a été désactivé pour des raisons de sécurité."}
                graph.nodes[node_id].handler = safe_handler
                
            if any(web in node_name for web in 
                  ["http", "web", "url", "fetch", "download"]) and not self.allow_web_access:
                logger.warning(f"Nœud d'accès web désactivé: {node_id}")
                # Modifier le comportement pour le rendre sûr
                def safe_web_handler(state, config=None):
                    return {"result": "L'accès web a été désactivé pour des raisons de sécurité."}
                graph.nodes[node_id].handler = safe_web_handler
        
        return graph
    
    def secure_state(self, state):
        """
        Sécurise l'état du graphe.
        
        Args:
            state: État du graphe à sécuriser
            
        Returns:
            État sécurisé
        """
        if not isinstance(state, dict):
            return state
            
        secure_state = {}
        for key, value in state.items():
            if isinstance(value, str):
                secure_state[key] = self.protector.sanitize_input(value)
            elif isinstance(value, dict):
                secure_state[key] = self.secure_state(value)
            elif isinstance(value, list):
                secure_state[key] = [
                    self.secure_state(item) if isinstance(item, dict)
                    else self.protector.sanitize_input(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                secure_state[key] = value
                
        return secure_state 