import re
import html
import logging
import traceback
import json
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple

from resk_llm.providers_integration import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager

# Configuration du logger
logger = logging.getLogger(__name__)

class AgentIdentityManager:
    """
    Gestionnaire d'identité pour les agents autonomes.
    Permet de vérifier l'authenticité des agents et de suivre leurs actions.
    """
    def __init__(self):
        """
        Initialise le gestionnaire d'identité.
        """
        self.registered_agents = {}  # uuid: {name, role, permissions, created_at}
        self.agent_actions = {}  # uuid: [{action, timestamp, status}]
        self.revoked_agents = set()  # ensemble des UUIDs révoqués
        
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        """
        Enregistre un nouvel agent et génère un identifiant.
        
        Args:
            name: Nom de l'agent
            role: Rôle de l'agent
            permissions: Liste des permissions accordées à l'agent
            
        Returns:
            UUID de l'agent
        """
        agent_id = str(uuid.uuid4())
        self.registered_agents[agent_id] = {
            "name": name,
            "role": role,
            "permissions": permissions,
            "created_at": time.time(),
            "last_action": time.time()
        }
        self.agent_actions[agent_id] = []
        return agent_id
        
    def verify_agent(self, agent_id: str) -> bool:
        """
        Vérifie si un agent est enregistré et non révoqué.
        
        Args:
            agent_id: UUID de l'agent
            
        Returns:
            True si l'agent est valide, False sinon
        """
        return agent_id in self.registered_agents and agent_id not in self.revoked_agents
    
    def check_permission(self, agent_id: str, permission: str) -> bool:
        """
        Vérifie si un agent possède une permission spécifique.
        
        Args:
            agent_id: UUID de l'agent
            permission: Permission à vérifier
            
        Returns:
            True si l'agent possède la permission, False sinon
        """
        if not self.verify_agent(agent_id):
            return False
        
        return permission in self.registered_agents[agent_id]["permissions"]
    
    def log_action(self, agent_id: str, action: str, status: str = "success") -> bool:
        """
        Enregistre une action effectuée par un agent.
        
        Args:
            agent_id: UUID de l'agent
            action: Description de l'action
            status: Statut de l'action (success, failure, blocked)
            
        Returns:
            True si l'action a été enregistrée, False sinon
        """
        if not self.verify_agent(agent_id):
            return False
        
        self.agent_actions[agent_id].append({
            "action": action,
            "timestamp": time.time(),
            "status": status
        })
        
        self.registered_agents[agent_id]["last_action"] = time.time()
        return True
    
    def revoke_agent(self, agent_id: str) -> bool:
        """
        Révoque un agent.
        
        Args:
            agent_id: UUID de l'agent
            
        Returns:
            True si l'agent a été révoqué, False sinon
        """
        if not self.verify_agent(agent_id):
            return False
        
        self.revoked_agents.add(agent_id)
        return True
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtient les informations sur un agent.
        
        Args:
            agent_id: UUID de l'agent
            
        Returns:
            Informations sur l'agent ou None si l'agent n'est pas enregistré
        """
        if not self.verify_agent(agent_id):
            return None
        
        info = self.registered_agents[agent_id].copy()
        info["actions"] = len(self.agent_actions[agent_id])
        info["is_active"] = agent_id not in self.revoked_agents
        
        return info
    
    def get_agent_actions(self, agent_id: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Obtient les actions d'un agent.
        
        Args:
            agent_id: UUID de l'agent
            limit: Nombre maximum d'actions à retourner
            
        Returns:
            Liste des actions ou None si l'agent n'est pas enregistré
        """
        if not self.verify_agent(agent_id):
            return None
        
        actions = self.agent_actions[agent_id]
        return actions[-limit:] if limit > 0 else actions


class AgentSecurityMonitor:
    """
    Moniteur de sécurité pour les agents autonomes.
    Surveille les activités des agents et bloque les comportements suspects.
    """
    def __init__(self, 
                 identity_manager: AgentIdentityManager,
                 model: str = "gpt-4o",
                 rate_limit: int = 100,
                 max_consecutive_failures: int = 5,
                 max_inactivity_time: int = 3600):
        """
        Initialise le moniteur de sécurité pour agents.
        
        Args:
            identity_manager: Gestionnaire d'identité des agents
            model: Modèle LLM à utiliser
            rate_limit: Nombre maximum d'actions par minute
            max_consecutive_failures: Nombre maximum d'échecs consécutifs avant révocation
            max_inactivity_time: Temps maximum d'inactivité en secondes
        """
        self.identity_manager = identity_manager
        self.protector = OpenAIProtector(model=model)
        self.rate_limit = rate_limit
        self.max_consecutive_failures = max_consecutive_failures
        self.max_inactivity_time = max_inactivity_time
        
        self.action_counts: Dict[str, Dict[int, int]] = {}  # uuid: {minute_timestamp: count}
        self.consecutive_failures: Dict[str, int] = {}  # uuid: count
        
    def monitor_action(self, agent_id: str, action: str, 
                      action_type: str, resource: Optional[str] = None) -> Tuple[bool, str]:
        """
        Surveille une action d'agent et détermine si elle doit être autorisée.
        
        Args:
            agent_id: UUID de l'agent
            action: Description de l'action
            action_type: Type d'action (api_call, file_access, network, computation)
            resource: Ressource accédée (optionnel)
            
        Returns:
            Tuple (allowed, reason)
        """
        # Vérifier si l'agent est valide
        if not self.identity_manager.verify_agent(agent_id):
            return False, "Agent non enregistré ou révoqué"
        
        # Vérifier l'inactivité
        agent_info = self.identity_manager.get_agent_info(agent_id)
        if agent_info is not None and time.time() - agent_info["last_action"] > self.max_inactivity_time:
            self.identity_manager.revoke_agent(agent_id)
            return False, "Agent inactif depuis trop longtemps"
        
        # Vérifier les permissions
        if not self.identity_manager.check_permission(agent_id, action_type):
            self.identity_manager.log_action(agent_id, action, "blocked")
            return False, f"Permission manquante: {action_type}"
        
        # Vérifier la limitation de débit
        current_minute = int(time.time() / 60)
        if agent_id not in self.action_counts:
            self.action_counts[agent_id] = {}
        
        if current_minute not in self.action_counts[agent_id]:
            # Nettoyer les anciennes entrées
            self.action_counts[agent_id] = {current_minute: 0}
        
        self.action_counts[agent_id][current_minute] += 1
        if self.action_counts[agent_id][current_minute] > self.rate_limit:
            self.identity_manager.log_action(agent_id, action, "blocked")
            return False, "Limite de débit dépassée"
        
        # Vérifier les échecs consécutifs
        if agent_id in self.consecutive_failures and self.consecutive_failures[agent_id] >= self.max_consecutive_failures:
            self.identity_manager.revoke_agent(agent_id)
            return False, "Trop d'échecs consécutifs"
        
        # Vérifier le contenu de l'action
        if action_type == "api_call" and resource and agent_info is not None:
            # Vérifier si l'API est autorisée
            if not self._is_api_allowed(resource, agent_info["permissions"]):
                self.identity_manager.log_action(agent_id, action, "blocked")
                return False, f"API non autorisée: {resource}"
        
        # Sanitiser l'action pour détecter les injections
        cleaned_action = self.protector.sanitize_input(action)
        warning = self.protector.ReskWordsLists.check_input(cleaned_action)
        if warning:
            self.identity_manager.log_action(agent_id, action, "blocked")
            self._increment_failures(agent_id)
            return False, f"Action non autorisée: {warning}"
        
        # Action autorisée
        self.identity_manager.log_action(agent_id, action, "success")
        if agent_id in self.consecutive_failures:
            self.consecutive_failures[agent_id] = 0
        
        return True, "Action autorisée"
    
    def report_failure(self, agent_id: str, action: str, reason: str) -> None:
        """
        Signale un échec d'action.
        
        Args:
            agent_id: UUID de l'agent
            action: Description de l'action
            reason: Raison de l'échec
        """
        self.identity_manager.log_action(agent_id, action, "failure")
        self._increment_failures(agent_id)
    
    def _increment_failures(self, agent_id: str) -> None:
        """
        Incrémente le compteur d'échecs consécutifs.
        
        Args:
            agent_id: UUID de l'agent
        """
        if agent_id not in self.consecutive_failures:
            self.consecutive_failures[agent_id] = 0
        
        self.consecutive_failures[agent_id] += 1
        
        if self.consecutive_failures[agent_id] >= self.max_consecutive_failures:
            self.identity_manager.revoke_agent(agent_id)
    
    def _is_api_allowed(self, api_url: str, permissions: List[str]) -> bool:
        """
        Vérifie si une API est autorisée.
        
        Args:
            api_url: URL de l'API
            permissions: Permissions de l'agent
            
        Returns:
            True si l'API est autorisée, False sinon
        """
        # Vérifiez si l'agent a la permission spécifique pour cette API
        if f"api:{api_url}" in permissions:
            return True
        
        # Vérifiez les permissions génériques
        domain = self._extract_domain(api_url)
        if f"domain:{domain}" in permissions:
            return True
        
        # Vérifiez les permissions par préfixe
        for perm in permissions:
            if perm.startswith("api_prefix:"):
                prefix = perm.split(":", 1)[1]
                if api_url.startswith(prefix):
                    return True
        
        return False
    
    def _extract_domain(self, url: str) -> str:
        """
        Extrait le domaine d'une URL.
        
        Args:
            url: URL à analyser
            
        Returns:
            Domaine extrait
        """
        match = re.search(r"https?://([^/]+)", url)
        if match:
            return match.group(1)
        return url


class AgentSandbox:
    """
    Environnement sécurisé pour l'exécution d'agents autonomes.
    Restreint les actions des agents et surveille leur comportement.
    """
    def __init__(self, 
                 agent_id: str,
                 security_monitor: AgentSecurityMonitor,
                 allowed_resources: Optional[Set[str]] = None,
                 context_tracking: bool = True):
        """
        Initialise un sandbox pour un agent.
        
        Args:
            agent_id: UUID de l'agent
            security_monitor: Moniteur de sécurité
            allowed_resources: Ensemble des ressources autorisées
            context_tracking: Activer le suivi du contexte
        """
        self.agent_id = agent_id
        self.security_monitor = security_monitor
        self.allowed_resources = allowed_resources or set()
        self.context_tracking = context_tracking
        self.context: List[Dict[str, Any]] = []
        
    def execute_action(self, action: str, action_type: str, 
                      resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Exécute une action dans le sandbox.
        
        Args:
            action: Description de l'action
            action_type: Type d'action
            resource: Ressource accédée (optionnel)
            
        Returns:
            Résultat de l'action
        """
        # Vérifier si l'action est autorisée
        allowed, reason = self.security_monitor.monitor_action(
            self.agent_id, action, action_type, resource
        )
        
        if not allowed:
            return {
                "status": "error",
                "error": reason,
                "result": None
            }
        
        # Vérifier si la ressource est autorisée
        if resource and self.allowed_resources and resource not in self.allowed_resources:
            self.security_monitor.report_failure(
                self.agent_id, action, f"Ressource non autorisée: {resource}"
            )
            return {
                "status": "error",
                "error": f"Ressource non autorisée: {resource}",
                "result": None
            }
        
        # Exécuter l'action (simulation)
        # Dans une implémentation réelle, vous exécuteriez l'action ici
        result = {
            "status": "success",
            "message": f"Action '{action}' exécutée avec succès",
            "result": {
                "action_type": action_type,
                "timestamp": time.time()
            }
        }
        
        # Mettre à jour le contexte
        if self.context_tracking:
            self.context.append({
                "action": action,
                "timestamp": time.time(),
                "result": "success"
            })
            
            # Limiter la taille du contexte
            if len(self.context) > 100:
                self.context = self.context[-100:]
        
        return result
    
    def get_context(self) -> List[Dict[str, Any]]:
        """
        Obtient le contexte des actions de l'agent.
        
        Returns:
            Liste des actions contextuelles
        """
        return self.context if self.context_tracking else []
        
    def close(self) -> None:
        """
        Ferme le sandbox.
        """
        self.context = []


class SecureAvatar:
    """
    Avatar sécurisé pour l'interaction avec les utilisateurs.
    Filtre les entrées et les sorties pour éviter les fuites d'information.
    """
    def __init__(self, 
                 name: str,
                 role: str,
                 model: str = "gpt-4o",
                 personality_traits: Optional[List[str]] = None,
                 banned_topics: Optional[List[str]] = None):
        """
        Initialise l'avatar sécurisé.
        
        Args:
            name: Nom de l'avatar
            role: Rôle de l'avatar
            model: Modèle OpenAI à utiliser
            personality_traits: Traits de personnalité de l'avatar
            banned_topics: Sujets interdits
        """
        self.name = name
        self.role = role
        self.protector = OpenAIProtector(model=model)
        self.personality_traits = personality_traits or []
        self.banned_topics = banned_topics or []
        
        # Ajouter les sujets interdits à la liste des mots prohibés
        for topic in self.banned_topics:
            self.protector.update_prohibited_list(topic, "add", "word")
    
    def process_message(self, message: str) -> Dict[str, Any]:
        """
        Traite un message entrant et génère une réponse sécurisée.
        
        Args:
            message: Message entrant
            
        Returns:
            Réponse formatée
        """
        # Nettoyer le message
        cleaned_message = self.protector.sanitize_input(message)
        
        # Vérifier les motifs malveillants
        warning = self.protector.ReskWordsLists.check_input(cleaned_message)
        if warning:
            return {
                "status": "error",
                "error": warning,
                "response": f"Je ne peux pas répondre à cette demande car elle contient du contenu inapproprié."
            }
        
        # Vérifier les sujets interdits
        for topic in self.banned_topics:
            if re.search(r'\b' + re.escape(topic) + r'\b', cleaned_message, re.IGNORECASE):
                return {
                    "status": "error",
                    "error": f"Sujet interdit: {topic}",
                    "response": f"Je ne peux pas discuter de ce sujet car il fait partie des sujets interdits."
                }
        
        # Dans une implémentation réelle, vous généreriez une réponse LLM ici
        # Ici, nous simulons juste une réponse
        response = f"En tant que {self.name}, je vous réponds dans mon rôle de {self.role}."
        
        # Nettoyer la réponse
        cleaned_response = self.protector.sanitize_input(response)
        
        return {
            "status": "success",
            "response": cleaned_response,
            "name": self.name,
            "role": self.role
        }
        
    def update_banned_topics(self, topics: List[str], action: str = "add") -> None:
        """
        Met à jour la liste des sujets interdits.
        
        Args:
            topics: Liste des sujets
            action: Action à effectuer (add, remove)
        """
        for topic in topics:
            if action == "add":
                self.banned_topics.append(topic)
                self.protector.update_prohibited_list(topic, "add", "word")
            elif action == "remove" and topic in self.banned_topics:
                self.banned_topics.remove(topic)
                self.protector.update_prohibited_list(topic, "remove", "word")


class AgentSecurityManager:
    """
    Gestionnaire de sécurité global pour agents autonomes.
    """
    
    def __init__(self, model: str = "gpt-4o", rate_limit: int = 100):
        """
        Initialise le gestionnaire de sécurité.
        
        Args:
            model: Modèle LLM à utiliser
            rate_limit: Limite d'actions par minute
        """
        self.identity_manager = AgentIdentityManager()
        self.security_monitor = AgentSecurityMonitor(
            identity_manager=self.identity_manager,
            model=model,
            rate_limit=rate_limit
        )
        self.sandboxes: Dict[str, AgentSandbox] = {}
        
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        """
        Enregistre un nouvel agent.
        
        Args:
            name: Nom de l'agent
            role: Rôle de l'agent
            permissions: Liste des permissions accordées
            
        Returns:
            ID de l'agent créé
        """
        return self.identity_manager.register_agent(name, role, permissions)
        
    def create_sandbox(self, agent_id: str, allowed_resources: Optional[Set[str]] = None) -> Optional[AgentSandbox]:
        """
        Crée un environnement sandbox pour un agent.
        
        Args:
            agent_id: ID de l'agent
            allowed_resources: Ressources autorisées pour l'agent
            
        Returns:
            Instance de sandbox ou None en cas d'échec
        """
        if not self.identity_manager.verify_agent(agent_id):
            return None
            
        sandbox = AgentSandbox(
            agent_id=agent_id,
            security_monitor=self.security_monitor,
            allowed_resources=allowed_resources
        )
        
        self.sandboxes[agent_id] = sandbox
        return sandbox
        
    def execute_action(self, agent_id: str, action: str, action_type: str, 
                     resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Exécute une action pour un agent spécifique.
        
        Args:
            agent_id: ID de l'agent
            action: Action à exécuter
            action_type: Type de l'action
            resource: Ressource ciblée (optionnel)
            
        Returns:
            Résultat de l'action
        """
        if agent_id not in self.sandboxes:
            self.create_sandbox(agent_id)
            
        if agent_id in self.sandboxes:
            return self.sandboxes[agent_id].execute_action(action, action_type, resource)
        else:
            return {
                "status": "error",
                "message": "Agent non autorisé"
            }
            
    def revoke_agent(self, agent_id: str) -> bool:
        """
        Révoque un agent.
        
        Args:
            agent_id: ID de l'agent à révoquer
            
        Returns:
            True si la révocation a réussi, False sinon
        """
        if agent_id in self.sandboxes:
            self.sandboxes[agent_id].close()
            del self.sandboxes[agent_id]
            
        return self.identity_manager.revoke_agent(agent_id)
        
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtient les informations sur un agent.
        
        Args:
            agent_id: ID de l'agent
            
        Returns:
            Informations sur l'agent ou None si non trouvé
        """
        return self.identity_manager.get_agent_info(agent_id)
        
    def get_agent_actions(self, agent_id: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Obtient l'historique des actions d'un agent.
        
        Args:
            agent_id: ID de l'agent
            limit: Nombre maximum d'actions à retourner
            
        Returns:
            Liste des actions ou None si agent non trouvé
        """
        return self.identity_manager.get_agent_actions(agent_id, limit)


class AgentPermission:
    """
    Types de permissions pour les agents.
    """
    # Permissions système
    SYSTEM_ACCESS = "system:access"
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    NETWORK_ACCESS = "network:access"
    
    # Permissions d'API
    API_READ = "api:read"
    API_WRITE = "api:write"
    
    # Permissions de base de données
    DB_READ = "db:read"
    DB_WRITE = "db:write"
    
    # Permissions utilisateur
    USER_INTERACT = "user:interact"
    USER_DATA_ACCESS = "user:data:access"
    
    # Permissions avancées
    ADMIN_ACCESS = "admin:access"
    SECURITY_OVERRIDE = "security:override"


class AgentIdentity:
    """
    Identité d'un agent.
    """
    def __init__(self, id: str, name: str, role: str, permissions: List[str]):
        """
        Initialise une identité d'agent.
        
        Args:
            id: ID unique de l'agent
            name: Nom de l'agent
            role: Rôle de l'agent
            permissions: Liste des permissions accordées
        """
        self.id = id
        self.name = name
        self.role = role
        self.permissions = permissions
        
    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit l'identité en dictionnaire.
        
        Returns:
            Dictionnaire représentant l'identité
        """
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "permissions": self.permissions
        }


class SecureAgentExecutor:
    """
    Exécuteur sécurisé pour agents autonomes.
    """
    def __init__(self, security_manager: AgentSecurityManager, agent_id: str):
        """
        Initialise l'exécuteur sécurisé.
        
        Args:
            security_manager: Gestionnaire de sécurité
            agent_id: ID de l'agent
        """
        self.security_manager = security_manager
        self.agent_id = agent_id
        
    def execute(self, action: str, action_type: str, resource: Optional[str] = None) -> Dict[str, Any]:
        """
        Exécute une action de manière sécurisée.
        
        Args:
            action: Action à exécuter
            action_type: Type de l'action
            resource: Ressource ciblée (optionnel)
            
        Returns:
            Résultat de l'action
        """
        return self.security_manager.execute_action(self.agent_id, action, action_type, resource)


# Permissions par défaut pour les agents
AGENT_DEFAULT_PERMISSIONS = [
    AgentPermission.SYSTEM_ACCESS,
    AgentPermission.FILE_READ,
    AgentPermission.API_READ,
    AgentPermission.USER_INTERACT
] 