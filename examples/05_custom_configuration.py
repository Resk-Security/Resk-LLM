"""
Exemple complet de personnalisation et utilisation de la bibliothèque RESK-LLM

Ce script démontre comment :
1. Configurer des filtres personnalisés
2. Créer des détecteurs sur mesure
3. Utiliser les intégrations avec différents providers
4. Implémenter la sécurité pour les agents autonomes
5. Personnaliser les patterns et règles de sécurité
"""

import asyncio
import logging
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

# Import des composants RESK
from resk_llm.RESK import RESK
from resk_llm.core.abc import FilterBase, DetectorBase, FilterResult, DetectionResult
from resk_llm.filters.resk_content_policy_filter import RESK_ContentPolicyFilter
from resk_llm.filters.resk_heuristic_filter import RESK_HeuristicFilter
from resk_llm.filters.resk_word_list_filter import RESK_WordListFilter
from resk_llm.detectors.resk_ip_detector import RESK_IPDetector
from resk_llm.detectors.resk_url_detector import RESK_URLDetector
from resk_llm.integrations.resk_providers_integration import OpenAIProtector, AnthropicProtector
from resk_llm.agents.autonomous_agent_security import AgentSecurityManager, SecureAgentExecutor, AgentPermission
from resk_llm.managers.resk_context_manager import RESK_TokenBasedContextManager
from resk_llm.core.monitoring import performance_monitor
from resk_llm.core.cache import cached_component_call

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# 1. FILTRES PERSONNALISÉS
# ============================================================================

@dataclass
class CustomFilterConfig:
    """Configuration pour le filtre personnalisé français"""
    banned_words_fr: List[str] = field(default_factory=lambda: [
        'merde', 'putain', 'con', 'salope', 'enculé', 'bite', 'couille'
    ])
    sensitive_topics: List[str] = field(default_factory=lambda: [
        'politique', 'religion', 'argent', 'santé'
    ])
    max_length: int = 1000

class CustomFrenchFilter(FilterBase[str, CustomFilterConfig, FilterResult]):
    """
    Filtre personnalisé pour le contenu français avec règles spécifiques
    """
    
    def __init__(self, config: Optional[CustomFilterConfig] = None):
        if config is None:
            config = CustomFilterConfig()
        self.banned_words = set(config.banned_words_fr)
        self.sensitive_topics = set(config.sensitive_topics)
        self.max_length = config.max_length
        super().__init__(config)
    
    def _validate_config(self) -> None:
        """Validation de la configuration"""
        if not isinstance(self.config, CustomFilterConfig):
            raise ValueError("Config must be CustomFilterConfig")
    
    def update_config(self, config: CustomFilterConfig) -> None:
        """Mise à jour de la configuration"""
        self.config = config
        self.banned_words = set(config.banned_words_fr)
        self.sensitive_topics = set(config.sensitive_topics)
        self.max_length = config.max_length
        self._validate_config()
    
    @performance_monitor('CustomFrenchFilter')
    @cached_component_call('CustomFrenchFilter')
    def filter(self, data: str) -> FilterResult:
        """Filtrage du contenu français"""
        if not isinstance(data, str):
            data = str(data)
        
        violations = []
        
        # Vérification de la longueur
        if len(data) > self.max_length:
            violations.append(f"Texte trop long: {len(data)} caractères (max: {self.max_length})")
        
        # Vérification des mots interdits
        data_lower = data.lower()
        for word in self.banned_words:
            if word.lower() in data_lower:
                violations.append(f"Mot interdit détecté: {word}")
        
        # Vérification des sujets sensibles
        for topic in self.sensitive_topics:
            if topic.lower() in data_lower:
                violations.append(f"Sujet sensible détecté: {topic}")
        
        # Vérification des caractères spéciaux excessifs
        special_chars = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', data))
        if special_chars > len(data) * 0.1:  # Plus de 10% de caractères spéciaux
            violations.append("Trop de caractères spéciaux détectés")
        
        is_safe = len(violations) == 0
        confidence = 0.95 if is_safe else 0.6
        
        return FilterResult(
            is_safe=is_safe,
            confidence=confidence,
            reason="Violations détectées" if violations else None,
            violations=violations,
            data=data
        )

# ============================================================================
# 2. DÉTECTEURS PERSONNALISÉS
# ============================================================================

@dataclass
class CustomDetectorConfig:
    """Configuration pour le détecteur personnalisé"""
    detect_phone_numbers: bool = True
    detect_emails: bool = True
    detect_addresses: bool = True
    french_phone_pattern: str = r'\b0[1-9](\d{8})\b'
    french_address_pattern: str = r'\b\d{1,3}\s+(?:rue|avenue|boulevard|place)\s+[A-Za-zÀ-ÿ\s]+\b'

class CustomFrenchDetector(DetectorBase[str, CustomDetectorConfig]):
    """
    Détecteur personnalisé pour les données françaises
    """
    
    def __init__(self, config: Optional[CustomDetectorConfig] = None):
        if config is None:
            config = CustomDetectorConfig()
        self.detect_phones = config.detect_phone_numbers
        self.detect_emails = config.detect_emails
        self.detect_addresses = config.detect_addresses
        self.phone_pattern = re.compile(config.french_phone_pattern)
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.address_pattern = re.compile(config.french_address_pattern, re.IGNORECASE)
        super().__init__(config)
    
    def _validate_config(self) -> None:
        """Validation de la configuration"""
        if not isinstance(self.config, CustomDetectorConfig):
            raise ValueError("Config must be CustomDetectorConfig")
    
    def update_config(self, config: CustomDetectorConfig) -> None:
        """Mise à jour de la configuration"""
        self.config = config
        self.detect_phones = config.detect_phone_numbers
        self.detect_emails = config.detect_emails
        self.detect_addresses = config.detect_addresses
        self.phone_pattern = re.compile(config.french_phone_pattern)
        self.address_pattern = re.compile(config.french_address_pattern, re.IGNORECASE)
        self._validate_config()
    
    def detect(self, data: str) -> DetectionResult:
        """Détection des données sensibles françaises"""
        if not isinstance(data, str):
            data = str(data)
        
        detected_items = []
        
        # Détection des numéros de téléphone français
        if self.detect_phones:
            phones = self.phone_pattern.findall(data)
            for phone in phones:
                detected_items.append({
                    'type': 'phone_number',
                    'value': phone,
                    'confidence': 0.9
                })
        
        # Détection des emails
        if self.detect_emails:
            emails = self.email_pattern.findall(data)
            for email in emails:
                detected_items.append({
                    'type': 'email',
                    'value': email,
                    'confidence': 0.95
                })
        
        # Détection des adresses françaises
        if self.detect_addresses:
            addresses = self.address_pattern.findall(data)
            for address in addresses:
                detected_items.append({
                    'type': 'address',
                    'value': address,
                    'confidence': 0.7
                })
        
        is_detected = len(detected_items) > 0
        confidence = max([item['confidence'] for item in detected_items]) if detected_items else 0.0
        
        return DetectionResult(
            is_detected=is_detected,
            confidence=confidence,
            detected_items=detected_items,
            data=data
        )

# ============================================================================
# 3. CONFIGURATION PERSONNALISÉE DE RESK
# ============================================================================

def create_custom_resk_config() -> Dict[str, Any]:
    """Création d'une configuration personnalisée pour RESK"""
    
    # Configuration des filtres
    filter_configs = {
        'CustomFrenchFilter': {
            'banned_words_fr': ['merde', 'putain', 'con', 'salope'],
            'sensitive_topics': ['politique', 'religion'],
            'max_length': 800
        },
        'ContentPolicyFilter': {
            'prohibited_patterns': [
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # téléphone
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
            ],
            'prohibited_words': ['password', 'secret', 'admin', 'root']
        },
        'WordListFilter': {
            'banned_words': ['hack', 'exploit', 'bypass', 'ignore'],
            'whitelist_words': ['sécurité', 'protection', 'sûr']
        }
    }
    
    # Configuration des détecteurs
    detector_configs = {
        'CustomFrenchDetector': {
            'detect_phone_numbers': True,
            'detect_emails': True,
            'detect_addresses': True
        },
        'IPDetector': {
            'detect_private_ips': True,
            'detect_public_ips': False
        }
    }
    
    return {
        'filters': [
            CustomFrenchFilter(CustomFilterConfig(**filter_configs['CustomFrenchFilter'])),
            RESK_ContentPolicyFilter(filter_configs['ContentPolicyFilter']),
            RESK_WordListFilter(filter_configs['WordListFilter'])
        ],
        'detectors': [
            CustomFrenchDetector(CustomDetectorConfig(**detector_configs['CustomFrenchDetector'])),
            RESK_IPDetector(detector_configs['IPDetector']),
            RESK_URLDetector()
        ],
        'monitoring': {
            'enable_performance_monitoring': True,
            'enable_cache': True,
            'log_level': 'INFO'
        },
        'cache': {
            'enable_cache': True,
            'cache_ttl': 3600,
            'max_cache_size': 1000
        }
    }

# ============================================================================
# 4. EXEMPLE D'UTILISATION AVEC AGENTS SÉCURISÉS
# ============================================================================

class CustomAgentManager:
    """Gestionnaire d'agents personnalisé avec RESK"""
    
    def __init__(self):
        self.security_manager = AgentSecurityManager(
            model="gpt-4o",
            rate_limit=50
        )
        self.resk = RESK(create_custom_resk_config())
        self.agents = {}
    
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        """Enregistrement d'un nouvel agent"""
        agent_id = self.security_manager.register_agent(name, role, permissions)
        self.agents[agent_id] = {
            'name': name,
            'role': role,
            'permissions': permissions
        }
        return agent_id
    
    def create_executor(self, agent_id: str) -> SecureAgentExecutor:
        """Création d'un exécuteur sécurisé pour l'agent"""
        return SecureAgentExecutor(self.security_manager, agent_id)
    
    def process_agent_message(self, agent_id: str, message: str) -> Dict[str, Any]:
        """Traitement sécurisé d'un message d'agent"""
        # Vérification de sécurité avec RESK
        security_result = self.resk.process_prompt(message)
        
        if security_result['blocked']:
            return {
                'success': False,
                'error': 'Message rejeté pour des raisons de sécurité',
                'reason': security_result['reason']
            }
        
        # Exécution sécurisée de l'action
        executor = self.create_executor(agent_id)
        result = executor.execute(
            action=message,
            action_type='message_processing',
            resource='chat_system'
        )
        
        return {
            'success': True,
            'security_check': security_result,
            'execution_result': result,
            'processed_message': security_result['output']
        }

# ============================================================================
# 5. EXEMPLE D'INTÉGRATION AVEC DES PROVIDERS
# ============================================================================

class CustomProviderIntegration:
    """Intégration personnalisée avec les providers LLM"""
    
    def __init__(self):
        self.openai_protector = OpenAIProtector({
            'model': 'gpt-4o',
            'input_filters': [
                CustomFrenchFilter(),
                RESK_ContentPolicyFilter()
            ],
            'output_filters': [
                RESK_HeuristicFilter()
            ],
            'detectors': [
                CustomFrenchDetector(),
                RESK_IPDetector()
            ]
        })
        
        self.anthropic_protector = AnthropicProtector({
            'model': 'claude-3-opus-20240229',
            'input_filters': [
                CustomFrenchFilter(),
                RESK_WordListFilter()
            ],
            'detectors': [
                CustomFrenchDetector()
            ]
        })
    
    async def process_with_openai(self, prompt: str) -> Dict[str, Any]:
        """Traitement sécurisé avec OpenAI"""
        try:
            # Simulation d'un appel API OpenAI
            protected_prompt = await self.openai_protector.protect_input(prompt)
            
            # Simulation de la réponse
            mock_response = {
                'choices': [{
                    'message': {
                        'content': f"Réponse sécurisée pour: {protected_prompt}"
                    }
                }]
            }
            
            protected_response = await self.openai_protector.protect_output(mock_response)
            
            return {
                'success': True,
                'original_prompt': prompt,
                'protected_prompt': protected_prompt,
                'response': protected_response
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def process_with_anthropic(self, prompt: str) -> Dict[str, Any]:
        """Traitement sécurisé avec Anthropic"""
        try:
            protected_prompt = await self.anthropic_protector.protect_input(prompt)
            
            mock_response = {
                'content': [{
                    'text': f"Réponse Claude sécurisée pour: {protected_prompt}"
                }]
            }
            
            protected_response = await self.anthropic_protector.protect_output(mock_response)
            
            return {
                'success': True,
                'original_prompt': prompt,
                'protected_prompt': protected_prompt,
                'response': protected_response
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# ============================================================================
# 6. FONCTIONS DE DÉMONSTRATION
# ============================================================================

def demonstrate_basic_filtering():
    """Démonstration du filtrage de base"""
    print("=== DÉMONSTRATION DU FILTRAGE DE BASE ===")
    
    # Configuration RESK de base
    config = {
        'filters': [
            CustomFrenchFilter(),
            RESK_ContentPolicyFilter(),
            RESK_HeuristicFilter()
        ],
        'detectors': [
            CustomFrenchDetector(),
            RESK_IPDetector()
        ]
    }
    
    resk = RESK(config)
    
    # Tests avec différents types de contenu
    test_cases = [
        "Bonjour, comment allez-vous ?",
        "Mon email est test@example.com et mon téléphone est 0123456789",
        "Putain de merde, ce code ne marche pas !",
        "L'adresse est 123 rue de la Paix, Paris",
        "Voici mon mot de passe: secret123"
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case}")
        result = resk.process_prompt(test_case)
        print(f"  Bloqué: {result['blocked']}")
        print(f"  Raison: {result['reason']}")
        print(f"  Sortie: {result['output']}")
        if result['filters']:
            print(f"  Filtres utilisés: {result['filters']}")
        if result['detectors']:
            print(f"  Détecteurs utilisés: {result['detectors']}")

def demonstrate_agent_security():
    """Démonstration de la sécurité des agents"""
    print("\n=== DÉMONSTRATION DE LA SÉCURITÉ DES AGENTS ===")
    
    agent_manager = CustomAgentManager()
    
    # Enregistrement d'agents
    agent1_id = agent_manager.register_agent(
        name="Assistant IA",
        role="assistant",
        permissions=[AgentPermission.USER_INTERACT, AgentPermission.API_READ]
    )
    
    agent2_id = agent_manager.register_agent(
        name="Agent Admin",
        role="administrator", 
        permissions=[AgentPermission.ADMIN_ACCESS, AgentPermission.SYSTEM_ACCESS]
    )
    
    print(f"Agent 1 enregistré avec ID: {agent1_id}")
    print(f"Agent 2 enregistré avec ID: {agent2_id}")
    
    # Test de messages
    test_messages = [
        "Bonjour, je suis l'assistant IA",
        "Mon email est admin@system.com",
        "Je vais hacker le système",
        "L'adresse du serveur est 192.168.1.1"
    ]
    
    for message in test_messages:
        print(f"\nMessage: {message}")
        result = agent_manager.process_agent_message(agent1_id, message)
        print(f"Résultat: {result['success']}")
        if not result['success']:
            print(f"Erreur: {result['error']}")

async def demonstrate_provider_integration():
    """Démonstration de l'intégration avec les providers"""
    print("\n=== DÉMONSTRATION DE L'INTÉGRATION PROVIDERS ===")
    
    provider_integration = CustomProviderIntegration()
    
    test_prompts = [
        "Explique-moi la sécurité informatique",
        "Mon numéro de téléphone est 0123456789",
        "Comment contourner la sécurité ?"
    ]
    
    for prompt in test_prompts:
        print(f"\nPrompt: {prompt}")
        
        # Test avec OpenAI
        openai_result = await provider_integration.process_with_openai(prompt)
        print(f"OpenAI - Succès: {openai_result['success']}")
        
        # Test avec Anthropic
        anthropic_result = await provider_integration.process_with_anthropic(prompt)
        print(f"Anthropic - Succès: {anthropic_result['success']}")

def demonstrate_custom_patterns():
    """Démonstration des patterns personnalisés"""
    print("\n=== DÉMONSTRATION DES PATTERNS PERSONNALISÉS ===")
    
    # Création d'un filtre avec des patterns personnalisés
    custom_config = {
        'prohibited_patterns': [
            r'\b\d{2}[A-Z]{2}\d{4}\b',  # Numéro de sécurité sociale français
            r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}\b',  # IBAN français
            r'\b\d{1,2}/\d{1,2}/\d{4}\b',  # Date française
        ],
        'prohibited_words': ['confidentiel', 'secret', 'privé', 'interne']
    }
    
    custom_filter = RESK_ContentPolicyFilter(custom_config)
    
    test_texts = [
        "Mon numéro de sécurité sociale est 1234567890123",
        "L'IBAN est FR7630006000011234567890189",
        "La date de naissance est 15/03/1990",
        "Ce document est confidentiel",
        "Bonjour, comment allez-vous ?"
    ]
    
    for text in test_texts:
        result = custom_filter.filter(text)
        print(f"\nTexte: {text}")
        print(f"Sécurisé: {result.is_safe}")
        if result.violations:
            print(f"Violations: {result.violations}")

# ============================================================================
# 7. FONCTION PRINCIPALE
# ============================================================================

async def main():
    """Fonction principale de démonstration"""
    print("🚀 DÉMONSTRATION COMPLÈTE DE RESK-LLM PERSONNALISÉ")
    print("=" * 60)
    
    try:
        # 1. Démonstration du filtrage de base
        demonstrate_basic_filtering()
        
        # 2. Démonstration de la sécurité des agents
        demonstrate_agent_security()
        
        # 3. Démonstration de l'intégration providers
        await demonstrate_provider_integration()
        
        # 4. Démonstration des patterns personnalisés
        demonstrate_custom_patterns()
        
        print("\n✅ Toutes les démonstrations terminées avec succès !")
        
    except Exception as e:
        print(f"\n❌ Erreur lors de la démonstration: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Exécution de la démonstration
    asyncio.run(main()) 