# Guide de Personnalisation Complète de RESK-LLM

Ce guide vous montre comment personnaliser complètement la bibliothèque RESK-LLM pour vos besoins spécifiques.

## 📋 Table des Matières

1. [Corrections des Erreurs](#corrections-des-erreurs)
2. [Exemples Disponibles](#exemples-disponibles)
3. [Personnalisation des Filtres](#personnalisation-des-filtres)
4. [Création de Détecteurs Personnalisés](#création-de-détecteurs-personnalisés)
5. [Intégration avec les Providers](#intégration-avec-les-providers)
6. [Sécurité des Agents Autonomes](#sécurité-des-agents-autonomes)
7. [Configuration Avancée](#configuration-avancée)

## 🔧 Corrections des Erreurs

### Erreur 1: TypeError dans ContentPolicyFilter

**Problème:** `TypeError: expected string or bytes-like object`

**Solution:** Ajout d'une vérification de type dans `resk_content_policy_filter.py`:

```python
def filter(self, data: str) -> FilterResult:
    # Ensure data is a string
    if not isinstance(data, str):
        data = str(data)
    # ... reste du code
```

### Erreur 2: Warning sur l'import des patterns

**Problème:** `WARNING:root:Could not import default pattern lists from resk_llm.filtering_patterns`

**Solution:** Création du fichier `resk_llm/filtering_patterns/__init__.py` avec les patterns par défaut.

### Erreur 3: SecureAgentExecutor

**Problème:** `TypeError: SecureAgentExecutor.__init__() got an unexpected keyword argument 'agent_manager'`

**Solution:** Correction du constructeur pour accepter `agent_manager` au lieu de `security_manager`.

## 📁 Exemples Disponibles

### 1. `test_fixes_example.py`
Teste les corrections des erreurs principales :
```bash
python examples/test_fixes_example.py
```

### 2. `custom_resk_example.py`
Exemple complet de personnalisation :
```bash
python examples/custom_resk_example.py
```

## 🛡️ Personnalisation des Filtres

### Création d'un Filtre Personnalisé

```python
from resk_llm.core.abc import FilterBase, FilterResult
from dataclasses import dataclass, field

@dataclass
class CustomFilterConfig:
    banned_words: List[str] = field(default_factory=list)
    max_length: int = 1000

class CustomFilter(FilterBase[str, CustomFilterConfig, FilterResult]):
    def __init__(self, config: Optional[CustomFilterConfig] = None):
        if config is None:
            config = CustomFilterConfig()
        self.banned_words = set(config.banned_words)
        self.max_length = config.max_length
        super().__init__(config)
    
    def filter(self, data: str) -> FilterResult:
        if not isinstance(data, str):
            data = str(data)
        
        violations = []
        
        # Votre logique de filtrage personnalisée
        if len(data) > self.max_length:
            violations.append(f"Texte trop long")
        
        for word in self.banned_words:
            if word.lower() in data.lower():
                violations.append(f"Mot interdit: {word}")
        
        return FilterResult(
            is_safe=len(violations) == 0,
            confidence=0.9 if len(violations) == 0 else 0.6,
            violations=violations,
            data=data
        )
```

### Utilisation du Filtre Personnalisé

```python
from resk_llm.RESK import RESK

config = {
    'filters': [
        CustomFilter({
            'banned_words': ['mot_interdit', 'autre_mot'],
            'max_length': 500
        })
    ]
}

resk = RESK(config)
result = resk.process_prompt("Votre texte ici")
```

## 🔍 Création de Détecteurs Personnalisés

### Détecteur pour Données Françaises

```python
from resk_llm.core.abc import DetectorBase, DetectionResult
import re

@dataclass
class FrenchDetectorConfig:
    detect_phones: bool = True
    detect_emails: bool = True
    french_phone_pattern: str = r'\b0[1-9](\d{8})\b'

class FrenchDetector(DetectorBase[str, FrenchDetectorConfig, DetectionResult]):
    def __init__(self, config: Optional[FrenchDetectorConfig] = None):
        if config is None:
            config = FrenchDetectorConfig()
        self.detect_phones = config.detect_phones
        self.phone_pattern = re.compile(config.french_phone_pattern)
        super().__init__(config)
    
    def detect(self, data: str) -> DetectionResult:
        if not isinstance(data, str):
            data = str(data)
        
        detected_items = []
        
        if self.detect_phones:
            phones = self.phone_pattern.findall(data)
            for phone in phones:
                detected_items.append({
                    'type': 'phone_number',
                    'value': phone,
                    'confidence': 0.9
                })
        
        return DetectionResult(
            is_detected=len(detected_items) > 0,
            confidence=max([item['confidence'] for item in detected_items]) if detected_items else 0.0,
            detected_items=detected_items,
            data=data
        )
```

## 🔌 Intégration avec les Providers

### Configuration OpenAI

```python
from resk_llm.integrations.resk_providers_integration import OpenAIProtector

openai_protector = OpenAIProtector({
    'model': 'gpt-4o',
    'input_filters': [
        CustomFilter(),
        RESK_ContentPolicyFilter()
    ],
    'output_filters': [
        RESK_HeuristicFilter()
    ],
    'detectors': [
        FrenchDetector(),
        RESK_IPDetector()
    ]
})

# Utilisation
protected_prompt = await openai_protector.protect_input("Votre prompt")
protected_response = await openai_protector.protect_output(response)
```

### Configuration Anthropic

```python
from resk_llm.integrations.resk_providers_integration import AnthropicProtector

anthropic_protector = AnthropicProtector({
    'model': 'claude-3-opus-20240229',
    'input_filters': [
        CustomFilter(),
        RESK_WordListFilter()
    ],
    'detectors': [
        FrenchDetector()
    ]
})
```

## 🤖 Sécurité des Agents Autonomes

### Gestionnaire d'Agents Personnalisé

```python
from resk_llm.agents.autonomous_agent_security import AgentSecurityManager, SecureAgentExecutor

class CustomAgentManager:
    def __init__(self):
        self.security_manager = AgentSecurityManager(
            model="gpt-4o",
            rate_limit=50
        )
        self.resk = RESK(config)
    
    def register_agent(self, name: str, role: str, permissions: List[str]) -> str:
        return self.security_manager.register_agent(name, role, permissions)
    
    def create_executor(self, agent_id: str) -> SecureAgentExecutor:
        return SecureAgentExecutor(self.security_manager, agent_id)
    
    def process_message(self, agent_id: str, message: str) -> Dict[str, Any]:
        # Vérification de sécurité
        security_result = self.resk.process_prompt(message)
        
        if not security_result.is_safe:
            return {
                'success': False,
                'error': 'Message rejeté',
                'violations': security_result.violations
            }
        
        # Exécution sécurisée
        executor = self.create_executor(agent_id)
        result = executor.execute(
            action=message,
            action_type='message_processing',
            resource='chat_system'
        )
        
        return {
            'success': True,
            'security_check': security_result,
            'execution_result': result
        }
```

### Utilisation

```python
agent_manager = CustomAgentManager()

# Enregistrement d'un agent
agent_id = agent_manager.register_agent(
    name="Assistant IA",
    role="assistant",
    permissions=["user:interact", "api:read"]
)

# Traitement d'un message
result = agent_manager.process_message(agent_id, "Votre message")
```

## ⚙️ Configuration Avancée

### Configuration Complète

```python
def create_advanced_config() -> Dict[str, Any]:
    return {
        'filters': [
            CustomFilter({
                'banned_words': ['mot1', 'mot2'],
                'max_length': 1000
            }),
            RESK_ContentPolicyFilter({
                'prohibited_patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
                ],
                'prohibited_words': ['password', 'secret']
            }),
            RESK_HeuristicFilter(),
            RESK_WordListFilter({
                'banned_words': ['hack', 'exploit'],
                'whitelist_words': ['sécurité', 'protection']
            })
        ],
        'detectors': [
            FrenchDetector({
                'detect_phones': True,
                'detect_emails': True
            }),
            RESK_IPDetector({
                'detect_private_ips': True,
                'detect_public_ips': False
            }),
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

# Utilisation
resk = RESK(create_advanced_config())
```

### Patterns Personnalisés

```python
# Création de patterns personnalisés
CUSTOM_PATTERNS = {
    'french_ssn': r'\b\d{2}[A-Z]{2}\d{4}\b',  # Numéro de sécurité sociale français
    'french_iban': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}\b',  # IBAN français
    'french_date': r'\b\d{1,2}/\d{1,2}/\d{4}\b',  # Date française
    'french_address': r'\b\d{1,3}\s+(?:rue|avenue|boulevard)\s+[A-Za-zÀ-ÿ\s]+\b'
}

# Utilisation dans un filtre
filter_config = {
    'prohibited_patterns': list(CUSTOM_PATTERNS.values()),
    'prohibited_words': ['confidentiel', 'secret', 'privé']
}
```

## 🚀 Bonnes Pratiques

### 1. Validation des Données
Toujours valider le type de données avant traitement :
```python
def filter(self, data: str) -> FilterResult:
    if not isinstance(data, str):
        data = str(data)
    # ... reste du code
```

### 2. Gestion des Erreurs
Utiliser des try-catch appropriés :
```python
try:
    result = resk.process_prompt(prompt)
except Exception as e:
    logger.error(f"Erreur lors du traitement: {e}")
    # Gestion de l'erreur
```

### 3. Configuration Modulaire
Séparer la configuration en modules réutilisables :
```python
def get_filter_config() -> Dict[str, Any]:
    return {...}

def get_detector_config() -> Dict[str, Any]:
    return {...}

def get_complete_config() -> Dict[str, Any]:
    return {
        'filters': get_filter_config(),
        'detectors': get_detector_config(),
        # ...
    }
```

### 4. Monitoring et Logging
Activer le monitoring pour le débogage :
```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
```

## 🔍 Tests et Validation

### Test de Base
```bash
python examples/test_fixes_example.py
```

### Test Complet
```bash
python examples/custom_resk_example.py
```

### Test Personnalisé
```python
def test_custom_configuration():
    config = create_advanced_config()
    resk = RESK(config)
    
    test_cases = [
        "Texte normal",
        "Mon email est test@example.com",
        "Mot interdit dans le texte",
        "123 rue de la Paix, Paris"
    ]
    
    for test_case in test_cases:
        result = resk.process_prompt(test_case)
        print(f"Test: {test_case}")
        print(f"  Sécurisé: {result.is_safe}")
        if result.violations:
            print(f"  Violations: {result.violations}")
```

## 📚 Ressources Supplémentaires

- [Documentation RESK-LLM](../README.md)
- [Exemples de base](../examples/)
- [Tests unitaires](../tests/)
- [Guide de contribution](../CONTRIBUTING.md)

## 🆘 Support

Si vous rencontrez des problèmes :
1. Vérifiez les logs pour les erreurs détaillées
2. Testez avec l'exemple de base
3. Consultez la documentation
4. Ouvrez une issue sur GitHub

---

**Note:** Ce guide couvre les fonctionnalités principales de personnalisation. Pour des cas d'usage spécifiques, consultez la documentation complète de RESK-LLM. 