# Intégration RESK-LLM avec FastAPI

Ce guide explique comment intégrer RESK-LLM avec FastAPI pour sécuriser vos API contre les injections de prompts et autres vulnérabilités de sécurité liées aux LLMs.

## Prérequis

- Python 3.8+
- FastAPI
- RESK-LLM (installé via `pip install resk-llm`)
- Uvicorn (serveur ASGI)

## Installation

```bash
pip install resk-llm fastapi uvicorn pydantic
```

## Exemple d'utilisation

Le fichier `fastapi_example.py` fournit un exemple complet d'API FastAPI sécurisée avec RESK-LLM. Voici les principales fonctionnalités:

1. **Middleware de sécurité global**: Vérifie toutes les requêtes POST pour détecter les tentatives d'injection
2. **Protection des appels à l'API OpenAI**: Utilise `OpenAIProtector` pour sécuriser les interactions avec le modèle
3. **Endpoints de gestion de la sécurité**: Permet d'ajouter des patterns prohibés à la volée

## Démarrage de l'exemple

```bash
# Définir votre clé API OpenAI
export OPENAI_API_KEY=votre-clé-api

# Démarrer l'application
python fastapi_example.py
```

L'API sera accessible à l'adresse `http://localhost:8000`.

## Structure de l'API d'exemple

### Endpoints principaux

- **GET /** - Page d'accueil de l'API
- **POST /api/chat** - Endpoint de chat sécurisé
- **POST /api/security-test** - Endpoint pour tester la détection d'injections
- **POST /api/add-prohibited-pattern** - Ajoute un pattern interdit à la liste de sécurité

### Documentation interactive

Une documentation Swagger est disponible à l'adresse `http://localhost:8000/docs`.

## Intégration dans votre propre projet

Voici les étapes clés pour intégrer RESK-LLM à votre API FastAPI:

1. **Initialiser le protecteur RESK-LLM**:

```python
from resk_llm.providers_integration import OpenAIProtector

resk_protector = OpenAIProtector(
    model="gpt-4o",
    preserved_prompts=2,
    request_sanitization=True,
    response_sanitization=True
)
```

2. **Ajouter un middleware de sécurité**:

```python
@app.middleware("http")
async def resk_security_middleware(request: Request, call_next):
    # Vérifier les requêtes POST
    if request.method == "POST":
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8')
        
        warning = resk_protector.ReskWordsLists.check_input(body_str)
        if warning:
            return JSONResponse(
                status_code=400,
                content={"error": f"Contenu non autorisé détecté: {warning}"}
            )
    
    response = await call_next(request)
    return response
```

3. **Sécuriser les appels à l'API LLM**:

```python
# Utiliser RESK-LLM pour protéger l'appel à l'API OpenAI
result = resk_protector.protect_openai_call(
    client.chat.completions.create,
    messages=messages,
    max_tokens=max_tokens,
    temperature=temperature
)
```

## Fonctionnalités avancées

### Personnalisation des patterns de sécurité

Vous pouvez ajouter des patterns personnalisés à RESK-LLM pour adapter la sécurité à vos besoins:

```python
# Ajouter un mot interdit
resk_protector.ReskWordsLists.update_prohibited_list("mot_sensible", "add", "word")

# Ajouter un pattern regex interdit
resk_protector.ReskWordsLists.update_prohibited_list(r"pattern\d+sensible", "add", "pattern")
```

### Protection multi-fournisseurs

RESK-LLM supporte plusieurs fournisseurs de LLM:

```python
from resk_llm.providers_integration import AnthropicProtector, CohereProtector

# Pour Anthropic Claude
anthropic_protector = AnthropicProtector(model="claude-3-opus-20240229")

# Pour Cohere
cohere_protector = CohereProtector(model="command-r-plus")
```

## Bonnes pratiques

1. **Validation des entrées**: Utilisez Pydantic pour valider le format des entrées
2. **Logging sécurisé**: Enregistrez les tentatives d'injection pour analyse
3. **Limites de débit**: Implémentez des limites de requêtes pour éviter les abus
4. **Gestion des erreurs**: Assurez-vous de gérer correctement les erreurs sans exposer d'informations sensibles

## Références

- [Documentation FastAPI](https://fastapi.tiangolo.com/)
- [Documentation RESK-LLM](https://github.com/votre-repo/resk-llm)
- [Guide OpenAI sur la sécurité des LLM](https://platform.openai.com/docs/guides/safety-best-practices) 