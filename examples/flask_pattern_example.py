"""
Exemple d'utilisation de l'intégration Flask avec gestion des patterns personnalisés.
Cette application montre comment configurer une API Flask sécurisée avec RESK-LLM
qui permet aux utilisateurs de gérer des patterns personnalisés pour la détection
de contenu malveillant.
"""

import os
import json
from flask import Flask, request, jsonify, render_template_string
from openai import OpenAI
from functools import wraps

from resk_llm import OpenAIProtector, FlaskProtector
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider
from resk_llm.filtering_patterns import (
    check_for_obfuscation,
    sanitize_text_from_obfuscation,
    detect_emojis,
    normalize_homoglyphs
)

# Configuration
API_KEY = os.environ.get("OPENAI_API_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "secret_key_change_me")
PATTERNS_DIR = os.path.join(os.path.dirname(__file__), "custom_patterns")

# Initialiser l'application Flask
app = Flask(__name__)

# Fonction d'authentification pour l'API de patterns
def check_admin_auth():
    api_key = request.headers.get('X-API-Key')
    return api_key == ADMIN_API_KEY

# Initialiser le fournisseur de patterns pour les patterns personnalisés
pattern_provider = FileSystemPatternProvider(patterns_dir=PATTERNS_DIR)

# Créer le filtre de liste de mots avec notre fournisseur de patterns
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

# Initialiser le protecteur Flask avec l'API de patterns activée
flask_protector = FlaskProtector(
    app=app,
    model="gpt-4o",
    rate_limit=60,
    request_sanitization=True,
    response_sanitization=True,
    custom_patterns_dir=PATTERNS_DIR,
    enable_patterns_api=True,
    patterns_api_prefix="/api/patterns",
    patterns_api_auth=check_admin_auth
)

# Initialiser le client OpenAI
client = OpenAI(api_key=API_KEY)

# Initialiser le protecteur OpenAI avec notre filtre
openai_protector = OpenAIProtector(model="gpt-4o", filters=[word_list_filter])

# Page d'accueil simple
@app.route('/')
def home():
    # Utiliser un template inline pour simplifier l'exemple
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>RESK-LLM Flask Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { margin-top: 20px; }
            textarea { width: 100%; height: 100px; }
            button { padding: 10px; margin-top: 10px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
            .result { margin-top: 20px; padding: 10px; border: 1px solid #ddd; }
            .error { color: red; }
            .success { color: green; }
            .tab { margin-right: 20px; display: inline-block; cursor: pointer; padding: 10px; }
            .active-tab { border-bottom: 2px solid #4CAF50; font-weight: bold; }
            .tab-content { display: none; }
            .active-content { display: block; }
        </style>
    </head>
    <body>
        <h1>RESK-LLM Flask Demo</h1>
        
        <div class="tabs">
            <div class="tab active-tab" onclick="showTab('chat')">Chat</div>
            <div class="tab" onclick="showTab('moderate')">Modérer</div>
            <div class="tab" onclick="showTab('patterns')">Patterns</div>
        </div>
        
        <div id="chat" class="tab-content active-content">
            <h2>Chat avec le modèle</h2>
            <div class="container">
                <textarea id="chat-input" placeholder="Entrez votre message..."></textarea>
                <button onclick="sendChat()">Envoyer</button>
                <div id="chat-result" class="result"></div>
            </div>
        </div>
        
        <div id="moderate" class="tab-content">
            <h2>Modérer un texte</h2>
            <div class="container">
                <textarea id="moderation-input" placeholder="Entrez le texte à modérer..."></textarea>
                <button onclick="moderate()">Modérer</button>
                <div id="moderation-result" class="result"></div>
            </div>
        </div>
        
        <div id="patterns" class="tab-content">
            <h2>Gestion des patterns</h2>
            <div class="container">
                <h3>Liste des patterns</h3>
                <button onclick="listPatterns()">Actualiser</button>
                <div id="patterns-list" class="result"></div>
                
                <h3>Créer un pattern</h3>
                <div>
                    <label for="pattern-name">Nom:</label>
                    <input type="text" id="pattern-name">
                </div>
                <div>
                    <label for="pattern-words">Mots interdits (séparés par des virgules):</label>
                    <input type="text" id="pattern-words">
                </div>
                <div>
                    <label for="pattern-regex">Patterns regex (séparés par des virgules):</label>
                    <input type="text" id="pattern-regex">
                </div>
                <button onclick="createPattern()">Créer</button>
                <div id="pattern-result" class="result"></div>
            </div>
        </div>
        
        <script>
            function showTab(tabId) {
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active-content');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active-tab');
                });
                document.getElementById(tabId).classList.add('active-content');
                document.querySelector(`.tab[onclick="showTab('${tabId}')"]`).classList.add('active-tab');
            }
            
            function sendChat() {
                const input = document.getElementById('chat-input').value;
                const resultDiv = document.getElementById('chat-result');
                resultDiv.innerHTML = "Envoi en cours...";
                
                fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        messages: [{ role: 'user', content: input }]
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
                    } else {
                        resultDiv.innerHTML = `<div class="success">Réponse: ${data.response}</div>`;
                    }
                })
                .catch(error => {
                    resultDiv.innerHTML = `<div class="error">Erreur: ${error.message}</div>`;
                });
            }
            
            function moderate() {
                const input = document.getElementById('moderation-input').value;
                const resultDiv = document.getElementById('moderation-result');
                resultDiv.innerHTML = "Modération en cours...";
                
                fetch('/api/moderate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: input })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
                    } else if (data.is_safe) {
                        resultDiv.innerHTML = `<div class="success">Texte sûr</div>`;
                        if (data.cleaned_text !== data.original_text) {
                            resultDiv.innerHTML += `<div>Texte nettoyé: ${data.cleaned_text}</div>`;
                        }
                    } else {
                        resultDiv.innerHTML = `<div class="error">Avertissement: ${data.warning}</div>`;
                    }
                })
                .catch(error => {
                    resultDiv.innerHTML = `<div class="error">Erreur: ${error.message}</div>`;
                });
            }
            
            function listPatterns() {
                const resultDiv = document.getElementById('patterns-list');
                resultDiv.innerHTML = "Chargement...";
                
                fetch('/api/patterns', {
                    method: 'GET',
                    headers: { 'X-API-Key': prompt("Entrez la clé API d'administration:") }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
                    } else {
                        let html = '<ul>';
                        data.patterns.forEach(pattern => {
                            html += `<li>${pattern.name} (${pattern.word_count} mots, ${pattern.pattern_count} patterns) 
                                    <button onclick="deletePattern('${pattern.name}')">Supprimer</button></li>`;
                        });
                        html += '</ul>';
                        resultDiv.innerHTML = html;
                    }
                })
                .catch(error => {
                    resultDiv.innerHTML = `<div class="error">Erreur: ${error.message}</div>`;
                });
            }
            
            function createPattern() {
                const name = document.getElementById('pattern-name').value;
                const words = document.getElementById('pattern-words').value.split(',').map(w => w.trim());
                const patterns = document.getElementById('pattern-regex').value.split(',').map(p => p.trim());
                const resultDiv = document.getElementById('pattern-result');
                
                if (!name) {
                    resultDiv.innerHTML = `<div class="error">Le nom est requis</div>`;
                    return;
                }
                
                resultDiv.innerHTML = "Création en cours...";
                
                fetch('/api/patterns', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-API-Key': prompt("Entrez la clé API d'administration:") 
                    },
                    body: JSON.stringify({
                        name: name,
                        prohibited_words: words,
                        prohibited_patterns: patterns
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
                    } else {
                        resultDiv.innerHTML = `<div class="success">Pattern créé avec succès</div>`;
                        listPatterns();
                    }
                })
                .catch(error => {
                    resultDiv.innerHTML = `<div class="error">Erreur: ${error.message}</div>`;
                });
            }
            
            function deletePattern(name) {
                if (!confirm(`Voulez-vous vraiment supprimer le pattern "${name}" ?`)) {
                    return;
                }
                
                fetch(`/api/patterns/${name}`, {
                    method: 'DELETE',
                    headers: { 'X-API-Key': prompt("Entrez la clé API d'administration:") }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert(`Erreur: ${data.error}`);
                    } else {
                        alert(`Pattern supprimé avec succès`);
                        listPatterns();
                    }
                })
                .catch(error => {
                    alert(`Erreur: ${error.message}`);
                });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(template)

# API de chat avec vérification avancée
@app.route('/api/chat', methods=['POST'])
@flask_protector.protect_route(check_prompt=True, check_pii=True, check_toxicity=True)
def chat_endpoint():
    """
    Endpoint pour discuter avec le modèle, avec vérification complète.
    """
    try:
        # Récupérer les données de la requête
        data = request.get_json()
        
        if not data or "messages" not in data:
            return jsonify({
                "error": "Les messages sont requis",
                "status": "error"
            }), 400
        
        # Utiliser le protecteur pour appeler l'API OpenAI
        response = openai_protector.protect_openai_call(
            client.chat.completions.create,
            messages=data["messages"]
        )
        
        # Vérifier si une erreur s'est produite
        if isinstance(response, dict) and "error" in response:
            return jsonify({
                "error": response["error"],
                "status": "error"
            }), 403
        
        # Retourner la réponse
        return jsonify({
            "response": response.choices[0].message.content,
            "status": "success"
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Une erreur s'est produite: {str(e)}",
            "status": "error"
        }), 500

# Endpoint de modération avec vérification d'emoji et d'homoglyphes
@app.route('/api/moderate', methods=['POST'])
@flask_protector.protect_route(check_prompt=True)
def moderate_endpoint():
    """
    Endpoint pour modérer un texte avec détection d'emoji et d'homoglyphes.
    """
    try:
        # Récupérer les données de la requête
        data = request.get_json()
        
        if not data or "text" not in data:
            return jsonify({
                "error": "Le texte est requis",
                "status": "error"
            }), 400
        
        # Récupérer le texte original
        original_text = data["text"]
        
        # Vérifier les emojis et caractères spéciaux
        obfuscation_results = check_for_obfuscation(original_text)
        
        # Nettoyer le texte des emojis et homoglyphes si nécessaire
        if obfuscation_results:
            cleaned_text = sanitize_text_from_obfuscation(original_text)
        else:
            cleaned_text = original_text
        
        # Normaliser les homoglyphes
        cleaned_text = normalize_homoglyphs(cleaned_text)
        
        # Nettoyer le texte avec le protecteur OpenAI
        passed, warning, final_cleaned_text = word_list_filter.filter(cleaned_text)
        
        if not passed:
            return jsonify({
                "is_safe": False,
                "warning": warning,
                "obfuscation_detected": bool(obfuscation_results),
                "obfuscation_details": obfuscation_results,
                "original_text": original_text,
                "cleaned_text": final_cleaned_text,
                "status": "warning"
            })
        
        # Vérifier si des emojis ont été détectés
        emojis = detect_emojis(original_text)
        if emojis:
            emoji_warning = f"Emojis détectés: {', '.join(emojis[:5])}"
            if len(emojis) > 5:
                emoji_warning += f" et {len(emojis) - 5} autres"
            
            return jsonify({
                "is_safe": True,
                "warning": emoji_warning,
                "obfuscation_detected": True,
                "obfuscation_details": {"emojis": emojis},
                "original_text": original_text,
                "cleaned_text": final_cleaned_text,
                "status": "warning"
            })
        
        # Texte sûr
        return jsonify({
            "is_safe": True,
            "original_text": original_text,
            "cleaned_text": final_cleaned_text,
            "obfuscation_detected": bool(obfuscation_results),
            "obfuscation_details": obfuscation_results,
            "status": "success"
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Une erreur s'est produite: {str(e)}",
            "status": "error"
        }), 500

# Endpoint de santé
@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Endpoint pour vérifier l'état de l'API.
    """
    return jsonify({
        "status": "ok",
        "version": "0.3.0"
    })

# Route avec limitation de débit
@app.route('/api/limited', methods=['POST'])
@flask_protector.rate_limiter(limit=10)
@flask_protector.protect_route(check_prompt=True)
def limited_endpoint():
    """
    Endpoint avec limitation de débit.
    """
    return jsonify({
        "message": "Requête traitée avec succès",
        "status": "success"
    })

if __name__ == '__main__':
    # Créer le répertoire des patterns s'il n'existe pas
    os.makedirs(PATTERNS_DIR, exist_ok=True)
    
    # Démarrer l'application Flask
    app.run(debug=True, host='0.0.0.0', port=5000) 