"""
Exemple d'utilisation de l'intégration Flask pour sécuriser une API LLM.
"""

import os
from flask import Flask, request, jsonify
from openai import OpenAI
from resk_llm import OpenAIProtector, FlaskProtector

# Initialiser l'application Flask
app = Flask(__name__)

# Initialiser le client OpenAI
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# Initialiser le protecteur Flask
flask_protector = FlaskProtector(
    app=app,
    model="gpt-4o",
    rate_limit=60,
    request_sanitization=True,
    response_sanitization=True
)

# Initialiser le protecteur OpenAI
openai_protector = OpenAIProtector(model="gpt-4o")

@app.route('/api/chat', methods=['POST'])
@flask_protector.protect_route(check_prompt=True)
def chat_endpoint():
    """
    Endpoint pour discuter avec le modèle.
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

@app.route('/api/moderate', methods=['POST'])
@flask_protector.protect_route(check_prompt=True)
def moderate_endpoint():
    """
    Endpoint pour modérer un texte.
    """
    try:
        # Récupérer les données de la requête
        data = request.get_json()
        
        if not data or "text" not in data:
            return jsonify({
                "error": "Le texte est requis",
                "status": "error"
            }), 400
        
        # Nettoyer le texte
        text = data["text"]
        cleaned_text = openai_protector.sanitize_input(text)
        
        # Vérifier les motifs malveillants
        warning = openai_protector.ReskWordsLists.check_input(cleaned_text)
        if warning:
            return jsonify({
                "is_safe": False,
                "warning": warning,
                "status": "warning"
            })
        
        # Texte sûr
        return jsonify({
            "is_safe": True,
            "original_text": text,
            "cleaned_text": cleaned_text,
            "status": "success"
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Une erreur s'est produite: {str(e)}",
            "status": "error"
        }), 500

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
    app.run(debug=True, host='0.0.0.0', port=5000) 