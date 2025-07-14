"""
Example of using RESK-LLM to secure a Flask API that uses LLMs.
This example demonstrates how to protect your Flask application
against prompt injection, sensitive data leakage, and other security threats.
"""

import os
from flask import Flask, request, jsonify
from openai import OpenAI
from resk_llm.flask_integration import FlaskProtector
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider

# Initialize Flask app
app = Flask(__name__)

# Initialize OpenAI client
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Initialize pattern provider and word list filter
pattern_provider = FileSystemPatternProvider(config={})
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

# Create and configure the Flask protector
protector = FlaskProtector(config={"app": app, "request_sanitization": True, "response_sanitization": True})

# Register endpoints with protection
@app.route("/api/generate-text", methods=["POST"])
def generate_text():
    """
    Generate text using OpenAI GPT models.
    This endpoint is protected by RESK-LLM against prompt injection and other attacks.
    """
    try:
        # Extract data from the request
        data = request.get_json()
        prompt = data.get("prompt", "")
        model = data.get("model", "gpt-3.5-turbo")
        
        # Simulate protected call (replace with actual API call in real use)
        response_text = f"[Simulated] {prompt}"
        
        # Return the generated text
        return jsonify({
            "success": True,
            "text": response_text
        })
        
    except Exception as e:
        # Return error response
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route("/api/generate-image", methods=["POST"])
def generate_image():
    """
    Generate an image using DALL-E.
    This endpoint is protected by RESK-LLM against prompt injection and other attacks.
    """
    try:
        # Extract data from the request
        data = request.get_json()
        prompt = data.get("prompt", "")
        size = data.get("size", "1024x1024")
        
        # Simulate protected call (replace with actual API call in real use)
        image_url = f"https://example.com/simulated_image.png?prompt={prompt}&size={size}"
        
        # Return the image URL
        return jsonify({
            "success": True,
            "image_url": image_url
        })
        
    except Exception as e:
        # Return error response
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route("/api/embeddings", methods=["POST"])
def generate_embeddings():
    """
    Generate embeddings for text.
    This endpoint is protected by RESK-LLM against potential attacks.
    """
    try:
        # Extract data from the request
        data = request.get_json()
        text = data.get("text", "")
        
        # Simulate protected call (replace with actual API call in real use)
        embeddings = [0.1, 0.2, 0.3]  # Dummy values
        
        # Return the embeddings
        return jsonify({
            "success": True,
            "embeddings": embeddings
        })
    
    except Exception as e:
        # Return error response
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# Route for patterns management (added by RESK-LLM)
# Access at /resk-llm/patterns to view and manage security patterns

# Run the application
if __name__ == "__main__":
    print("\ud83d\udd12 RESK-LLM Flask Integration Example \ud83d\udd12")
    print("----------------------------------------")
    print("Available endpoints:")
    print("  - POST /api/generate-text")
    print("  - POST /api/generate-image")
    print("  - POST /api/embeddings")
    print("\nStarting Flask app...")
    app.run(debug=True, host="0.0.0.0", port=5000) 