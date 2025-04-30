"""
Example of using RESK-LLM to secure a Flask API that uses LLMs.
This example demonstrates how to protect your Flask application
against prompt injection, sensitive data leakage, and other security threats.
"""

import os
from flask import Flask, request, jsonify
from resk_llm import create_flask_protector
from openai import OpenAI

# Initialize Flask app
app = Flask(__name__)

# Initialize OpenAI client
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Create and configure the Flask protector
protector = create_flask_protector(
    app=app,
    sanitize_request=True,
    sanitize_response=True,
    patterns_dir="./patterns",  # Directory with security patterns
    logging_level="INFO"
)

# Register endpoints with protection
@app.route("/api/generate-text", methods=["POST"])
@protector.protect
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
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        
        # Return the generated text
        return jsonify({
            "success": True,
            "text": response.choices[0].message.content
        })
        
    except Exception as e:
        # Return error response
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route("/api/generate-image", methods=["POST"])
@protector.protect
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
        
        # Call OpenAI API
        response = client.images.generate(
            model="dall-e-3",
            prompt=prompt,
            n=1,
            size=size
        )
        
        # Return the image URL
        return jsonify({
            "success": True,
            "image_url": response.data[0].url
        })
        
    except Exception as e:
        # Return error response
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route("/api/embeddings", methods=["POST"])
@protector.protect
def generate_embeddings():
    """
    Generate embeddings for text.
    This endpoint is protected by RESK-LLM against potential attacks.
    """
    try:
        # Extract data from the request
        data = request.get_json()
        text = data.get("text", "")
        
        # Call OpenAI API
        response = client.embeddings.create(
            model="text-embedding-ada-002",
            input=text
        )
        
        # Return the embeddings
        return jsonify({
            "success": True,
            "embeddings": response.data[0].embedding
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
    print("🔒 RESK-LLM Flask Integration Example 🔒")
    print("----------------------------------------")
    print("Available endpoints:")
    print("  - POST /api/generate-text")
    print("  - POST /api/generate-image")
    print("  - POST /api/embeddings")
    print("  - GET /resk-llm/patterns (Security Patterns Management)")
    print("\nStarting Flask app...")
    app.run(debug=True, host="0.0.0.0", port=5000) 