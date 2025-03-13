# RESK-LLM: Advanced Security for Large Language Models

## Project Overview

RESK-LLM is an open-source security toolkit for Large Language Models (LLMs), designed to protect against prompt injections, data leakage, and malicious use. It provides comprehensive security features for multiple LLM providers including OpenAI, Anthropic, Cohere, DeepSeek, and OpenRouter.

## Key Features

- 🛡️ **Prompt Injection Protection**: Defends against attempts to manipulate model behavior through carefully crafted prompts
- 🔒 **Input Sanitization**: Scrubs user inputs to prevent malicious patterns and special tokens
- 📊 **Content Moderation**: Identifies and filters toxic, harmful, or inappropriate content
- 🧩 **Multiple LLM Providers**: Supports OpenAI, Anthropic, Cohere, DeepSeek, and OpenRouter
- 🧠 **Custom Pattern Support**: Allows users to define their own prohibited words and patterns
- 🔍 **PII Detection**: Identifies and helps protect personally identifiable information
- 🚨 **Doxxing Prevention**: Detects and blocks attempts to reveal private personal information
- 🔄 **Context Management**: Efficiently manages conversation context for LLMs
- 🌐 **Web Framework Integration**: First-class support for Flask and FastAPI
- 🤖 **Agent Security**: Special protections for autonomous AI agents

## New Features

### 1. Flask Integration

The new Flask integration allows you to easily protect your Flask-based LLM applications:

```python
from flask import Flask, request, jsonify
from resk_llm.flask_integration import FlaskProtector

# Create a Flask app
app = Flask(__name__)

# Initialize RESK protector for Flask
protector = FlaskProtector(
    app=app,
    model="gpt-4o",
    rate_limit=60,  # 60 requests per minute
    request_sanitization=True,
    response_sanitization=True,
    enable_patterns_api=True,  # Enable the patterns management API
    patterns_api_prefix="/api/patterns"
)

# Create a protected chat endpoint
@app.route("/api/chat", methods=["POST"])
@protector.protect_route(check_prompt=True, check_pii=True, check_toxicity=True)
def chat_endpoint():
    # Get sanitized JSON data from the request
    data = request.get_json()
    
    # Use OpenAI client
    client = OpenAI(api_key="your-api-key")
    
    # Use protector to make the API call
    response = protector.protector.protect_openai_call(
        client.chat.completions.create,
        model="gpt-4o",
        messages=data.get("messages", [])
    )
    
    if "error" in response:
        return jsonify({"error": response["error"]}), 400
    
    return jsonify({"response": response.choices[0].message.content})

if __name__ == "__main__":
    app.run(debug=True)
```

This integration provides:
- Automatic request sanitization
- Response sanitization
- Rate limiting
- Security headers
- API for managing custom patterns

### 2. FastAPI Integration

For modern asynchronous applications, the new FastAPI integration delivers advanced protection:

```python
from fastapi import FastAPI, Depends, Header, HTTPException
from resk_llm.fastapi_integration import FastAPIProtector, ChatRequest

# Create a FastAPI app
app = FastAPI(title="RESK-LLM Protected API")

# Initialize RESK protector for FastAPI
protector = FastAPIProtector(
    app=app,
    default_model="gpt-4o",
    rate_limit=100,
    enable_patterns_api=True,
    patterns_api_prefix="/api/patterns",
    agent_security_enabled=True,  # Enable agent security
    api_key_header="X-API-Key",
    agent_id_header="X-Agent-ID",
    cors_origins=["*"],  # Allow all origins for CORS in this example
    request_sanitization=True,
    response_sanitization=True
)

# Create a protected chat endpoint
@app.post("/api/chat")
@protector.secure_endpoint(
    check_prompt=True,
    check_pii=True,
    check_toxicity=True,
    agent_permission="chat"
)
async def chat_endpoint(request: ChatRequest, api_key: str = Header(None)):
    # Use OpenAI client
    client = OpenAI(api_key="your-api-key")
    
    # Format the messages from the ChatRequest model
    messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
    
    # Use protector to make the API call
    response = protector._provider_protector.protect_openai_call(
        client.chat.completions.create,
        model=request.model or "gpt-4o",
        messages=messages
    )
    
    if "error" in response:
        raise HTTPException(status_code=400, detail=response["error"])
    
    return {"response": response.choices[0].message.content}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

This integration provides:
- Pydantic model validation
- Asynchronous request handling
- CORS support
- Agent-based security model
- API key authentication
- Middleware for request sanitization

### 3. Agent Security

For applications using autonomous agents, RESK-LLM now offers specialized security controls:

```python
from resk_llm.fastapi_integration import FastAPIProtector, AgentSecurityConfig

# Register a new agent with specific permissions
agent_config = AgentSecurityConfig(
    agent_id="customer-support-agent",
    permissions=["chat", "knowledge-base-read"],
    rate_limit=200,
    max_tokens=8192,
    allowed_models=["gpt-4o", "claude-3-opus"],
    api_keys=["sk_secure_key_1", "sk_secure_key_2"]
)

# In your FastAPI app
@app.post("/api/agents")
async def register_agent(config: AgentSecurityConfig, api_key: str = Header(None)):
    if not api_key or api_key != "admin_key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Register the agent
    protector.register_agent(config)
    return {"message": "Agent registered successfully"}

# Protected endpoint that requires agent permissions
@app.post("/api/knowledge")
@protector.secure_endpoint(agent_permission="knowledge-base-read")
async def access_knowledge_base(request_data: dict, agent_id: str = Header(None)):
    # This will only run if the agent has "knowledge-base-read" permission
    # ...
```

### 4. Custom Pattern Management

With the new API endpoints, you can manage custom security patterns dynamically:

```python
# Creating a custom pattern via API
import requests

# Create a new pattern
pattern_data = {
    "name": "financial_security",
    "prohibited_words": ["ssn", "cvv", "account number"],
    "prohibited_patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\b\\d{16}\\b"]
}

response = requests.post(
    "https://your-api.com/api/patterns",
    json=pattern_data,
    headers={"X-API-Key": "your-admin-key"}
)

# Get all patterns
patterns = requests.get(
    "https://your-api.com/api/patterns",
    headers={"X-API-Key": "your-admin-key"}
)

# Update a pattern
updated_pattern = {
    "name": "financial_security",
    "prohibited_words": ["ssn", "cvv", "account number", "routing number"],
    "prohibited_patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\b\\d{16}\\b", "\\b\\d{9}\\b"]
}

response = requests.put(
    "https://your-api.com/api/patterns/financial_security",
    json=updated_pattern,
    headers={"X-API-Key": "your-admin-key"}
)
```

## How to Submit Changes to GitHub

To submit your changes to the GitHub repository, follow these steps:

1. Make sure you have Git installed and configured with your GitHub account
2. Clone the repository (if you haven't already):
   ```
   git clone https://github.com/username/resk-llm.git
   cd resk-llm
   ```

3. Create a new branch for your changes:
   ```
   git checkout -b feature/improved-documentation
   ```

4. Add your modified files:
   ```
   git add .
   ```

5. Commit your changes with a descriptive message:
   ```
   git commit -m "Add English documentation and improve Colab examples"
   ```

6. Push your changes to GitHub:
   ```
   git push origin feature/improved-documentation
   ```

7. Create a Pull Request on GitHub:
   - Go to https://github.com/username/resk-llm
   - Click "Pull requests" > "New pull request"
   - Select your branch and describe your changes
   - Submit the pull request

## Running the Colab Notebook

The improved Colab notebook demonstrates all the new features of RESK-LLM. To run it:

1. Open the notebook in Google Colab
2. Execute each cell sequentially
3. For API calls that require API keys, insert your own keys where indicated

The notebook provides examples of:
- Basic OpenAI API protection
- Flask integration
- FastAPI integration
- Custom pattern management
- PII detection and anonymization
- Multi-provider support 