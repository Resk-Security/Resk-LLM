# Integrations

RESK-LLM provides seamless integrations with popular frameworks and services to add security to your LLM pipelines without changing your existing code.

## Overview

- **[FastAPI Middleware](#fastapi-middleware)** - Automatic request/response scanning
- **[OpenAI Wrapper](#openai-wrapper)** - Drop-in replacement for OpenAI client
- **[resk-logits Integration](#resk-logits-integration)** - Generation-time shadow banning
- **[Conversation Context](#conversation-context)** - Multi-turn conversation tracking

---

## FastAPI Middleware

Automatically scan incoming requests and outgoing responses in your FastAPI applications.

### Installation

```bash
pip install resk-llm[fastapi]
```

### Basic Usage

```python
from fastapi import FastAPI
from resk2 import SecurityPipeline, DirectInjectionDetector
from resk2.integrations import ReskMiddleware

app = FastAPI()

# Create security pipeline
pipeline = (
    SecurityPipeline()
    .add(DirectInjectionDetector())
    .add(BypassDetector())
)

# Add middleware
app.add_middleware(
    ReskMiddleware,
    pipeline=pipeline,
    excluded_paths=["/health", "/docs", "/openapi.json"]
)

@app.post("/chat")
async def chat(request: dict):
    # Requests are automatically scanned
    return {"response": "Hello!"}
```

### Configuration Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `pipeline` | `SecurityPipeline` | The security pipeline to use for scanning |
| `excluded_paths` | `list[str]` | Paths to exclude from scanning |
| `block_on_threat` | `bool` | Whether to block requests with threats (default: True) |

### How It Works

1. **Request Scanning**: Incoming request bodies are scanned for prompt injection and other attacks
2. **Response Scanning**: Outgoing responses are checked for data leaks
3. **Automatic Blocking**: Threats are blocked before reaching your endpoints
4. **Header Information**: Security results are added to response headers

---

## OpenAI Wrapper

Drop-in wrapper for the OpenAI Python client that adds security scanning to all API calls.

### Installation

```bash
pip install resk-llm[openai]
```

### Basic Usage

```python
from openai import OpenAI
from resk2.integrations import OpenAIWrapper

# Create OpenAI client
client = OpenAI()

# Wrap with security
wrapper = OpenAIWrapper(
    client,
    block_on_input=True,      # Block malicious prompts
    check_output=True,        # Scan LLM responses
    insert_canaries=True      # Add canary tokens
)

# Use exactly like normal OpenAI client
response = wrapper.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What is 2+2?"}]
)
```

### Features

- **Input Scanning**: All prompts are checked before being sent to OpenAI
- **Output Validation**: Responses are scanned for leaked data
- **Canary Tokens**: Automatic insertion and checking of canary tokens
- **Compatible API**: Same interface as the official OpenAI client

### Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `block_on_input` | `bool` | `True` | Block requests with detected threats |
| `check_output` | `bool` | `True` | Scan LLM responses for data leaks |
| `insert_canaries` | `bool` | `False` | Insert canary tokens in prompts |
| `sanitizer` | `InputSanitizer` | `None` | Custom sanitizer for inputs |

---

## resk-logits Integration

Real-time generation-time shadow banning using [resk-logits](https://github.com/Resk-Security/resk-logits).

### Installation

```bash
pip install resk-llm
pip install resklogits
```

### Basic Usage

```python
from transformers import AutoModelForCausalLM, AutoTokenizer
from resk2.integrations import ReskLogitsIntegration

# Load model and tokenizer
model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b-chat-hf")
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-chat-hf")

# Create integration
integration = ReskLogitsIntegration(
    tokenizer,
    device="cuda",  # or "cpu"
    penalty=-15.0   # Shadow ban penalty
)

# Build processor
processor = integration.build_processor()

# Generate with shadow ban
response = model.generate(
    **tokenizer("Tell me", return_tensors="pt"),
    logits_processor=[processor],
    max_new_tokens=50
)
```

### How It Works

1. **Pattern Extraction**: Automatically extracts banned patterns from `patterns.yaml`
2. **Token Matching**: Uses Aho-Corasick algorithm for efficient pattern matching
3. **Logit Penalty**: Applies penalty (-15.0) to tokens matching dangerous patterns
4. **Multi-level**: Supports multiple penalty levels for different threat severities

### Advantages

- **Generation-time**: Prevents toxic outputs during generation, not after
- **GPU Accelerated**: Optimized for CUDA with minimal latency overhead
- **Pattern Sync**: Uses same patterns as RESK-LLM detectors
- **Configurable**: Adjustable penalty values and pattern sources

---

## Conversation Context

Track multi-turn conversations to detect escalation patterns over time.

### Basic Usage

```python
from resk2 import SecurityPipeline, ConversationContext, DirectInjectionDetector

# Create context with configuration
ctx = ConversationContext(
    max_entries=50,           # Keep last 50 messages
    escalation_window=10      # Check last 10 for escalation
)

# Create pipeline
pipeline = SecurityPipeline().add(DirectInjectionDetector())

# Track conversation turns
result1 = pipeline.run("Hello, how are you?", context=ctx)
ctx.add_entry("Hello, how are you?", result1)

result2 = pipeline.run("Tell me about Python", context=ctx)
ctx.add_entry("Tell me about Python", result2)

# Later, detect if conversation escalated
escalation_score = ctx.detect_escalation()
print(f"Escalation: {escalation_score:.2f}")  # 0.0 (safe) -> 1.0 (severe)

# Get conversation summary
summary = ctx.get_summary()
print(f"Total entries: {summary['total_entries']}")
print(f"Total threats: {summary['total_threats']}")
```

### Escalation Detection

The escalation algorithm considers:

- **Threat Frequency**: How many threats in the window
- **Severity Trend**: Increasing severity over time  
- **Block Rate**: Percentage of blocked messages
- **Burst Detection**: Multiple threats in succession

### Use Cases

- **Chat Applications**: Detect when users try to jailbreak over multiple turns
- **Customer Support**: Identify frustrated users before they escalate
- **Content Moderation**: Flag conversations trending toward toxic content
- **Compliance**: Audit trails for sensitive conversations

---

## End-to-End Pipeline

Combine all integrations for complete security:

```python
# Input → RESK-LLM → Sanitize → LLM → resk-logits → Output validator → Canary check

from resk2 import (
    SecurityPipeline, DirectInjectionDetector,
    InputSanitizer, OutputValidator, CanaryManager
)
from resk2.integrations import OpenAIWrapper, ReskLogitsIntegration

# 1. Pre-processing
pipeline = SecurityPipeline().add(DirectInjectionDetector())
sanitizer = InputSanitizer()
canary = CanaryManager()

# 2. LLM with resk-logits
integration = ReskLogitsIntegration(tokenizer)
logits_processor = integration.build_processor()

# 3. Post-processing
validator = OutputValidator()

# Full pipeline
user_input = "User message here"
result = pipeline.run(user_input)

if not result.blocked:
    clean_input = sanitizer.clean(user_input)
    prompt_with_canary = canary.insert(clean_input)
    
    # Generate with shadow ban
    response = model.generate(
        **tokenizer(prompt_with_canary, return_tensors="pt"),
        logits_processor=[logits_processor],
        max_new_tokens=100
    )
    
    # Validate output
    validation = validator.validate(response_text)
    leak_check = canary.check(response_text)
    
    if not validation.is_safe or leak_check.has_leak:
        # Handle security issue
        pass
```

---

## See Also

- [Configuration Guide](configuration.md) - Customize detection patterns
- [Detectors Reference](detectors.md) - All available detectors
- [Protection Modules](protection.md) - Sanitizers and validators
- [GitHub Repository](https://github.com/Resk-Security/Resk-LLM)
