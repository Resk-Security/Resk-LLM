# LLM Protector for OpenAI

LLM Protector is a Python library designed to secure calls to the OpenAI API by protecting against context overflow attacks, cleaning inputs, and managing a sliding context window.

## Installation

```
pip install resk ##soon available  
```
Instead use : 
```
git clone https://github.com/yourusername/llm-protector.git
```

## Usage

```python
from openai import OpenAI
from llm_protector import OpenAIProtector

# Initialize the OpenAI client
client = OpenAI(api_key="your-api-key")

# Create a protector instance
protector = OpenAIProtector(model="gpt-4o-mini", preserved_prompts=2, reserved_tokens=1000)

# Example usage with OpenAI API
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello, can you help me?"},
    {"role": "assistant", "content": "Of course! How can I assist you today?"},
    {"role": "user", "content": "I'd like to learn more about Python programming."}
]

response = protector.protect_openai_call(
    client.chat.completions.create,
    model="gpt-4o-mini",
    messages=messages
)

print(response.choices[0].message.content)
```

## Features

### Model Selection

You can specify the model when initializing the protector:

```python
protector = OpenAIProtector(model="gpt-4o-mini")
```

To get the list of available models:

```python
print(OpenAIProtector.get_available_models())
```

To get information about a specific model:

```python
print(OpenAIProtector.get_model_info("gpt-4o-mini"))
```

### Special Tokens

The protector uses a predefined list of OpenAI special tokens for input sanitization. You can view and modify this list if necessary.

To get the current list of special tokens:

```python
print(OpenAIProtector.get_special_tokens())
```

To update the list of special tokens:

```python
new_tokens = {
    "general": ["<|endoftext|>", "<|fim_prefix|>"],
    "chat": ["<|im_start|>user", "<|im_start|>assistant"]
}
OpenAIProtector.update_special_tokens(new_tokens)
```

### Context Management

The protector automatically manages a sliding context for long conversations. You can specify the number of prompts to preserve and the number of reserved tokens during initialization:

```python
protector = OpenAIProtector(model="gpt-4o-mini", preserved_prompts=2, reserved_tokens=1000)
```

- `preserved_prompts`: Number of messages at the beginning of the conversation to always preserve (default 2, typically the system prompt and the first user message).
- `reserved_tokens`: Number of tokens reserved for preserved messages and the last message (default 1000).

The protector:
- Cleans messages by removing non-UTF-8 characters and special tokens.
- Automatically closes open HTML tags.
- Escapes special HTML characters.
- Truncates messages that are too long if necessary.
- Removes the oldest messages to respect the model's context limit.

## Security

The protector automatically sanitizes all inputs and manages the context when using the `protect_openai_call` method. Always use this method for your OpenAI API calls to benefit from all protections.

## License

This project is licensed under a Custom Open Source License. See the [LICENSE](LICENSE) file for full details. Key points:

- Free for commercial and non-commercial use
- Modifications must be documented and attributed
- Paid versions based on this code are subject to royalties
- The original source must be cited in all derivative works
```

This format is more suitable for a GitHub README.md file. It includes all the necessary sections such as Installation, Usage, Features, and License. The code blocks are properly formatted using markdown syntax, and the structure is clear and easy to read.
