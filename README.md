
# RESK LLM Library

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Main Features](#main-features)
   - [OpenAIProtector](#openaiprotector)
   - [Context Managers](#context-managers)
   - [Text Cleaner](#text-cleaner)
   - [ReskWordsLists](#reskwordslists)
4. [Usage](#usage)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Security](#security)
8. [Contributing](#contributing)
9. [License](#license)

## Introduction

The RESK LLM library is a powerful set of tools designed to interact securely with OpenAI's language models. It offers advanced features for context management, text cleaning, and protection against potentially malicious injections.

This library is particularly useful for developers who want to integrate OpenAI's language model capabilities into their applications while maintaining a high level of security and control over inputs and outputs.

## Installation

```bash
pip install resk-llm
```

## Main Features

### OpenAIProtector

The `OpenAIProtector` class is the core of the library. It provides a secure interface for interacting with OpenAI APIs. Its main features include:

- Selection and configuration of specific OpenAI models
- Cleaning and sanitization of user inputs
- Context management for long conversations
- Protection against special token injection

### Context Managers

The library offers two types of context managers:

1. `TokenBasedContextManager`: Manages context based on the number of tokens, ideal for models with strict context limits.
2. `MessageBasedContextManager`: Manages context based on the number of messages, suitable for scenarios where limiting the number of messages is more important than the number of tokens.

These managers allow maintaining coherent conversations while respecting the context limits of the models.

### Text Cleaner

The `TextCleaner` class provides utility methods for cleaning and truncating text, ensuring that inputs are well-formatted and respect length limits.

Certainly! I'll update the README with the new code and elements you've provided. Here's the revised version of the Usage and Features sections:

### ReskWordsLists

The ReskWordsLists class manages lists of prohibited words and patterns. It provides methods to check input against these lists and to add or remove items from the lists.

## Usage

```python
from openai import OpenAI
from resk_llm import OpenAIProtector
from resk_llm.resk_context_manager import TokenBasedContextManager
from resk_llm.resk_models import RESK_MODELS

# Initialize the OpenAI client
client = OpenAI(api_key="API_KEY")
model = "gpt-4o"
# Initializing the protector
protector = OpenAIProtector(model=model, context_manager=TokenBasedContextManager(RESK_MODELS[model]))

messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello, can you help me?"},
    {"role": "assistant", "content": "Of course! How can I assist you today?"},
    {"role": "user", "content": "I'd like to learn more about Python programming."}
]

response = protector.protect_openai_call(
    client.chat.completions.create,
    model = model,
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

#### Special Tokens

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

## Prohibited Words and Patterns

The ReskWordsLists class manages prohibited words and patterns:
```python
protector.update_prohibited_list("badword", "add", "word")
protector.update_prohibited_list(r"\b(ignore)\s+(system)\b", "add", "pattern")
## You can also perform batch updates:
pythonCopyupdates = [
    {"item": "badword1", "action": "add", "item_type": "word"},
    {"item": "badword2", "action": "remove", "item_type": "word"},
    {"item": r"\b(avoid)\s+(rules)\b", "action": "add", "item_type": "pattern"}
]
protector.batch_update(updates)
```

## API Reference

### OpenAIProtector

- `__init__(self, model: str = "gpt-4", context_manager: Union[TokenBasedContextManager, MessageBasedContextManager] = None)`
- `sanitize_input(self, text: str) -> str`
- `protect_openai_call(self, api_function: Callable, *args: Any, **kwargs: Any) -> Any`
- `get_available_models(cls) -> List[str]`
- `get_model_info(cls, model: str) -> Dict[str, Any]`
- `get_special_tokens(cls) -> Dict[str, List[str]]`
- `update_special_tokens(cls, new_tokens: Dict[str, List[str]]) -> None`
- `get_control_chars(cls) -> Dict[str, str]`
- `update_control_chars(cls, new_chars: Dict[str, str]) -> None`

### TokenBasedContextManager and MessageBasedContextManager

- `__init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2, ...)`
- `clean_message(self, message: str) -> str`
- `manage_sliding_context(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]`

### TextCleaner

- `clean_text(text: str) -> str`
- `truncate_text(text: str, max_length: int) -> str`

### ReskWordsLists

- `__init__(self)`
- `check_input(self, text: str) -> Union[str, None]`
- `add_prohibited_word(self, word: str) -> None`
- `add_prohibited_pattern(self, pattern: str) -> None`
- `remove_prohibited_word(self, word: str) -> None`
- `remove_prohibited_pattern(self, pattern: str) -> None`

## Configuration

The library uses several constants and configurations defined in separate modules:

- `RESK_MODELS`: Information about supported models
- `OPENAI_SPECIAL_TOKENS`: Special tokens to filter
- `RESK_CONTROL_CHARS`: Control characters to manage

These configurations can be dynamically updated using the class methods of `OpenAIProtector`.

## Security

Security is a priority in this library. It implements several measures:

- Cleaning and sanitization of user inputs
- Removal of potentially dangerous special tokens
- UTF-8 encoding and HTML escaping
- Secure management of conversation context
- Filtering of prohibited words and patterns


## Contributing

Contributions to this library are welcome. Please follow these steps to contribute:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
