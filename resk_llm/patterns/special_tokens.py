"""
Module containing special token lists for different LLM models.
These tokens can be used for prompt injection attacks.
"""

from typing import Dict, List, Set, Any, Union

# Special tokens for OpenAI models
OPENAI_SPECIAL_TOKENS: Dict[str, List[str]] = {
    "general": [
        "<|endoftext|>",
        "<|fim_prefix|>",
        "<|fim_middle|>",
        "<|fim_suffix|>",
        "<|endofprompt|>",
        "<s>",
        "</s>",
        "<|im_start|>",
        "<|im_end|>",
        "<|im_sep|>",
        "[/INST]",
        "SYS",
        "[INST]",
        "<endoftext>",
        "</endoftext>",
        "<|end|>", 
        "Human:",
        "Assistant:"
    ],
    "chat": [
        "<|im_start|>user",
        "<|im_start|>assistant",
        "<|im_start|>system",
    ]
}

# Special tokens for Anthropic Claude models
ANTHROPIC_SPECIAL_TOKENS: Dict[str, List[str]] = {
    "claude": [
        "<human>", "</human>", 
        "<assistant>", "</assistant>",
        "<s>", "</s>",
        "<answer>", "</answer>",
        "<message>", "</message>",
        "\n\nHuman:", "\n\nAssistant:"
    ]
}

# Special tokens for Meta Llama models
LLAMA_SPECIAL_TOKENS: Dict[str, List[str]] = {
    "llama": [
        "<|begin_of_text|>", "<|end_of_text|>",
        "<|begin_of_system|>", "<|end_of_system|>",
        "<|begin_of_user|>", "<|end_of_user|>",
        "<|begin_of_assistant|>", "<|end_of_assistant|>",
        "[INST]", "[/INST]",
        "<<SYS>>", "<</SYS>>",
        "<s>", "</s>"
    ]
}

# Special tokens for Mistral models
MISTRAL_SPECIAL_TOKENS: Dict[str, List[str]] = {
    "mistral": [
        "<s>", "</s>", 
        "<|system|>", "<|user|>", "<|assistant|>",
        "[INST]", "[/INST]"
    ]
}

# Special tokens for Cohere models
COHERE_SPECIAL_TOKENS: Dict[str, List[str]] = {
    "cohere": [
        "<|USER|>", "<|ASSISTANT|>", "<|SYSTEM|>",
        "<|USER_END|>", "<|ASSISTANT_END|>", "<|SYSTEM_END|>"
    ]
}

# Group all special tokens together
ALL_SPECIAL_TOKENS: Set[str] = set()

for token_list in OPENAI_SPECIAL_TOKENS.values():
    ALL_SPECIAL_TOKENS.update(token_list)

for token_list in ANTHROPIC_SPECIAL_TOKENS.values():
    ALL_SPECIAL_TOKENS.update(token_list)
    
for token_list in LLAMA_SPECIAL_TOKENS.values():
    ALL_SPECIAL_TOKENS.update(token_list)
    
for token_list in MISTRAL_SPECIAL_TOKENS.values():
    ALL_SPECIAL_TOKENS.update(token_list)
    
for token_list in COHERE_SPECIAL_TOKENS.values():
    ALL_SPECIAL_TOKENS.update(token_list)

# Control characters that can be used for attacks
CONTROL_CHARS: Dict[str, str] = {
    '\r': '\\r',  # Carriage Return
    '\n': '\\n',  # Line Feed
    '\t': '\\t',  # Tab
    '\b': '\\b',  # Backspace
    '\f': '\\f',  # Form Feed
    '\v': '\\v',  # Vertical Tab
    '\0': '\\0',  # Null character
    '\a': '\\a',  # Bell/Alert
    '\x1b': '\\x1b',  # Escape
    '\u001b': '\\u001b',  # Escape (unicode)
    '\u0000': '\\u0000',  # Null
    '\u0007': '\\u0007',  # Bell
    '\u001b[0m': '\\u001b[0m',  # Reset ANSI
    '\u001b[31m': '\\u001b[31m',  # Red ANSI
    '\u001b[32m': '\\u001b[32m'  # Green ANSI
}

# List of special characters that can be used in attacks
SPECIAL_CHARS: List[str] = [
    # Quotes and delimiters
    '"', "'", "`", """, """, "「", "」", "『", "』", "«", "»",
    
    # Escape and formatting characters
    "\\", "%", "$", "#", "@", "&", "*", "^", "_", "~",
    
    # Markup characters
    "<", ">", "{", "}", "[", "]", "(", ")", "|",
    
    # Special punctuation characters
    "…", "•", "◆", "★", "✓", "✗", "✓", "☑", "☐", "☒"
]

def get_all_special_tokens() -> Set[str]:
    """
    Returns all special tokens from all models.
    
    Returns:
        Set containing all special tokens
    """
    return ALL_SPECIAL_TOKENS

def get_model_special_tokens(model_type: str) -> List[str]:
    """
    Returns special tokens for a specific model type.
    
    Args:
        model_type: Model type ('openai', 'anthropic', 'llama', 'mistral', 'cohere')
        
    Returns:
        List of special tokens for the specified model type
    """
    model_type = model_type.lower()
    
    if model_type == 'openai':
        return list(set(OPENAI_SPECIAL_TOKENS["general"] + OPENAI_SPECIAL_TOKENS["chat"]))
    elif model_type == 'anthropic':
        return list(ANTHROPIC_SPECIAL_TOKENS["claude"])
    elif model_type == 'llama':
        return list(LLAMA_SPECIAL_TOKENS["llama"])
    elif model_type == 'mistral':
        return list(MISTRAL_SPECIAL_TOKENS["mistral"])
    elif model_type == 'cohere':
        return list(COHERE_SPECIAL_TOKENS["cohere"])
    else:
        return list(ALL_SPECIAL_TOKENS) 