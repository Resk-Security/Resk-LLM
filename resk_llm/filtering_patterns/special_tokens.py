"""
Module contenant des listes de tokens spéciaux pour différents modèles LLM.
Ces tokens peuvent être utilisés pour les attaques d'injection de prompts.
"""

from typing import Dict, List, Set

# Tokens spéciaux pour les modèles OpenAI
OPENAI_SPECIAL_TOKENS = {
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

# Tokens spéciaux pour les modèles Anthropic Claude
ANTHROPIC_SPECIAL_TOKENS = {
    "claude": [
        "<human>", "</human>", 
        "<assistant>", "</assistant>",
        "<system>", "</system>",
        "<answer>", "</answer>",
        "<message>", "</message>",
        "\n\nHuman:", "\n\nAssistant:"
    ]
}

# Tokens spéciaux pour les modèles Meta Llama
LLAMA_SPECIAL_TOKENS = {
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

# Tokens spéciaux pour les modèles Mistral
MISTRAL_SPECIAL_TOKENS = {
    "mistral": [
        "<s>", "</s>", 
        "<|system|>", "<|user|>", "<|assistant|>",
        "[INST]", "[/INST]"
    ]
}

# Tokens spéciaux pour les modèles Cohere
COHERE_SPECIAL_TOKENS = {
    "cohere": [
        "<|USER|>", "<|ASSISTANT|>", "<|SYSTEM|>",
        "<|USER_END|>", "<|ASSISTANT_END|>", "<|SYSTEM_END|>"
    ]
}

# Regroupement de tous les tokens spéciaux
ALL_SPECIAL_TOKENS = set()

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

# Caractères de contrôle qui peuvent être utilisés pour des attaques
CONTROL_CHARS = {
    '\r': '\\r',  # Carriage Return
    '\n': '\\n',  # Line Feed
    '\t': '\\t',  # Tab
    '\b': '\\b',  # Backspace
    '\f': '\\f',  # Form Feed
    '\v': '\\v',  # Vertical Tab
    '\0': '\\0',  # Null character
    '\a': '\\a',  # Bell/Alert
    '\x1b': '\\x1b',  # Escape (was '\e')
    '\x1b': '\\x1b',  # Escape (hex)
    '\u001b': '\\u001b',  # Escape (unicode)
    '\u0000': '\\u0000',  # Null
    '\u0007': '\\u0007',  # Bell
    '\u001b[0m': '\\u001b[0m',  # Reset ANSI
    '\u001b[31m': '\\u001b[31m',  # Red ANSI
    '\u001b[32m': '\\u001b[32m'  # Green ANSI
}

# Liste des caractères spéciaux pouvant être utilisés dans les attaques
SPECIAL_CHARS = [
    # Guillemets et délimiteurs
    '"', "'", "`", """, """, "「", "」", "『", "』", "«", "»",
    
    # Caractères d'échappement et de formatage
    "\\", "%", "$", "#", "@", "&", "*", "^", "_", "~",
    
    # Caractères de balisage
    "<", ">", "{", "}", "[", "]", "(", ")", "|",
    
    # Caractères de ponctuation spéciaux
    "…", "•", "◆", "★", "✓", "✗", "✓", "☑", "☐", "☒"
]

def get_all_special_tokens() -> Set[str]:
    """
    Retourne tous les tokens spéciaux de tous les modèles.
    
    Returns:
        Ensemble de tous les tokens spéciaux
    """
    return ALL_SPECIAL_TOKENS

def get_model_special_tokens(model_type: str) -> List[str]:
    """
    Retourne les tokens spéciaux pour un type de modèle spécifique.
    
    Args:
        model_type: Type de modèle ('openai', 'anthropic', 'llama', 'mistral', 'cohere')
        
    Returns:
        Liste des tokens spéciaux pour le type de modèle spécifié
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