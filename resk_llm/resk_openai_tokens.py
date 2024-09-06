# resk_openai_tokens.py

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