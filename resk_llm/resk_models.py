
RESK_MODELS = {
    # GPT-4o models
    "gpt-4o": {
        "description": "Our high-intelligence flagship model for complex, multi-step tasks. GPT-4o is cheaper and faster than GPT-4 Turbo.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Oct 2023",
        "version": "gpt-4o-2024-05-13"
    },
    "gpt-4o-2024-05-13": {
        "description": "gpt-4o currently points to this version.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Oct 2023"
    },
    "gpt-4o-2024-08-06": {
        "description": "Latest snapshot that supports Structured Outputs",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    "chatgpt-4o-latest": {
        "description": "Dynamic model continuously updated to the current version of GPT-4o in ChatGPT. Intended for research and evaluation.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    
    # GPT-4o mini models
    "gpt-4o-mini": {
        "description": "Our affordable and intelligent small model for fast, lightweight tasks. GPT-4o mini is cheaper and more capable than GPT-3.5 Turbo.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023",
        "version": "gpt-4o-mini-2024-07-18"
    },
    "gpt-4o-mini-2024-07-18": {
        "description": "gpt-4o-mini currently points to this version.",
        "context_window": 128000,
        "max_output_tokens": 16384,
        "training_data": "Up to Oct 2023"
    },
    
    # GPT-4 Turbo and GPT-4 models
    "gpt-4-turbo": {
        "description": "The latest GPT-4 Turbo model with vision capabilities. Vision requests can now use JSON mode and function calling.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023",
        "version": "gpt-4-turbo-2024-04-09"
    },
    "gpt-4-turbo-2024-04-09": {
        "description": "GPT-4 Turbo with Vision model. Vision requests can now use JSON mode and function calling.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023"
    },
    "gpt-4-turbo-preview": {
        "description": "GPT-4 Turbo preview model.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023",
        "version": "gpt-4-0125-preview"
    },
    "gpt-4-0125-preview": {
        "description": "GPT-4 Turbo preview model intended to reduce cases of 'laziness' where the model doesn't complete a task.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Dec 2023"
    },
    "gpt-4-1106-preview": {
        "description": "GPT-4 Turbo preview model featuring improved instruction following, JSON mode, reproducible outputs, parallel function calling, and more.",
        "context_window": 128000,
        "max_output_tokens": 4096,
        "training_data": "Up to Apr 2023"
    },
    "gpt-4": {
        "description": "Currently points to gpt-4-0613.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021",
        "version": "gpt-4-0613"
    },
    "gpt-4-0613": {
        "description": "Snapshot of gpt-4 from June 13th 2023 with improved function calling support.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021"
    },
    "gpt-4-0314": {
        "description": "Legacy Snapshot of gpt-4 from March 14th 2023.",
        "context_window": 8192,
        "max_output_tokens": 8192,
        "training_data": "Up to Sep 2021"
    },
    
    # GPT-3.5 Turbo models
    "gpt-3.5-turbo": {
        "description": "Currently points to gpt-3.5-turbo-0125.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021",
        "version": "gpt-3.5-turbo-0125"
    },
    "gpt-3.5-turbo-0125": {
        "description": "The latest GPT-3.5 Turbo model with higher accuracy at responding in requested formats and a fix for a bug which caused a text encoding issue for non-English language function calls.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    },
    "gpt-3.5-turbo-1106": {
        "description": "GPT-3.5 Turbo model with improved instruction following, JSON mode, reproducible outputs, parallel function calling, and more.",
        "context_window": 16385,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    },
    "gpt-3.5-turbo-instruct": {
        "description": "Similar capabilities as GPT-3 era models. Compatible with legacy Completions endpoint and not Chat Completions.",
        "context_window": 4096,
        "max_output_tokens": 4096,
        "training_data": "Up to Sep 2021"
    }
}