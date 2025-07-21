# Simple example: Secure a prompt using the RESK orchestrator
# TIP: To avoid loading torch and vector DB features, set enable_heuristic_filter=False and do not provide an embedding_function to PromptSecurityManager.

from resk_llm.RESK import RESK

# Initialize RESK
resk = RESK()

# Test prompt
prompt = "Hello, how are you?"

# Process the prompt
result = resk.process_prompt(prompt)

# Print results
print("Basic RESK Usage Example")
print("=" * 30)
for key, value in result.items():
    print(f"{key}: {value}")
