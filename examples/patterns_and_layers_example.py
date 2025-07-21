# TIP: To avoid loading torch and vector DB features, set enable_heuristic_filter=False and do not provide an embedding_function to PromptSecurityManager.
# Example: Custom patterns and security layers configuration
from resk_llm.RESK import RESK
from resk_llm.filters.resk_content_policy_filter import RESK_ContentPolicyFilter
from resk_llm.filters.resk_word_list_filter import RESK_WordListFilter
from resk_llm.detectors.resk_ip_detector import RESK_IPDetector
from resk_llm.managers.prompt_security import PromptSecurityManager
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider

# Custom pattern provider (could point to a custom directory or config)
pattern_provider = FileSystemPatternProvider(config={"patterns_base_dir": "./custom_patterns"})

# Configure filters, detectors, and managers with the custom provider
filters = [
    RESK_ContentPolicyFilter(config={"pattern_provider": pattern_provider}),
    RESK_WordListFilter(config={"pattern_provider": pattern_provider})
]
detectors = [RESK_IPDetector()]
managers = [PromptSecurityManager(enable_heuristic_filter=False)]  # disables vector DB/torch

# Instantiate RESK with custom layers and patterns
resk = RESK(filters=filters, detectors=detectors, managers=managers, patterns=pattern_provider)

# Example prompt to test
prompt = "This prompt contains a secret IP: 192.168.1.1."

# Process the prompt
result = resk.process_prompt(prompt)

# Print the structured result
print("Custom patterns & layers result:")
for key, value in result.items():
    print(f"  {key}: {value}") 