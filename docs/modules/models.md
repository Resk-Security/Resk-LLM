---
title: Models Registry
---

# Models Registry

`resk_llm.models.resk_models` provides a `ModelRegistry` with metadata like context windows and token limits.

```python
from resk_llm.models.resk_models import ModelRegistry, default_registry

print(default_registry.get_context_window('gpt-4o'))

reg = ModelRegistry()
print(reg.is_model_supported('gpt-3.5-turbo'))
```

You can add or update models at runtime:

```python
reg.add_model('my-model', {'context_window': 8192, 'max_output_tokens': 2048})
```


