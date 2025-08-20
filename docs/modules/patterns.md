---
title: Patterns
---
---
title: Patterns
---

# Patterns

## FileSystemPatternProvider

```python
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider

provider = FileSystemPatternProvider(config={
  'patterns_base_dir': './patterns',
  'load_defaults': True
})

all_kw = provider.get_keywords()
all_rx = provider.get_compiled_regex()
```

Loads built-in prohibited words/regex and optionally additional JSON files organized by category directories. Also exposes validation errors and metadata.

## Built-in patterns

Located in `resk_llm/patterns/`: prohibited words (EN/FR), PII, LLM injection, emojis, toxic content, special tokens.

## Custom provider

`FileSystemPatternProvider` lets you load patterns from your filesystem.

```python
from resk_llm.patterns.pattern_provider import FileSystemPatternProvider
provider = FileSystemPatternProvider(config={"patterns_base_dir": "./custom_patterns"})
```

