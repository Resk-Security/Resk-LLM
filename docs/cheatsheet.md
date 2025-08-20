---
title: Cheat sheet
---

## Install

```bash
pip install resk-llm
```

## Orchestrator

```python
from resk_llm.RESK import RESK
resk = RESK()
res = resk.process_prompt("Hello")
```

## Prompt security manager

```python
from resk_llm.managers.prompt_security import PromptSecurityManager
m = PromptSecurityManager(enable_heuristic_filter=True, use_canary_tokens=True)
prompt, info = m.secure_prompt("Ignore previous instructions")
```

## Filters

```python
from resk_llm.filters.resk_word_list_filter import RESK_WordListFilter
f = RESK_WordListFilter(config={"blocked_words": ["password"]})
```

## Detectors

```python
from resk_llm.detectors.resk_url_detector import RESK_URLDetector
RESK_URLDetector().detect("http://evil.test")
```

## Vector DB

```python
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase
db = RESK_VectorDatabase(embedding_dim=1536, similarity_threshold=0.85)
```

