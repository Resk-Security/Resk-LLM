---
title: Utilities
---

# Utilities

## RESK_Embedder and SimpleEmbedder

```python
from resk_llm.utilities.resk_embedding_utils import RESK_Embedder, SimpleEmbedder

simple = SimpleEmbedder(dimension=64)
vec = simple.embed("hello world")

# sklearn-based (requires scikit-learn)
# emb = RESK_Embedder(dimension=128)
# emb.train(["a corpus", "of texts"]) 
# v = emb.embed("hello world")
```

## RESK_TextAnalyzer

```python
from resk_llm.utilities.resk_text_analysis import RESK_TextAnalyzer

ta = RESK_TextAnalyzer()
print(ta.clean_text("foo\u200Bbar"))
```

## RESK_VectorDatabase

See Detectors page for end-to-end example, including external DBs.

---
title: Utilities
---

## Text analysis

`resk_llm.utilities.resk_text_analysis.RESK_TextAnalyzer` detects homoglyphs, invisible chars, etc.

## Embeddings and vector DB

`RESK_Embedder` and `RESK_VectorDatabase` help store and compare embeddings for similarity to known attacks.

```python
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase
db = RESK_VectorDatabase(embedding_dim=1536, similarity_threshold=0.85)
```

