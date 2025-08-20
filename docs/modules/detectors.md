---
title: Detectors
---

# Detectors

## RESK_IPDetector

```python
from resk_llm.detectors.resk_ip_detector import RESK_IPDetector

d = RESK_IPDetector()
report = d.detect("Contact 192.168.1.1 or 8.8.8.8; CIDR 10.0.0.0/8")
print(report['counts'], report['classified_ips'])
```

Finds IPv4/IPv6, CIDR, MACs, and network commands; classifies private vs public.

## RESK_URLDetector

```python
from resk_llm.detectors.resk_url_detector import RESK_URLDetector

u = RESK_URLDetector()
res = u.detect("Visit http://paypa1-secure.com/login")
print(res['detected_urls_count'], res['suspicious_urls_count'], res['max_risk_score'])
```

Checks shorteners, suspicious TLDs, ports, phishing patterns, and typosquatting.

## RESK_VectorDatabase

```python
import numpy as np
from resk_llm.utilities.resk_embedding_utils import SimpleEmbedder
from resk_llm.utilities.resk_vector_db import RESK_VectorDatabase

embedder = SimpleEmbedder(dimension=64)
vdb = RESK_VectorDatabase(config={'embedding_dim': 64, 'similarity_threshold': 0.7})

v1 = embedder.embed("prompt injection example")
vdb.add_entry(v1, {'text_preview': 'prompt injection example'})

q = embedder.embed("attempt to bypass instructions")
print(vdb.detect(q))
```

In-memory vector similarity with optional external DB adapters (FAISS, Qdrant, etc.).

## RESK_TextAnalyzer

```python
from resk_llm.utilities.resk_text_analysis import RESK_TextAnalyzer

ta = RESK_TextAnalyzer()
analysis = ta.analyze_text("foo\u200Bbar")
print(analysis['overall_risk'])
```

Detects invisible chars, homoglyphs, unusual spaces; can clean text.

---
title: Detectors
---

## Overview

Detectors analyze text and return a signal or details to flag risks.

### RESK_IPDetector

Detects IP leakage.

```python
from resk_llm.detectors.resk_ip_detector import RESK_IPDetector
d = RESK_IPDetector()
det = d.detect("My IP is 192.168.1.10")
```

### RESK_URLDetector

Detects malicious or suspicious URLs.

```python
from resk_llm.detectors.resk_url_detector import RESK_URLDetector
d = RESK_URLDetector()
det = d.detect("visit http://evil.test")
```

