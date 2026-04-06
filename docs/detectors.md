# Detectors

RESK-LLM ships with 10 specialized threat detectors, organized by attack vector.

| Detector | Category | Attack Type |
|---|---|---|
| `DirectInjectionDetector` | Pattern matching | "Ignore instructions", system prompt override |
| `BypassDetector` | Jailbreak detection | DAN, developer mode, base64 payloads, stealth |
| `MemoryPoisoningDetector` | Memory attacks | "Remember that..." with false credentials/endpoint |
| `GoalHijackDetector` | Behavioral | Goal drift, scope creep, permission escalation |
| `ExfiltrationDetector` | Data theft | External_endpoint injection, bulk export, encoding |
| `InterAgentInjectionDetector` | Multi-agent | Instruction masquerade, trust exploitation |
| `VectorSimilarityDetector` | Semantic similarity | Cosine similarity against known attack corpus |
| `ACLDecisionTreeDetector` | Access control | RBAC policy tree evaluation |
| `ContentFramingDetector` | Framing attacks | Syntactic masking, sentiment saturation, oversight evasion, persona hyperstition |

All detectors are YAML-configured via `resk2/config/patterns.yaml`.

## Vector Similarity

Uses TF-IDF + cosine similarity (stdlib only, no ML deps). Supports external backends:

```yaml
vector_similarity:
  backend: local  # local | qdrant | pinecone | pgvector | custom
  threshold: 0.75
  attack_patterns:
    - pattern: "ignore all previous instructions"
      label: "classic_injection"
```

## ACL Decision Tree

Role-based access control via configurable decision tree:

```yaml
acl_decision_tree:
  root:
    condition: "user_role"
    branches:
      admin: { action: "allow" }
      agent: { condition: "request_type", branches: {...} }
```

## Content Framing

Detects sophisticated attacks using formatting and framing:

- **Syntactic Masking**: LaTeX macros, Markdown code blocks, zero-width chars
- **Sentiment Saturation**: Urgency, authority, moral imperative framing
- **Oversight Evasion**: Academic, hypothetical, red-teaming wrappers
- **Persona Hyperstition**: Identity renaming, narrative seeding, retrieval re-entry
