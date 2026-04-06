# Configuration

All detection patterns and thresholds are in `resk2/config/patterns.yaml`.

## Sections

- `global`: languages, confidence, max input
- `direct_injection`: high/medium/low patterns
- `bypass_detection`: jailbreak + stealth patterns
- `memory_poisoning`: memory manipulation + fake facts
- `goal_hijack`: drift, scope, escalation
- `exfiltration`: endpoints, data collection, encoding, webhook
- `inter_agent_injection`: masquerade, role override, chain, trust
- `vector_similarity`: backend, threshold, attack_patterns
- `acl_decision_tree`: RBAC policy tree
- `content_framing`: syntactic masking, sentiment, oversight, persona
- `thresholds`: per-detector scoring parameters
