# API Reference

## Core Classes

### SecurityPipeline

```python
class SecurityPipeline:
    def add(self, detector: BaseDetector) -> SecurityPipeline
    def remove(self, name: str) -> bool
    def run(self, text: str, context=None, **kwargs) -> PipelineResult
    def run_safe(self, text: str, context=None, **kwargs) -> tuple[bool, PipelineResult]
```

### ConversationContext

```python
class ConversationContext:
    def __init__(self, max_entries=50, escalation_window=10)
    def add_entry(self, text: str, result)
    def detect_escalation(self) -> float     # 0.0 (safe) → 1.0 (severe)
    def get_summary(self) -> dict
```

### DetectionResult / PipelineResult

See `resk2/core/detector.py` and `resk2/core/pipeline.py` for dataclass definitions.

---

Generated from source. See individual modules for docstrings.
