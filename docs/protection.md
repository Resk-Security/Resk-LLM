# Protection Modules

## Input Sanitizer

```python
from resk2 import InputSanitizer
san = InputSanitizer()
clean = san.clean("<script>alert(1)</script>Hello <!-- hidden -->")
```

## Output Validator

```python
from resk2 import OutputValidator
v = OutputValidator()
result = v.validate("Email: user@test.com")
```

## Canary Tokens

```python
from resk2 import CanaryManager
c = CanaryManager()
prompt = c.insert("Secret document")
```

## resk-logits Integration

```python
from resk2.integrations import ReskLogitsIntegration
integration = ReskLogitsIntegration(tokenizer, device="cpu")
processor = integration.build_processor()
```
