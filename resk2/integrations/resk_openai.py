"""OpenAI wrapper with built-in security pipeline."""
from __future__ import annotations
from typing import Any
from resk2.core import SecurityPipeline, PipelineResult
from resk2.protection import CanaryManager, OutputValidator

class OpenAIWrapper:
    """Thin wrapper around OpenAI client with automatic security scanning.
    
    Usage:
        from openai import OpenAI
        from resk2.integrations import OpenAIWrapper
        
        client = OpenAI()
        wrapper = OpenAIWrapper(client)
        
        response = wrapper.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}]
        )
    """
    
    def __init__(self, client, pipeline: SecurityPipeline | None = None,
                 canary: CanaryManager | None = None,
                 validator: OutputValidator | None = None,
                 block_on_input: bool = True,
                 check_output: bool = True):
        self._client = client
        self.pipeline = pipeline or SecurityPipeline()
        self.canary = canary or CanaryManager()
        self.validator = validator or OutputValidator()
        self.block_on_input = block_on_input
        self.check_output = check_output
    
    def _build_messages(self, messages: list[dict]) -> list[dict]:
        """Insert canary tokens into system message if present."""
        result = []
        for msg in messages:
            if msg.get("role") == "system":
                content = self.canary.insert(msg["content"], context="system")
                result.append({**msg, "content": content})
            else:
                result.append(msg)
        return result
    
    class _ChatProxy:
        def __init__(self, wrapper: "OpenAIWrapper"):
            self._wrapper = wrapper
        
        class CompletionsProxy:
            def __init__(self, wrapper: "OpenAIWrapper"):
                self._wrapper = wrapper
            
            def create(self, messages: list[dict], **kwargs: Any) -> Any:
                # Check input
                full_text = " ".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))
                if self._wrapper.block_on_input:
                    result = self._wrapper.pipeline.run(full_text)
                    if result.blocked:
                        raise ValueError(
                            f"Input blocked by security: {result.block_reason}"
                        )
                
                # Inject canary tokens
                secure_messages = self._wrapper._build_messages(messages)
                
                # Call actual client
                response = self._wrapper._client.chat.completions.create(
                    messages=secure_messages, **kwargs
                )
                
                # Validate output
                if self._wrapper.check_output:
                    content = response.choices[0].message.content if response.choices else ""
                    validation = self._wrapper.validator.validate(content)
                    if not validation.is_safe:
                        response._security_issues = validation.issues
                    
                    # Check canary leaks
                    leak_result = self._wrapper.canary.check(content)
                    if leak_result.has_leak:
                        response._canary_leak = True
                        response._leaked_tokens = leak_result.leaked_tokens
                
                return response
        
        def __init__(self, wrapper: "OpenAIWrapper"):
            self.completions = self.CompletionsProxy(wrapper)
    
    @property
    def chat(self):
        return self._ChatProxy(self)
