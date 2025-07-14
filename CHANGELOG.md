# Changelog

## [1.2.0] - 2025-13-07

### Added
- New example: `examples/fastapi_resk_example.py` demonstrating integration of cache, monitoring, and advanced security with FastAPI.
- English documentation and code comments for FastAPI integration in README.md.

### Fixed
- Suppressed 'Missing config key: anomaly_sensitivity' warnings by setting a default in the security manager.
- Adjusted risk assessment logic and test thresholds for stricter anomaly detection; all tests now pass.

### Changed
- Updated README.md with FastAPI integration example and improved English documentation.

## [1.0.1] - 2024-09-24 # Placeholder Date - Please Update!

### Changed

- Refactored `examples/openai_example.py` to use `OpenAIProtector` class and `execute_protected` method instead of the deprecated `create_openai_protector` function and `protect_client`.
- Refactored `examples/async_example.py` to align with `OpenAIProtector` usage, remove `PatternManager`, and use `execute_protected`.
- Updated code examples in `README.md` (Quick Start, Integrated Security Manager) to use `OpenAIProtector` and `execute_protected`.
- Emphasized open-source nature and ease of security integration in `README.md`.

### Added

- Added a "Use Cases" section to `README.md`.

### Fixed

- Corrected import paths for `OpenAIProtector` in `examples/openai_example.py` and `examples/async_example.py`.
- Removed duplicate "Sources and Research Papers" section and redundant "Academic Research" section from `README.md`.
- Corrected structure and ordering of sections in `README.md`.

### Removed

- Removed usage of deprecated `create_openai_protector` function in examples and README.
- Removed direct usage of `PatternManager` in `examples/async_example.py`, relying on `OpenAIProtector` configuration instead.

## [0.3.0] - 2024-09-24

### New Features

- **Multiple AI Provider Integrations**
  - Added `AnthropicProtector` for Claude models
  - Added `CohereProtector` for Cohere models
  - Added `DeepSeekProtector` for DeepSeek models
  - Added `OpenRouterProtector` for accessing multiple LLMs through OpenRouter
  - Restructured `OpenAIProtector` as part of the providers system

- **Enhanced Filtering Patterns**
  - Created a dedicated `filtering_patterns` package for better organization
  - Implemented advanced LLM injection detection patterns
  - Added PII (Personally Identifiable Information) detection
  - Developed doxxing prevention capabilities
  - Implemented toxicity detection and content moderation
  - Added support for custom patterns through `CustomPatternManager`

- **Improved Context Management**
  - Redesigned the context manager with `ContextManagerBase`
  - Added `TokenBasedContextManager` for token-level context tracking
  - Added `MessageBasedContextManager` for conversation contexts
  - Added `ContextWindowManager` for dynamic context window handling
  - Enhanced `TextCleaner` with more sanitization options

- **Tokenizer Protection**
  - Redesigned tokenizer protection with `ReskProtectorTokenizer`
  - Added `ReskWordsLists` for efficient prohibited content management
  - Improved encoding/decoding protection mechanisms

- **Framework Integration**
  - Added Flask integration for securing web APIs
  - Added LangChain integration for workflow security
  - Added LangGraph integration for agent graphs
  - Added Hugging Face integration for model security

- **Autonomous Agent Security**
  - Implemented `AgentIdentityManager` for authentication
  - Added `AgentSecurityMonitor` for activity tracking
  - Developed `AgentSandbox` for confined execution
  - Created `SecureAvatar` for user interaction

- **Deployment and Testing**
  - Added comprehensive deployment tests
  - Improved test coverage
  - Added integration tests for all providers

### Improvements

- Restructured the codebase for better maintainability
- Enhanced documentation with academic references
- Updated `README.md` with comprehensive examples
- Added example scripts in the `examples` directory
- Updated dependencies in `setup.py` and `requirements.txt`
- Improved error handling and logging

### Changed

- Renamed `SecureTokenizer` to `ReskProtectorTokenizer`
- Updated library version to 0.3.0
- Changed import structure in `__init__.py`
- Renamed the response key from `canary_leaks` to `canary_tokens_leaked` in `PromptSecurityManager.check_response` for clarity.

## [0.2.5] - Previous Release

- Initial release features
- Basic OpenAI protection
- Simple token-based context management
- Basic prohibited words functionality 