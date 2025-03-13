# Changelog

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

## [0.2.5] - Previous Release

- Initial release features
- Basic OpenAI protection
- Simple token-based context management
- Basic prohibited words functionality 