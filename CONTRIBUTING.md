# Contributing to Resk-LLM

Thank you for your interest in contributing to Resk-LLM! This document provides guidelines and instructions for contributing to this project.

## Getting Started

### Prerequisites

- Python 3.9 or 3.10
- Git

### Setting Up Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```
   git clone https://github.com/your-username/Resk-LLM.git
   cd Resk-LLM
   ```
3. Set up a virtual environment using UV:
   ```
   curl -LsSf https://astral.sh/uv/install.sh | sh
   uv venv
   ```
4. Install the development dependencies:
   ```
   uv pip install -e ".[dev,embeddings]"
   ```

## Development Workflow

1. Create a new branch for your feature or bug fix:
   ```
   git checkout -b feature/your-feature-name
   ```
   or
   ```
   git checkout -b fix/issue-description
   ```

2. Make your changes and commit them with a clear commit message:
   ```
   git commit -m "Add feature: description" 
   ```

3. Push your branch to your fork:
   ```
   git push origin feature/your-feature-name
   ```

4. Open a pull request from your fork to the main repository

## Code Style and Quality

- Follow PEP 8 style guidelines
- Run linters before submitting:
  ```
  flake8 ./resk_llm
  mypy --ignore-missing-imports resk_llm/
  ```
- Write tests for new features
- Run the test suite:
  ```
  pytest -v
  ```

## Pull Request Process

1. Ensure all tests, linting, and type checking pass
2. Update documentation if needed
3. Describe your changes in the PR description
4. Reference any related issues
5. Wait for review from maintainers

## Creating Releases

Releases are created automatically when a version tag is pushed:

```
git tag v1.0.0
git push origin v1.0.0
```

## License

By contributing to this project, you agree that your contributions will be licensed under the project's license.

## Questions?

If you have any questions about contributing, please open an issue for discussion. 