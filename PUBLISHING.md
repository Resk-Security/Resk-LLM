# Publishing RESK-LLM

This guide explains how to publish a new version of RESK-LLM to PyPI and GitHub.

## Preparation

1. **Update Translations**: Make sure all code comments, docstrings, and error messages are translated to English.

2. **Update Version Number**: Update the version number in the following files:
   ```bash
   # In setup.py
   setup(
       name="resk-llm",
       version="0.2.5",  # Update this version
       # ...
   )
   
   # In resk_llm/__init__.py
   __version__ = "0.2.5"  # Update this version
   ```

3. **Update CHANGELOG.md**: Document your changes in the CHANGELOG.md file:
   ```markdown
   ## [0.2.5] - YYYY-MM-DD
   
   ### Added
   - Added Flask integration for securing web APIs
   - Added FastAPI integration for securing asynchronous APIs
   - Added agent security controls for autonomous LLM agents
   - Added custom pattern management API
   
   ### Changed
   - Improved filtering patterns with better detection for obfuscation
   - Enhanced context management for more efficient token usage
   - Updated documentation with examples for new features
   - Translated code comments and docstrings to English
   
   ### Fixed
   - Fixed issue with nested sanitization in JSON objects
   - Fixed token counting in large context windows
   ```

4. **Update Colab Examples**: Make sure all Colab notebooks are updated with the new features.

5. **Run Pre-Release Check**: Run the pre-release check script to ensure everything is consistent:
   ```bash
   python pre_release_check.py
   ```

## Testing

1. **Local Testing**: Install the package locally and test it:
   ```bash
   pip install -e .
   pytest
   ```

2. **Build Test**: Make sure the package builds correctly:
   ```bash
   pip install build
   python -m build
   ```

## Publishing

### Option 1: Manual Publishing

1. **Build the Package**:
   ```bash
   python -m build
   ```

2. **Upload to PyPI**:
   ```bash
   pip install twine
   twine check dist/*
   twine upload dist/*
   ```

3. **Create a GitHub Release**:
   - Create a new tag: `git tag v0.2.5`
   - Push the tag: `git push origin v0.2.5`
   - Go to GitHub and create a release from this tag

### Option 2: Automated Publishing (Recommended)

1. **Commit and Push Your Changes**:
   ```bash
   git add .
   git commit -m "Release v0.2.5: Added Flask and FastAPI integrations"
   git push origin main
   ```

2. **Create and Push a Tag**:
   ```bash
   git tag v0.2.5
   git push origin v0.2.5
   ```

3. **Monitor GitHub Actions**: The GitHub workflow will:
   - Run tests on multiple Python versions
   - Run the pre-release check
   - Build the package
   - Publish to PyPI
   - Create a GitHub release

## Post-Release

1. **Verify PyPI Release**: Check that your package is available on PyPI: https://pypi.org/project/resk-llm/

2. **Verify Documentation**: Make sure the documentation reflects the new version.

3. **Notify Users**: Announce the new release on relevant channels.

## Troubleshooting

### Common Issues

1. **Version Already Exists on PyPI**: You cannot upload a package with the same version number twice to PyPI. You must increment the version number.

2. **Missing PyPI API Token**: Make sure the `PYPI_API_TOKEN` secret is set in your GitHub repository.

3. **Workflow Failures**: If the GitHub workflow fails, check the logs to identify the issue.

### Getting Help

If you encounter issues, please:

1. Check the GitHub Actions logs
2. Consult the PyPI documentation: https://packaging.python.org/tutorials/packaging-projects/
3. Reach out to the project maintainers 