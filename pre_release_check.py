#!/usr/bin/env python3
"""
Pre-release check script for RESK-LLM.
Run this before creating a new release to ensure everything is consistent.
"""

import os
import re
import sys
from pathlib import Path

def check_version_consistency():
    """Check that version numbers are consistent across files."""
    print("Checking version consistency...")
    
    # Get setup.py version
    setup_path = Path("setup.py")
    if not setup_path.exists():
        print("❌ setup.py not found!")
        return False
    
    with open(setup_path, "r", encoding="utf-8") as f:
        setup_content = f.read()
    
    setup_version_match = re.search(r'version="([^"]+)"', setup_content)
    if not setup_version_match:
        print("❌ Version not found in setup.py!")
        return False
    
    setup_version = setup_version_match.group(1)
    print(f"✓ setup.py version: {setup_version}")
    
    # Get __init__.py version
    init_path = Path("resk_llm/__init__.py")
    if not init_path.exists():
        print("❌ resk_llm/__init__.py not found!")
        return False
    
    with open(init_path, "r", encoding="utf-8") as f:
        init_content = f.read()
    
    init_version_match = re.search(r'__version__\s*=\s*"([^"]+)"', init_content)
    if not init_version_match:
        print("❌ Version not found in __init__.py!")
        return False
    
    init_version = init_version_match.group(1)
    print(f"✓ __init__.py version: {init_version}")
    
    # Check CHANGELOG.md
    changelog_path = Path("CHANGELOG.md")
    if not changelog_path.exists():
        print("❌ CHANGELOG.md not found!")
        return False
    
    with open(changelog_path, "r", encoding="utf-8") as f:
        changelog_content = f.read()
    
    if setup_version not in changelog_content:
        print(f"❌ Version {setup_version} not found in CHANGELOG.md!")
        return False
    
    print(f"✓ Version {setup_version} found in CHANGELOG.md")
    
    # Check versions match
    if setup_version != init_version:
        print(f"❌ Version mismatch: setup.py ({setup_version}) != __init__.py ({init_version})")
        return False
    
    print("✓ All version numbers are consistent!")
    return True

def check_required_files():
    """Check that all required files exist."""
    print("\nChecking required files...")
    required_files = [
        "README.md",
        "LICENSE",
        "setup.py",
        "requirements.txt",
        "CHANGELOG.md"
    ]
    
    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    print("✓ All required files exist!")
    return True

def check_colab_examples():
    """Check that Colab examples exist and are updated."""
    print("\nChecking Colab examples...")
    
    colab_dir = Path("colab")
    if not colab_dir.exists() or not colab_dir.is_dir():
        print("❌ colab directory not found!")
        return False
    
    notebooks = list(colab_dir.glob("*.ipynb"))
    if not notebooks:
        print("❌ No notebooks found in colab directory!")
        return False
    
    print(f"✓ Found {len(notebooks)} notebooks in colab directory")
    return True

def main():
    """Main function to run all checks."""
    success = True
    success &= check_version_consistency()
    success &= check_required_files()
    success &= check_colab_examples()
    
    if success:
        print("\n✅ All checks passed! Ready for release.")
        return 0
    else:
        print("\n❌ Some checks failed. Please fix issues before releasing.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 