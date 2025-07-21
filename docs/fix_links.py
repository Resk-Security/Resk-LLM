#!/usr/bin/env python3
"""
Script to fix broken links in the documentation.
This script corrects common link issues in the README and other documentation files.
"""

import re
import os
from pathlib import Path

def fix_readme_links():
    """Fix broken links in README.md"""
    readme_path = Path("../README.md")
    
    if not readme_path.exists():
        print("README.md not found")
        return
    
    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix broken GitHub links
    replacements = {
        # Fix GitHub organization links
        r'https://github\.com/ReskLLM/Resk-LLM': 'https://github.com/Resk-Security/Resk-LLM',
        
        # Fix documentation links
        r'https://resk\.readthedocs\.io/en/latest/index\.html': 'https://resk-llm.readthedocs.io/',
        
        # Fix badge links
        r'https://img\.shields\.io/github/issues/ReskLLM/Resk-LLM\.svg': 'https://img.shields.io/github/issues/Resk-Security/Resk-LLM.svg',
        r'https://img\.shields\.io/github/stars/ReskLLM/Resk-LLM\.svg': 'https://img.shields.io/github/stars/Resk-Security/Resk-LLM.svg',
        
        # Fix LICENSE link
        r'https://github\.com/ReskLLM/Resk-LLM/blob/main/LICENSE': 'https://github.com/Resk-Security/Resk-LLM/blob/main/LICENSE.txt',
    }
    
    for old_pattern, new_pattern in replacements.items():
        content = re.sub(old_pattern, new_pattern, content)
    
    # Write back the fixed content
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Fixed links in README.md")

def create_linkcheck_ignore():
    """Create a linkcheck ignore file to skip problematic links"""
    ignore_content = """# Links to ignore during linkcheck
# These are external links that may be temporarily unavailable

# GitHub rate limiting
https://github.com/Resk-Security/Resk-LLM/commits/main

# External services that may be slow
https://pepy.tech/project/resk-llm
https://pepy.tech/projects/resk-llm

# Documentation that may not exist yet
https://resk.readthedocs.io/en/latest/index.html

# GitHub badges that may be rate limited
https://img.shields.io/github/issues/Resk-Security/Resk-LLM.svg
https://img.shields.io/github/stars/Resk-Security/Resk-LLM.svg
"""
    
    with open("linkcheck_ignore.txt", 'w') as f:
        f.write(ignore_content)
    
    print("Created linkcheck_ignore.txt")

if __name__ == "__main__":
    fix_readme_links()
    create_linkcheck_ignore()
    print("Link fixing completed!") 