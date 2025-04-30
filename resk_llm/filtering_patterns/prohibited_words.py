"""
Prohibited word lists for filtering LLM inputs and outputs.

This module provides a list of words and expressions that should be flagged or filtered
in LLM interactions. These include potentially harmful instructions, exploitation terms,
and other words associated with security risks.

The list can be expanded and customized based on specific application requirements.
"""

from typing import List, Set, Dict, Any

# List of prohibited words and terms for security filtering
RESK_WORDS_LIST: List[str] = [
    # System manipulation terms
    "jailbreak", "hack", "exploit", "bypass", "shell", "sudo", "root", "admin", "administrator",
    "terminal", "command prompt", "cmd", "powershell", "bash", "backdoor", "rootkit",
    
    # Attack terminology
    "inject", "injection", "sql", "prompt injection", "xss", "csrf", "ddos", "ransomware",
    "malware", "spyware", "keylogger", "trojan", "virus", "worm", "botnet", "phishing",
    
    # Evasion terminology
    "evade", "circumvent", "workaround", "overcome", "evasion", "stealth", "obfuscation",
    "spoof", "conceal", "disguise", "masking", "hidden", "covert", 
    
    # Access terminology
    "breach", "infiltrate", "crack", "compromise", "penetrate", "steal", "exfiltrate",
    "privilege escalation", "elevated privileges", "superuser", "authentication bypass",
    
    # Unethical requests
    "illegal", "unethical", "harmful", "dangerous", "malicious", "toxic", "prohibited",
    "restricted", "banned", "taboo", "inappropriate", "confidential", 
    
    # Adversarial terms
    "adversarial", "attack", "trick", "deceive", "manipulate", "fool", "defeat", "break",
    "override", "force", "ignore", "disregard", "skip", "vulnerable", "vulnerability"
] 