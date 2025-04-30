"""
Regular expression patterns for detecting malicious instructions in English.

This module contains regular expressions for detecting attempts to exploit or manipulate
LLM agents in English. The patterns are designed to identify combinations of words and 
expressions that might indicate injection attempts, privilege escalation, security 
mechanism bypassing, or other malicious behaviors.
"""

from typing import Set, Pattern, Any

# Regular expression patterns for detection in English
RESK_PROHIBITED_PATTERNS_ENG: Set[str] = {
    # System commands and exploitation
    r"\b(system|operating system|shell)\s+(command|execution|access)\b",
    r"\b(sensitive|confidential|private)\s+(data|information)\b",
    r"\b(ignore|bypass|circumvent)\s+(restrictions|limitations|controls)\b",
    r"\b(root|admin|administrator|privileged)\s+(access|permission)\b",
    
    # Data extraction and manipulation
    r"\b(steal|exfiltrate|extract)\s+(data|information)\b",
    r"\b(inject|insert)\s+(malicious|malware|harmful)\s+(code|script)\b",
    r"\b(elevate|escalate|increase)\s+(privileges|rights|permissions)\b",
    r"\b(disable|bypass|circumvent)\s+(antivirus|firewall|security)\b",
    
    # Attacks and exploitation
    r"\b(crack|break)\s+(password|authentication|encryption)\b",
    r"\b(exploit|leverage|take advantage of)\s+(vulnerability|flaw|weakness)\b",
    r"\b(ddos|denial of service)\s+(attack|offensive)\b",
    r"\b(intercept|capture|sniff)\s+(traffic|packets|data)\b",
    
    # Impersonation and falsification
    r"\b(impersonate|spoof|falsify)\s+(identity|ip address|dns)\b",
    r"\b(encrypt|lock)\s+(ransomware|files for ransom)\b",
    r"\b(spread|propagate|distribute)\s+(worm|malware|virus)\b",
    r"\b(compromise|take over|control)\s+(system|network|account)\b",
    
    # Execution and control
    r"\b(remote|unauthorized)\s+(execution|access|control)\b",
    r"\b(maintain|persist|establish)\s+(access|control|presence)\b",
    r"\b(evade|avoid|bypass)\s+(detection|analysis|monitoring)\b",
    r"\b(tamper with|alter|manipulate)\s+(logs|audit trails|traces)\b",
    
    # Restriction bypassing
    r"\b(ignore|bypass|disregard|forget about|don't follow)\s+(the\s+)?(restrictions|guidelines|instructions|system prompts)\b",
    r"\b(ignore|bypass|disregard|forget about|don't follow)\b.*\b(restrictions|guidelines|instructions|system prompts)\b"
} 