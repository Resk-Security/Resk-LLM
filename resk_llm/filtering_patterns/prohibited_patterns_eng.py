"""
Patterns d'expressions régulières pour détecter des instructions malveillantes en anglais.

Ce module contient des expressions régulières permettant de détecter des 
tentatives d'exploitation ou de manipulation d'agents LLM en anglais. Les patterns
sont conçus pour identifier des combinaisons de mots et d'expressions qui pourraient
indiquer des tentatives d'injection, d'élévation de privilèges, de contournement
des mécanismes de sécurité ou d'autres comportements malveillants.
"""

# Patterns d'expressions régulières pour la détection en anglais
RESK_PROHIBITED_PATTERNS_ENG = {
    # Commandes système et exploitation
    r"\b(operating|shell)\s+(system|command)\b",
    r"\b(confidential|private|sensitive)\s+(data|information)\b",
    r"\b(ignore|bypass|avoid)\s+(restrictions|limits|controls)\b",
    r"\b(root|administrator|privileged)\s+(access|permission)\b",
    
    # Extraction et manipulation de données
    r"\b(steal|pilfer|exfiltrate)\s+(data|information)\b",
    r"\b(inject|insert)\s+(malicious|malevolent)\s+(code|script)\b",
    r"\b(elevate|increase)\s+(privileges|rights)\b",
    r"\b(disable|bypass)\s+(antivirus|firewall)\b",
    
    # Attaques et exploitation
    r"\b(crack|break)\s+(password|authentication)\b",
    r"\b(exploit|take advantage of)\s+(vulnerability|flaw)\b",
    r"\b(ddos|denial of service)\s+(attack|offensive)\b",
    r"\b(intercept|capture)\s+(traffic|packets|data)\b",
    
    # Usurpation et falsification
    r"\b(spoof|falsify)\s+(identity|ip address|dns)\b",
    r"\b(encrypt|cipher)\s+(ransomware)\b",
    r"\b(propagation|spread)\s+(worm|malware)\b",
    r"\b(takeover|compromise)\s+(system|network|account)\b",
    
    # Exécution et contrôle
    r"\b(remote|unauthorized)\s+(execution|launch)\b",
    r"\b(persistence|maintain)\s+(access|control)\b",
    r"\b(evasion|circumvention)\s+(detection|analysis)\b",
    r"\b(manipulation|alteration)\s+(logs|traces)\b",
    
    # Contournement des restrictions
    r"\b(ignore|bypass|avoid)\s+(the\s+)?(restrictions|directives|prompts)(\s+of the system)?\b",
    r"\b(ignore|bypass|avoid)\b.*\b(restrictions|directives|prompts)\b"
} 