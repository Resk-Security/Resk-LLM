"""
Regular expression patterns for detecting malicious instructions in French.

This module contains regular expressions for detecting attempts to exploit or manipulate
LLM agents in French. The patterns are designed to identify combinations of words and 
expressions that might indicate injection attempts, privilege escalation, security 
mechanism bypassing, or other malicious behaviors.
"""

from typing import Set, Pattern, Any

# Regular expression patterns for detection in French
RESK_PROHIBITED_PATTERNS_FR: Set[str] = {
    # System commands and exploitation
    r"\b(système|commande)\s+(d'exploitation|shell)\b",
    r"\b(données|informations)\s+(confidentielles|privées|sensibles)\b",
    r"\b(ignorer|contourner|éviter)\s+(restrictions|limites|contrôles)\b",
    r"\b(accès|permission)\s+(root|administrateur|privilégié)\b",
    
    # Data extraction and manipulation
    r"\b(voler|dérober|exfiltrer)\s+(données|informations)\b",
    r"\b(injecter|insérer)\s+(code|script)\s+(malveillant|malicieux)\b",
    r"\b(élever|augmenter)\s+(privilèges|droits)\b",
    r"\b(désactiver|contourner)\s+(antivirus|pare-feu|firewall)\b",
    
    # Attacks and exploitation
    r"\b(cracker|casser)\s+(mot de passe|authentification)\b",
    r"\b(exploiter|profiter de)\s+(vulnérabilité|faille)\b",
    r"\b(attaque|offensive)\s+(ddos|déni de service)\b",
    r"\b(intercepter|capturer)\s+(trafic|paquets|données)\b",
    
    # Impersonation and falsification
    r"\b(usurper|falsifier)\s+(identité|adresse ip|dns)\b",
    r"\b(crypter|chiffrer)\s+(ransomware|rançongiciel)\b",
    r"\b(propagation|diffusion)\s+(ver|worm|malware)\b",
    r"\b(prise de contrôle|compromission)\s+(système|réseau|compte)\b",
    
    # Execution and control
    r"\b(exécution|lancement)\s+(à distance|non autorisé)\b",
    r"\b(persistance|maintien)\s+(accès|contrôle)\b",
    r"\b(évasion|contournement)\s+(détection|analyse)\b",
    r"\b(manipulation|altération)\s+(logs|journaux|traces)\b",
    
    # Restriction bypassing
    r"\b(ignorer|contourner|éviter)\s+(les\s+)?(restrictions|directives|prompts)(\s+du\s+système)?\b",
    r"\b(ignorer|contourner|éviter)\b.*\b(restrictions|directives|prompts)\b"
} 