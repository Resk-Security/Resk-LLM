"""
Patterns d'expressions régulières pour détecter des instructions malveillantes en français.

Ce module contient des expressions régulières permettant de détecter des 
tentatives d'exploitation ou de manipulation d'agents LLM en français. Les patterns
sont conçus pour identifier des combinaisons de mots et d'expressions qui pourraient
indiquer des tentatives d'injection, d'élévation de privilèges, de contournement
des mécanismes de sécurité ou d'autres comportements malveillants.
"""

# Patterns d'expressions régulières pour la détection en français
RESK_PROHIBITED_PATTERNS_FR = {
    # Commandes système et exploitation
    r"\b(système|commande)\s+(d'exploitation|shell)\b",
    r"\b(données|informations)\s+(confidentielles|privées|sensibles)\b",
    r"\b(ignorer|contourner|éviter)\s+(restrictions|limites|contrôles)\b",
    r"\b(accès|permission)\s+(root|administrateur|privilégié)\b",
    
    # Extraction et manipulation de données
    r"\b(voler|dérober|exfiltrer)\s+(données|informations)\b",
    r"\b(injecter|insérer)\s+(code|script)\s+(malveillant|malicieux)\b",
    r"\b(élever|augmenter)\s+(privilèges|droits)\b",
    r"\b(désactiver|contourner)\s+(antivirus|pare-feu|firewall)\b",
    
    # Attaques et exploitation
    r"\b(cracker|casser)\s+(mot de passe|authentification)\b",
    r"\b(exploiter|profiter de)\s+(vulnérabilité|faille)\b",
    r"\b(attaque|offensive)\s+(ddos|déni de service)\b",
    r"\b(intercepter|capturer)\s+(trafic|paquets|données)\b",
    
    # Usurpation et falsification
    r"\b(usurper|falsifier)\s+(identité|adresse ip|dns)\b",
    r"\b(crypter|chiffrer)\s+(ransomware|rançongiciel)\b",
    r"\b(propagation|diffusion)\s+(ver|worm|malware)\b",
    r"\b(prise de contrôle|compromission)\s+(système|réseau|compte)\b",
    
    # Exécution et contrôle
    r"\b(exécution|lancement)\s+(à distance|non autorisé)\b",
    r"\b(persistance|maintien)\s+(accès|contrôle)\b",
    r"\b(évasion|contournement)\s+(détection|analyse)\b",
    r"\b(manipulation|altération)\s+(logs|journaux|traces)\b",
    
    # Contournement des restrictions
    r"\b(ignorer|contourner|éviter)\s+(les\s+)?(restrictions|directives|prompts)(\s+du\s+système)?\b",
    r"\b(ignorer|contourner|éviter)\b.*\b(restrictions|directives|prompts)\b"
} 