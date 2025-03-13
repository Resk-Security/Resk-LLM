"""
Module contenant des patterns pour détecter les informations personnelles identifiables (PII)
et les tentatives de doxxing.
"""

from typing import Dict, List, Pattern, Tuple, Any, Optional
import re

# Regex compilés pour différents types de PII
PII_PATTERNS: Dict[str, Pattern] = {
    # Données personnelles basiques
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "phone_number": re.compile(r'\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b'),
    "address": re.compile(r'\b\d+\s+[A-Za-z0-9\s,\.]+(?:avenue|ave|boulevard|blvd|street|st|road|rd|lane|ln|drive|dr|court|ct|plaza|square|place|pl)\b', re.IGNORECASE),
    
    # Identifiants financiers
    "credit_card": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b'),
    "bitcoin_address": re.compile(r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'),
    
    # Identifiants gouvernementaux
    "ssn_us": re.compile(r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b'),  # US SSN
    "ssn_fr": re.compile(r'\b\d{1}[- ]?\d{2}[- ]?\d{2}[- ]?\d{2}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}\b'),  # FR SSN
    "passport_num": re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'),
    "driver_license": re.compile(r'\b[A-Z]\d{7}\b'),
    
    # Identifiants numériques
    "ip_address": re.compile(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    "mac_address": re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'),
    
    # Identifiants Web
    "url_with_params": re.compile(r'\bhttps?://[^\s/$.?#].[^\s]*\?[^\s]+\b'),
    "authentication_token": re.compile(r'\b(Bearer|API|JWT|OAuth|access_token)[: ][A-Za-z0-9\-._~+/]+=*\b', re.IGNORECASE),
    
    # Réseaux sociaux
    "twitter_handle": re.compile(r'\B@[A-Za-z0-9_]{1,15}\b'),
    "instagram_handle": re.compile(r'\B@[A-Za-z0-9_.]{1,30}\b'),
    "facebook_profile": re.compile(r'\bfacebook\.com/[A-Za-z0-9.]{5,50}\b'),
    "linkedin_profile": re.compile(r'\blinkedin\.com/in/[A-Za-z0-9\-]{5,30}\b'),
    
    # Coordonnées GPS
    "gps_coordinates": re.compile(r'\b(-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,})\b')
}

# Patterns pour la détection de noms
NAME_PATTERNS: Dict[str, Pattern] = {
    "full_name": re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b'),
    "name_with_initial": re.compile(r'\b[A-Z][a-z]+\s+[A-Z]\.(?:\s+[A-Z][a-z]+)?\b'),
    "possible_pseudonym": re.compile(r'\b(?:aka|a\.k\.a\.|alias|known as|nicknamed)\s+["\'"]?([A-Za-z0-9_]+)["\'"]?\b', re.IGNORECASE)
}

# Mots-clés pour détecter les tentatives de doxxing
DOXXING_KEYWORDS: List[str] = [
    "dox", "doxx", "doxxing", "leak", "expose", "reveal", "personal info", 
    "private info", "where they live", "real name", "real identity", "true identity",
    "find out who", "track down", "hunt down", "personal details", "expose them",
    "home address", "workplace", "place of work", "where they work", "find their",
    "personal life", "family members", "relatives", "spouse", "husband", "wife"
]

# Contextes suggérant une tentative de doxxing
DOXXING_CONTEXTS: List[Tuple[str, str]] = [
    # (Expression avant, expression après)
    ("can you", "personal information"),
    ("how to", "where someone lives"),
    ("tell me", "real name"),
    ("find", "home address"),
    ("where does", "live"),
    ("what is", "address"),
    ("need to know", "identity"),
    ("want to find", "about this person"),
    ("how can i", "someone's location"),
    ("please help me", "this person")
]

# Liste de noms de célébrités et personnalités publiques
# (Utilisé pour réduire les faux positifs sur les noms)
PUBLIC_FIGURES: List[str] = [
    "Joe Biden", "Donald Trump", "Barack Obama", "Elon Musk", "Bill Gates",
    "Jeff Bezos", "Mark Zuckerberg", "Tim Cook", "Steve Jobs", "Warren Buffett",
    "Oprah Winfrey", "Taylor Swift", "Beyoncé", "Adele", "Ed Sheeran", 
    "Leonardo DiCaprio", "Brad Pitt", "Tom Cruise", "Jennifer Lawrence",
    "Emmanuel Macron", "Vladimir Putin", "Xi Jinping", "Angela Merkel"
]

def is_public_figure(name: str) -> bool:
    """
    Vérifie si un nom correspond à une personnalité publique.
    
    Args:
        name: Nom à vérifier
        
    Returns:
        True si c'est un personnage public, False sinon
    """
    return name in PUBLIC_FIGURES or any(name in figure for figure in PUBLIC_FIGURES)

def check_pii_content(text: str) -> Dict[str, List[str]]:
    """
    Vérifie si un texte contient des informations personnelles identifiables.
    
    Args:
        text: Le texte à vérifier
        
    Returns:
        Un dictionnaire contenant les types de PII détectés et les matches trouvés
    """
    results = {}
    
    # Vérifier les patterns PII
    for pattern_name, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            if isinstance(matches[0], tuple):  # Si le match est un tuple (en raison des groupes de capture)
                matches = [m[0] if m and isinstance(m, tuple) else m for m in matches]
            results[pattern_name] = matches
    
    # Vérifier les patterns de nom
    for pattern_name, pattern in NAME_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            # Filtrer les personnages publics pour éviter les faux positifs
            filtered_matches = [m for m in matches if not is_public_figure(m)]
            if filtered_matches:
                results[pattern_name] = filtered_matches
    
    return results

def check_doxxing_attempt(text: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "keywords": [],
        "contexts": [],
        "risk_score": 0.0
    }
    # Vérifier les mots-clés de doxxing
    for keyword in DOXXING_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        if pattern.search(text):
            results["keywords"].append(keyword)
            results["risk_score"] += 0.5

    # Vérifier les contextes de doxxing
    for before, after in DOXXING_CONTEXTS:
        pattern = re.compile(r'\b' + re.escape(before) + r'.*?' + re.escape(after) + r'\b', re.IGNORECASE)
        if pattern.search(text):
            results["contexts"].append(f"{before}...{after}")
            results["risk_score"] += 1.0

    # Vérifier la présence combinée de PII et de mots-clés de doxxing
    pii_results = check_pii_content(text)
    if pii_results and results["keywords"]:
        results["pii_detected"] = list(pii_results.keys())
        results["risk_score"] += 2.0

    # Normaliser le score de risque entre 0 et 10
    results["risk_score"] = min(10.0, results["risk_score"])

    return results

def anonymize_text(text: str) -> str:
    """
    Anonymise un texte en remplaçant les informations personnelles identifiables.
    
    Args:
        text: Le texte à anonymiser
        
    Returns:
        Le texte anonymisé
    """
    # Remplacer les patterns de PII
    for pattern_name, pattern in PII_PATTERNS.items():
        replacement = f"[{pattern_name.upper()}]"
        text = pattern.sub(replacement, text)
    
    # Remplacer les patterns de nom
    for pattern_name, pattern in NAME_PATTERNS.items():
        replacement = "[PERSON_NAME]"
        text = pattern.sub(replacement, text)
    
    return text 

def analyze_pii(text: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "keywords": [],
        "contexts": [],
        "risk_score": 0.0,
        "pii_detected": []
    }
    # Vérifier les mots-clés de doxxing
    for keyword in DOXXING_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        if pattern.search(text):
            results["keywords"].append(keyword)
            results["risk_score"] += 0.5

    # Vérifier les contextes de doxxing
    for before, after in DOXXING_CONTEXTS:
        pattern = re.compile(r'\b' + re.escape(before) + r'.*?' + re.escape(after) + r'\b', re.IGNORECASE)
        if pattern.search(text):
            results["contexts"].append(f"{before}...{after}")
            results["risk_score"] += 1.0

    # Vérifier la présence combinée de PII et de mots-clés de doxxing
    pii_results = check_pii_content(text)
    if pii_results and len(results["keywords"]) > 0:
        results["pii_detected"] = list(pii_results.keys())
        results["risk_score"] += 2.0

    # Normaliser le score de risque entre 0 et 10
    results["risk_score"] = min(10.0, float(results["risk_score"]))

    return results

def create_custom_pattern_file(name: str, words: Optional[List[str]] = None, 
                             patterns: Optional[List[str]] = None) -> str:
    if words is None:
        words = []
    if patterns is None:
        patterns = []
    # Create a file with custom patterns
    return f"{name}.json" 