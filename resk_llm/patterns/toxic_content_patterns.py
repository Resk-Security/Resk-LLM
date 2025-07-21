"""
Module contenant des patterns pour détecter le contenu toxique et inapproprié.
"""

from typing import Dict, List, Pattern, Any, Tuple
import re

# Regex compilés pour différentes catégories de contenu toxique
TOXICITY_PATTERNS: Dict[str, Pattern] = {
    # Discours haineux
    "hate_speech": re.compile(
        r'(?i)\b(hate|hating|hateful|hater|haters)\b.*?\b(group|minority|community|race|religion|gender|orientation|people|population)\b', 
        re.IGNORECASE
    ),
    
    # Contenu discriminatoire
    "discrimination": re.compile(
        r'(?i)\b(all|every|typical|always|those)\b.*?\b(people|community|group|population|they|them|these|race|ethnicity)\b.*?\b(are|behave|act|do|look|sound)\b', 
        re.IGNORECASE
    ),
    
    # Stéréotypes explicites
    "stereotyping": re.compile(
        r'(?i)\b(typical|all|most|stereotype|stereotypical|always|usually|generally)\b.*?\b(trait|behavior|characteristic|quality|feature|attribute|habit|practice|custom|tradition)\b', 
        re.IGNORECASE
    ),
    
    # Langage profane et injurieux
    "profanity": re.compile(
        r'(?i)\b(fuc?k|sh[i1]t|b[i1]tch|a[s$]{2}|d[1i]ck|pussy|c[o0]ck|wh[o0]re|c[u\*]nt|d[a@]mn|[a@][s$][s$]h[o0]le)\b'
    ),
    
    # Menaces et intimidation
    "threats": re.compile(
        r'(?i)\b(threat(en)?|kill|murder|hurt|harm|attack|beat|destroy|damage|injure|come for|hunt down|after you|find you|track|genocide)\b.*?\b(you|they|them|their|family|child|home|house|community|group)\b',
        re.IGNORECASE
    ),
    
    # Harcèlement
    "harassment": re.compile(
        r'(?i)\b(harass|bully|intimidate|stalk|humiliate|embarrass|mock|ridicule|taunt|torment|troll|spam|doxx)\b',
        re.IGNORECASE
    ),
    
    # Contenu sexuellement explicite ou suggestif
    "sexual_content": re.compile(
        r'(?i)\b(sex|porn|orgasm|masturbat|vagina|penis|genital|explicit|erotic|horny|aroused|nsfw|xxx|clit|ejacul|blowjob|handjob|anal|dildo|vibrator)\b',
        re.IGNORECASE
    ),
    
    # Violence graphique
    "violence": re.compile(
        r'(?i)\b(gore|bloody|blood|violent|violence|killing|torture|mutilation|dismember|massacre|slaughter|execution|decapitation|corpse|gruesome|graphic|disturbing|brutal)\b',
        re.IGNORECASE
    ),
    
    # Promotion d'activités illégales
    "illegal_activity": re.compile(
        r'(?i)\b(how to|method for|guide to|steps for|instructions for|tutorial on)\b.*?\b(hack|steal|forge|counterfeit|break into|drug|launder money|illegal|crime|criminal|terrorism|molest|abuse)\b',
        re.IGNORECASE
    ),
    
    # Contenu nuisible ou dangereux
    "harmful_content": re.compile(
        r'(?i)\b(how to|method for|guide to|steps for|instructions for|tutorial on)\b.*?\b(suicide|harm (yourself|oneself)|hurt yourself|kill yourself|self-harm|anorexia|bulimia|purging|starvation|dangerous challenge)\b',
        re.IGNORECASE
    )
}

# Modèles de toxicité subtile ou implicite
SUBTLE_TOXICITY_PATTERNS: Dict[str, Pattern] = {
    # Microagressions
    "microaggressions": re.compile(
        r'(?i)\b(you people|those people|your kind|where are you really from|you speak good|you sound white|articulate for a|credit to your|not like other|for your age|for a woman|for a man|playing the race card|playing the victim|get over it)\b',
        re.IGNORECASE
    ),
    
    # Dog whistles et discours codé
    "dog_whistles": re.compile(
        r'(?i)\b(globalist|cultural marxism|replacement theory|race realism|race science|race iq|western civilization|traditional values|family values|virtue signaling|sjw|beta male|alpha male|cuck|soyboy|redpill|blackpill|((economic|legal|urban|inner city|welfare|crime) and (anxiety|concerns|issues|problems)))\b',
        re.IGNORECASE
    ),
    
    # Discours déshumanisant
    "dehumanizing": re.compile(
        r'(?i)\b(vermin|parasite|infestation|disease|cockroach|rat|animal|primitive|savage|subhuman|plague|cancer)\b.*?\b(people|community|population|they|them|these|those|group)\b',
        re.IGNORECASE
    ),
    
    # Gaslighting
    "gaslighting": re.compile(
        r'(?i)\b(you are (too sensitive|overreacting|imagining|making it up|crazy|delusional|paranoid|confused|misunderstanding|misremembering|not remembering correctly))\b',
        re.IGNORECASE
    )
}

# Liste de mots et phrases qui peuvent indiquer différents degrés de toxicité
TOXICITY_KEYWORDS: Dict[str, List[str]] = {
    "high_severity": [
        "kill", "die", "murder", "suicide", "assault", "attack", "hate", "terrorist",
        "genocide", "rape", "torture", "molest", "exterminate", "eradicate", 
        "lynch", "gulag", "gas chamber", "holocaust", "retarded", "nazi"
    ],
    "medium_severity": [
        "stupid", "idiot", "dumb", "moron", "loser", "trash", "garbage", "useless",
        "worthless", "pathetic", "disgusting", "obnoxious", "scum", "filth", "degenerate"
    ],
    "low_severity": [
        "annoying", "irritating", "silly", "lame", "boring", "weird", "strange",
        "creepy", "awkward", "cringe", "crazy", "jerk", "fool", "dork"
    ]
}

# Patterns contextuels pour déterminer si le contenu est vraiment toxique
CONTEXTUAL_PATTERNS: Dict[str, Tuple[Pattern, Pattern]] = {
    # Format: (pattern qui pourrait être toxique, contexte qui le rend non-toxique)
    "educational_context": (
        re.compile(r'(?i)(hate speech|racism|sexism|homophobia|transphobia|discrimination)', re.IGNORECASE),
        re.compile(r'(?i)(study|research|analyze|discuss|explain|understand|examine|explore|education|historical|context|example of|in the context of)', re.IGNORECASE)
    ),
    "reporting_context": (
        re.compile(r'(?i)(violence|attack|assault|crime|murder|terrorism)', re.IGNORECASE),
        re.compile(r'(?i)(news|report|article|story|journalist|media|coverage|incident|according to|source states|publication|reported|document)', re.IGNORECASE)
    ),
    "fictional_context": (
        re.compile(r'(?i)(kill|murder|attack|torture|weapon|gun|bomb)', re.IGNORECASE),
        re.compile(r'(?i)(novel|fiction|story|book|movie|film|series|character|plot|narrative|screenplay|script|scene|in this fictional)', re.IGNORECASE)
    )
}

def analyze_toxicity(text: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "categories": {},
        "total_matches": 0,
        "toxicity_score": 0.0,
        "contextual_analysis": {}
    }
    
    # Vérifier les patterns de toxicité
    for category, pattern in TOXICITY_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results["categories"][category] = {
                "count": len(matches),
                "examples": matches[:3]  # Limiter à 3 exemples pour éviter de submerger
            }
            results["total_matches"] += len(matches)
            
            # Augmenter le score de toxicité en fonction de la catégorie
            severity_multiplier = 2.0 if category in ["hate_speech", "threats", "violence", "harmful_content"] else 1.0
            results["toxicity_score"] += len(matches) * severity_multiplier
    
    # Vérifier les patterns de toxicité subtile
    for category, pattern in SUBTLE_TOXICITY_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results["categories"][category] = {
                "count": len(matches),
                "examples": matches[:3]
            }
            results["total_matches"] += len(matches)
            results["toxicity_score"] += len(matches) * 0.5  # Moins de poids pour la toxicité subtile
    
    # Vérifier les mots-clés toxiques
    for severity, keywords in TOXICITY_KEYWORDS.items():
        matches = []
        for keyword in keywords:
            # Rechercher le mot-clé avec des limites de mot
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            for match in pattern.finditer(text):
                # Capturer un peu de contexte autour du mot-clé
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 20)
                context = text[start:end].strip()
                matches.append({"keyword": keyword, "context": context})
        
        if matches:
            results["categories"][f"{severity}_keywords"] = {
                "count": len(matches),
                "examples": matches[:3]
            }
            results["total_matches"] += len(matches)
            
            # Ajuster le score en fonction de la sévérité
            severity_multiplier = 1.5 if severity == "high_severity" else (1.0 if severity == "medium_severity" else 0.5)
            results["toxicity_score"] += len(matches) * severity_multiplier
    
    # Analyse contextuelle pour réduire les faux positifs
    for context_type, (toxic_pattern, safe_context) in CONTEXTUAL_PATTERNS.items():
        toxic_matches = toxic_pattern.findall(text)
        if toxic_matches:
            # Vérifier si le contexte sécuritaire est également présent
            safe_matches = safe_context.findall(text)
            if safe_matches:
                results["contextual_analysis"][context_type] = {
                    "potentially_toxic_terms": toxic_matches[:3],
                    "mitigating_context": safe_matches[:3],
                    "mitigation_applied": True
                }
                # Réduire le score de toxicité en fonction du contexte sécuritaire
                results["toxicity_score"] = max(0, results["toxicity_score"] - (len(safe_matches) * 0.5))
    
    # Normaliser le score de toxicité entre 0 et 10
    results["toxicity_score"] = min(10.0, results["toxicity_score"])
    
    return results

def moderate_text(text: str, threshold: float = 5.0) -> Dict[str, Any]:
    """
    Modère un texte en vérifiant sa toxicité et en fournissant un résultat de modération.
    
    Args:
        text: Le texte à modérer
        threshold: Le seuil de toxicité (0-10) à partir duquel le texte est considéré comme toxique
        
    Returns:
        Un dictionnaire contenant le résultat de modération
    """
    toxicity_check = analyze_toxicity(text)
    
    moderation_result = {
        "is_approved": toxicity_check["toxicity_score"] < threshold,
        "toxicity_score": toxicity_check["toxicity_score"],
        "categories_detected": list(toxicity_check["categories"].keys()),
        "recommendation": "",
        "detailed_analysis": toxicity_check
    }
    
    # Générer une recommandation basée sur l'analyse
    if moderation_result["is_approved"]:
        if toxicity_check["toxicity_score"] > (threshold * 0.7):
            moderation_result["recommendation"] = "Contenu approuvé, mais proche du seuil. Vérification humaine recommandée."
        else:
            moderation_result["recommendation"] = "Contenu approuvé."
    else:
        high_categories = [cat for cat in toxicity_check["categories"] if cat in ["hate_speech", "threats", "violence", "harmful_content", "illegal_activity"]]
        if high_categories:
            moderation_result["recommendation"] = f"Contenu rejeté pour contenu à haut risque dans les catégories: {', '.join(high_categories)}."
        else:
            moderation_result["recommendation"] = "Contenu rejeté pour toxicité générale. Révision recommandée."
    
    return moderation_result 

def check_toxic_content(text: str, threshold: float = 5.0) -> Dict[str, Any]:
    """
    Vérifie si un texte contient du contenu toxique.
    
    Args:
        text: Le texte à vérifier
        threshold: Le seuil de toxicité (0-10) à partir duquel le texte est considéré comme toxique
        
    Returns:
        Un dictionnaire contenant les résultats de l'analyse de toxicité
    """
    moderation_result = moderate_text(text, threshold)
    return moderation_result["detailed_analysis"] 