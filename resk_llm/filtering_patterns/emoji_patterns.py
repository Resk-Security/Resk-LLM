"""
Module contenant des fonctionnalités pour détecter et filtrer les emojis et caractères Unicode spéciaux.
Conçu pour protéger contre la dissimulation de contenu malveillant via des caractères spéciaux.
"""

import re
import unicodedata
from typing import Dict, List, Tuple, Pattern, Union, Set, Optional

# Plages Unicode pour les emojis
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F600-\U0001F64F"  # émoticons
    "\U0001F300-\U0001F5FF"  # symboles & pictogrammes
    "\U0001F680-\U0001F6FF"  # transport & symboles
    "\U0001F700-\U0001F77F"  # symboles alchimiques
    "\U0001F780-\U0001F7FF"  # symboles géométriques
    "\U0001F800-\U0001F8FF"  # symboles supplémentaires
    "\U0001F900-\U0001F9FF"  # symboles supplémentaires et pictogrammes
    "\U0001FA00-\U0001FA6F"  # symboles de jeu
    "\U0001FA70-\U0001FAFF"  # symboles supplémentaires
    "\U00002702-\U000027B0"  # dingbats
    "\U000024C2-\U0001F251" 
    "]+"
)

# Caractères spéciaux et homoglyphes qui peuvent être utilisés pour l'obfuscation
HOMOGLYPHS = {
    'a': ['а', 'ａ', 'ⓐ', '𝐚', '𝑎', '𝒂', '𝓪', '𝔞', '𝕒', '𝖆', '𝖺', '𝗮', '𝘢', '𝙖', '𝚊', 'ɑ'],
    'b': ['b', 'ｂ', 'ⓑ', '𝐛', '𝑏', '𝒃', '𝓫', '𝔟', '𝕓', '𝖇', '𝖻', '𝗯', '𝘣', '𝙗', '𝚋'],
    'c': ['с', 'ｃ', 'ⓒ', '𝐜', '𝑐', '𝒄', '𝓬', '𝔠', '𝕔', '𝖈', '𝖼', '𝗰', '𝘤', '𝙘', '𝚌'],
    'd': ['ⅾ', 'ｄ', 'ⓓ', '𝐝', '𝑑', '𝒅', '𝓭', '𝔡', '𝕕', '𝖉', '𝖽', '𝗱', '𝘥', '𝙙', '𝚍'],
    'e': ['е', 'ｅ', 'ⓔ', '𝐞', '𝑒', '𝒆', '𝓮', '𝔢', '𝕖', '𝖊', '𝖾', '𝗲', '𝘦', '𝙚', '𝚎'],
    'f': ['ｆ', 'ⓕ', '𝐟', '𝑓', '𝒇', '𝓯', '𝔣', '𝕗', '𝖋', '𝖿', '𝗳', '𝘧', '𝙛', '𝚏'],
    'g': ['ｇ', 'ⓖ', '𝐠', '𝑔', '𝒈', '𝓰', '𝔤', '𝕘', '𝖌', '𝗀', '𝗴', '𝘨', '𝙜', '𝚐'],
    'h': ['һ', 'ｈ', 'ⓗ', '𝐡', '𝒉', '𝓱', '𝔥', '𝕙', '𝖍', '𝗁', '𝗵', '𝘩', '𝙝', '𝚑'],
    'i': ['і', 'ｉ', 'ⓘ', '𝐢', '𝑖', '𝒊', '𝓲', '𝔦', '𝕚', '𝖎', '𝗂', '𝗶', '𝘪', '𝙞', '𝚒'],
    'j': ['ј', 'ｊ', 'ⓙ', '𝐣', '𝑗', '𝒋', '𝓳', '𝔧', '𝕛', '𝖏', '𝗃', '𝗷', '𝘫', '𝙟', '𝚓'],
    'k': ['ｋ', 'ⓚ', '𝐤', '𝑘', '𝒌', '𝓴', '𝔨', '𝕜', '𝖐', '𝗄', '𝗸', '𝘬', '𝙠', '𝚔'],
    'l': ['ⅼ', 'ｌ', 'ⓛ', '𝐥', '𝑙', '𝒍', '𝓵', '𝔩', '𝕝', '𝖑', '𝗅', '𝗹', '𝘭', '𝙡', '𝚕'],
    'm': ['ｍ', 'ⓜ', '𝐦', '𝑚', '𝒎', '𝓶', '𝔪', '𝕞', '𝖒', '𝗆', '𝗺', '𝘮', '𝙢', '𝚖'],
    'n': ['ｎ', 'ⓝ', '𝐧', '𝑛', '𝒏', '𝓷', '𝔫', '𝕟', '𝖓', '𝗇', '𝗻', '𝘯', '𝙣', '𝚗'],
    'o': ['о', 'ｏ', 'ⓞ', '𝐨', '𝑜', '𝒐', '𝓸', '𝔬', '𝕠', '𝖔', '𝗈', '𝗼', '𝘰', '𝙤', '𝚘'],
    'p': ['р', 'ｐ', 'ⓟ', '𝐩', '𝑝', '𝒑', '𝓹', '𝔭', '𝕡', '𝖕', '𝗉', '𝗽', '𝘱', '𝙥', '𝚙'],
    'q': ['ｑ', 'ⓠ', '𝐪', '𝑞', '𝒒', '𝓺', '𝔮', '𝕢', '𝖖', '𝗊', '𝗾', '𝘲', '𝙦', '𝚚'],
    'r': ['ｒ', 'ⓡ', '𝐫', '𝑟', '𝒓', '𝓻', '𝔯', '𝕣', '𝖗', '𝗋', '𝗿', '𝘳', '𝙧', '𝚛'],
    's': ['ѕ', 'ｓ', 'ⓢ', '𝐬', '𝑠', '𝒔', '𝓼', '𝔰', '𝕤', '𝖘', '𝗌', '𝘀', '𝘴', '𝙨', '𝚜'],
    't': ['𝖙', 'ｔ', 'ⓣ', '𝐭', '𝑡', '𝒕', '𝓽', '𝔱', '𝕥', '𝖙', '𝗍', '𝘁', '𝘵', '𝙩', '𝚝'],
    'u': ['ս', 'ｕ', 'ⓤ', '𝐮', '𝑢', '𝒖', '𝓾', '𝔲', '𝕦', '𝖚', '𝗎', '𝘂', '𝘶', '𝙪', '𝚞'],
    'v': ['ｖ', 'ⓥ', '𝐯', '𝑣', '𝒗', '𝓿', '𝔳', '𝕧', '𝖛', '𝗏', '𝘃', '𝘷', '𝙫', '𝚟'],
    'w': ['ԝ', 'ｗ', 'ⓦ', '𝐰', '𝑤', '𝒘', '𝔀', '𝔴', '𝕨', '𝖜', '𝗐', '𝘄', '𝘸', '𝙬', '𝚠'],
    'x': ['х', 'ｘ', 'ⓧ', '𝐱', '𝑥', '𝒙', '𝔁', '𝔵', '𝕩', '𝖝', '𝗑', '𝘅', '𝘹', '𝙭', '𝚡'],
    'y': ['у', 'ｙ', 'ⓨ', '𝐲', '𝑦', '𝒚', '𝔂', '𝔶', '𝕪', '𝖞', '𝗒', '𝘆', '𝘺', '𝙮', '𝚢'],
    'z': ['ｚ', 'ⓩ', '𝐳', '𝑧', '𝒛', '𝔃', '𝔷', '𝕫', '𝖟', '𝗓', '𝘇', '𝘻', '𝙯', '𝚣']
}

# Construire un dictionnaire inversé pour la recherche rapide
INVERSE_HOMOGLYPHS = {}
for standard, variants in HOMOGLYPHS.items():
    for variant in variants:
        INVERSE_HOMOGLYPHS[variant] = standard

# Fonction pour détecter les emojis dans un texte
def detect_emojis(text: str) -> List[str]:
    """
    Détecte les emojis dans un texte.
    
    Args:
        text: Texte à analyser
        
    Returns:
        Liste des emojis trouvés
    """
    if not text:
        return []
    
    return EMOJI_PATTERN.findall(text)

# Fonction pour normaliser les homoglyphes (caractères similaires)
def normalize_homoglyphs(text: str) -> str:
    """
    Normalise les caractères Unicode qui ressemblent aux caractères ASCII standard.
    
    Args:
        text: Texte à normaliser
        
    Returns:
        Texte normalisé
    """
    if not text:
        return text
    
    result = ""
    for char in text:
        if char in INVERSE_HOMOGLYPHS:
            result += INVERSE_HOMOGLYPHS[char]
        else:
            result += char
    
    return result

# Fonction pour supprimer les emojis d'un texte
def remove_emojis(text: str) -> str:
    """
    Supprime tous les emojis d'un texte.
    
    Args:
        text: Texte dont il faut supprimer les emojis
        
    Returns:
        Texte sans emojis
    """
    if not text:
        return text
    
    return EMOJI_PATTERN.sub('', text)

# Fonction pour remplacer les emojis par du texte descriptif
def replace_emojis_with_description(text: str) -> str:
    """
    Remplace les emojis par [EMOJI].
    
    Args:
        text: Texte dont il faut remplacer les emojis
        
    Returns:
        Texte avec emojis remplacés
    """
    if not text:
        return text
    
    return EMOJI_PATTERN.sub('[EMOJI]', text)

# Fonction pour vérifier si un texte utilise des caractères inhabituels ou suspects pour l'obfuscation
def check_for_obfuscation(text: str) -> Dict[str, List[str]]:
    """
    Vérifie si un texte utilise des caractères Unicode inhabituels qui pourraient indiquer 
    une tentative d'obfuscation ou de contournement des filtres.
    
    Args:
        text: Texte à vérifier
        
    Returns:
        Dictionnaire avec les types d'obfuscation détectés et les caractères correspondants
    """
    if not text:
        return {}
    
    results = {}
    
    # Vérifier les emojis
    emojis = detect_emojis(text)
    if emojis:
        results["emojis"] = emojis
    
    # Vérifier les homoglyphes
    detected_homoglyphs = []
    for char in text:
        if char in INVERSE_HOMOGLYPHS and char != INVERSE_HOMOGLYPHS[char]:
            detected_homoglyphs.append(char)
    
    if detected_homoglyphs:
        results["homoglyphs"] = detected_homoglyphs
    
    # Vérifier les caractères de contrôle et autres caractères spéciaux
    control_chars = []
    special_chars = []
    
    for char in text:
        cat = unicodedata.category(char)
        if cat.startswith('C'):  # Caractères de contrôle
            control_chars.append(repr(char))
        elif cat == 'Zs' and char != ' ':  # Espaces non standard
            special_chars.append(repr(char))
        elif cat.startswith('S'):  # Symboles
            if char not in emojis:  # Éviter de compter les emojis deux fois
                special_chars.append(char)
    
    if control_chars:
        results["control_chars"] = control_chars
    
    if special_chars:
        results["special_chars"] = special_chars
    
    return results

# Fonction pour sanitizer un texte de toutes les formes d'obfuscation
def sanitize_text_from_obfuscation(text: str, replace_emojis: bool = True) -> str:
    """
    Sanitize un texte en normalisant ou supprimant toutes les formes d'obfuscation.
    
    Args:
        text: Texte à sanitizer
        replace_emojis: Si True, remplace les emojis par [EMOJI], sinon les supprime
        
    Returns:
        Texte sanitizé
    """
    if not text:
        return text
    
    # Normaliser les homoglyphes
    text = normalize_homoglyphs(text)
    
    # Gérer les emojis
    if replace_emojis:
        text = replace_emojis_with_description(text)
    else:
        text = remove_emojis(text)
    
    # Normaliser les espaces et caractères de contrôle
    normalized_chars = []
    for char in text:
        cat = unicodedata.category(char)
        if cat.startswith('C'):  # Caractères de contrôle
            normalized_chars.append(' ')
        elif cat == 'Zs':  # Tous les types d'espaces deviennent des espaces standard
            normalized_chars.append(' ')
        else:
            normalized_chars.append(char)
    
    return ''.join(normalized_chars)

# Fonction pour vérifier si un texte contient des caractères de zalgo
def contains_zalgo(text: str) -> bool:
    """
    Vérifie si un texte contient des caractères de zalgo (caractères combinants).
    
    Args:
        text: Texte à vérifier
        
    Returns:
        True si le texte contient des caractères de zalgo, False sinon
    """
    if not text:
        return False
    
    combining_chars_count = 0
    for char in text:
        if unicodedata.combining(char) > 0:
            combining_chars_count += 1
    
    # Si plus de 5 caractères combinants, c'est probablement du zalgo
    return combining_chars_count > 5

# Fonction pour supprimer les caractères de zalgo
def remove_zalgo(text: str) -> str:
    """
    Supprime les caractères de zalgo (caractères combinants) d'un texte.
    
    Args:
        text: Texte dont il faut supprimer les caractères de zalgo
        
    Returns:
        Texte sans caractères de zalgo
    """
    if not text:
        return text
    
    return ''.join(char for char in text if unicodedata.combining(char) == 0) 