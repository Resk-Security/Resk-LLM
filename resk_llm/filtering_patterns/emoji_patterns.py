"""
Module containing features to detect and filter emojis and special Unicode characters.
Designed to protect against malicious content hiding via special characters.
"""

import re
import unicodedata
from typing import Dict, List, Tuple, Pattern, Union, Set, Optional, Any

# Unicode ranges for emojis
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F600-\U0001F64F"  # emoticons
    "\U0001F300-\U0001F5FF"  # symbols & pictograms
    "\U0001F680-\U0001F6FF"  # transport & symbols
    "\U0001F700-\U0001F77F"  # alchemical symbols
    "\U0001F780-\U0001F7FF"  # geometric symbols
    "\U0001F800-\U0001F8FF"  # supplemental symbols
    "\U0001F900-\U0001F9FF"  # supplemental symbols and pictograms
    "\U0001FA00-\U0001FA6F"  # game symbols
    "\U0001FA70-\U0001FAFF"  # supplemental symbols
    "\U00002702-\U000027B0"  # dingbats
    "\U000024C2-\U0001F251" 
    "]+"
)

# Special characters and homoglyphs that can be used for obfuscation
HOMOGLYPHS: Dict[str, List[str]] = {
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

# Build an inverted dictionary for quick lookup
INVERSE_HOMOGLYPHS: Dict[str, str] = {}
for standard, variants in HOMOGLYPHS.items():
    for variant in variants:
        INVERSE_HOMOGLYPHS[variant] = standard

def detect_emojis(text: str) -> List[str]:
    """
    Detects emojis in text.
    
    This function identifies all emoji characters in the input text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of emojis found in the text. Empty list if no emojis are found
        or if the input is empty.
    """
    if not text:
        return []
    
    return EMOJI_PATTERN.findall(text)

def normalize_homoglyphs(text: str) -> str:
    """
    Normalizes Unicode characters that resemble standard ASCII characters.
    
    This function replaces homoglyphs (visually similar characters) with their
    standard ASCII equivalents to prevent obfuscation attacks.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text with homoglyphs replaced by their standard equivalents
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

def remove_emojis(text: str) -> str:
    """
    Removes all emojis from text.
    
    Args:
        text: Text from which to remove emojis
        
    Returns:
        Text with all emojis removed
    """
    if not text:
        return text
    
    return EMOJI_PATTERN.sub('', text)

def replace_emojis_with_description(text: str) -> str:
    """
    Replaces emojis with [EMOJI].
    
    This function substitutes all emoji characters with a standard token to
    maintain text structure while removing potentially problematic characters.
    
    Args:
        text: Text in which to replace emojis
        
    Returns:
        Text with emojis replaced by [EMOJI] tokens
    """
    if not text:
        return text
    
    return EMOJI_PATTERN.sub('[EMOJI]', text)

def check_for_obfuscation(text: str) -> Dict[str, List[str]]:
    """
    Checks if a text uses unusual or suspicious Unicode characters that could indicate
    an attempt at obfuscation or bypassing filters.
    
    This function examines text for various techniques often used to hide malicious content,
    such as homoglyphs, invisible characters, and unusual Unicode symbols.
    
    Args:
        text: Text to check
        
    Returns:
        Dictionary with detected obfuscation types and their corresponding characters.
        Returns an empty dictionary if no obfuscation is detected or the input is empty.
    """
    if not text:
        return {}
    
    results: Dict[str, List[str]] = {}
    
    # Check for emojis
    emojis = detect_emojis(text)
    if emojis:
        results["emojis"] = emojis
    
    # Check for homoglyphs
    detected_homoglyphs: List[str] = []
    for char in text:
        if char in INVERSE_HOMOGLYPHS and char != INVERSE_HOMOGLYPHS[char]:
            detected_homoglyphs.append(char)
    
    if detected_homoglyphs:
        results["homoglyphs"] = detected_homoglyphs
    
    # Check for control characters and other special characters
    control_chars: List[str] = []
    special_chars: List[str] = []
    
    for char in text:
        cat = unicodedata.category(char)
        if cat.startswith('C'):  # Control characters
            control_chars.append(repr(char))
        elif cat == 'Zs' and char != ' ':  # Non-standard spaces
            special_chars.append(repr(char))
        elif cat.startswith('S'):  # Symbols
            if char not in emojis:  # Avoid counting emojis twice
                special_chars.append(char)
    
    if control_chars:
        results["control_chars"] = control_chars
    
    if special_chars:
        results["special_chars"] = special_chars
    
    return results

def sanitize_text_from_obfuscation(text: str, replace_emojis: bool = True) -> str:
    """
    Sanitizes text by normalizing or removing all forms of obfuscation.
    
    This function handles multiple types of text obfuscation techniques:
    - Normalizes homoglyphs to their standard ASCII equivalents
    - Handles emojis by replacing or removing them
    - Standardizes spaces and control characters
    
    Args:
        text: Text to sanitize
        replace_emojis: If True, replaces emojis with [EMOJI], otherwise removes them
        
    Returns:
        Sanitized text with obfuscation techniques mitigated
    """
    if not text:
        return text
    
    # Normalize homoglyphs
    text = normalize_homoglyphs(text)
    
    # Handle emojis
    if replace_emojis:
        text = replace_emojis_with_description(text)
    else:
        text = remove_emojis(text)
    
    # Normalize spaces and control characters
    normalized_chars: List[str] = []
    for char in text:
        cat = unicodedata.category(char)
        if cat.startswith('C'):  # Control characters
            normalized_chars.append(' ')
        elif cat == 'Zs':  # All types of spaces become standard spaces
            normalized_chars.append(' ')
        else:
            normalized_chars.append(char)
    
    return ''.join(normalized_chars)

def contains_zalgo(text: str) -> bool:
    """
    Checks if text contains zalgo characters (combining characters).
    
    Zalgo text uses many combining Unicode characters to create a distorted,
    glitchy appearance that can bypass content filters.
    
    Args:
        text: Text to check
        
    Returns:
        True if the text contains zalgo characters, False otherwise
    """
    if not text:
        return False
    
    combining_chars_count = 0
    for char in text:
        if unicodedata.combining(char) > 0:
            combining_chars_count += 1
    
    # If more than 5 combining characters, it's probably zalgo
    return combining_chars_count > 5

def remove_zalgo(text: str) -> str:
    """
    Removes zalgo (combining characters) from text.
    
    This function removes combining characters that are often used to create
    glitchy, distorted text that might bypass content filters.
    
    Args:
        text: Text from which to remove zalgo characters
        
    Returns:
        Text with zalgo characters removed
    """
    if not text:
        return text
    
    normalized_chars: List[str] = []
    for char in text:
        if unicodedata.combining(char) == 0:
            normalized_chars.append(char)
    
    return ''.join(normalized_chars) 