import re
import logging
from typing import Dict, List, Tuple, Any, Optional, Union
import unicodedata

from resk_llm.core.abc import DetectorBase

# Type de configuration pour TextAnalyzer
TextAnalyzerConfig = Dict[str, Any]

class TextAnalyzer(DetectorBase[str, TextAnalyzerConfig]):
    """
    Analyzes text for potential security risks like invisible characters,
    encoding tricks, homoglyphs, and other obfuscation techniques.
    """
    
    def __init__(self, config: Optional[TextAnalyzerConfig] = None):
        """
        Initialize the text analyzer.
        
        Args:
            config: Optional configuration dictionary which may contain:
                'additional_homoglyphs': Dict mapping ASCII chars to similar-looking non-ASCII chars
                'additional_invisible_chars': List of additional invisible character codes
                'risk_thresholds': Dict with thresholds for risk levels
        """
        default_config: TextAnalyzerConfig = {
            'risk_thresholds': {
                'low': 0.3,
                'medium': 0.6,
                'high': 0.9
            }
        }
        
        if config:
            default_config.update(config)
            
        super().__init__(default_config)
        
        self.logger = logging.getLogger(__name__)
        
        # Zero-width and invisible characters
        self.invisible_chars = [
            '\u200B', '\u200C', '\u200D', '\u200E', '\u200F',  # Zero-width chars
            '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',  # Word joiner and function chars
            '\u2065', '\u2066', '\u2067', '\u2068', '\u2069',  # Invisible chars
            '\u206A', '\u206B', '\u206C', '\u206D', '\u206E', '\u206F',  # Deprecated format chars
            '\uFEFF',  # Zero-width no-break space
            '\u180E',  # Mongolian vowel separator
            '\u061C',  # Arabic letter mark
        ]
        
        # Add any additional invisible characters from config
        if config and 'additional_invisible_chars' in config:
            self.invisible_chars.extend(config['additional_invisible_chars'])
        
        # Homoglyphs (characters that look similar to common ASCII)
        self.homoglyphs = {
            'a': ['а', 'ɑ', 'α', 'ａ'],
            'b': ['Ь', 'ｂ'],
            'c': ['с', 'ϲ', 'ｃ'],
            'd': ['ԁ', 'ｄ'],
            'e': ['е', 'ε', 'ｅ'],
            'f': ['ｆ'],
            'g': ['ɡ', 'ｇ'],
            'h': ['һ', 'ｈ'],
            'i': ['і', 'ｉ'],
            'j': ['ϳ', 'ｊ'],
            'k': ['ｋ', 'κ'],
            'l': ['ӏ', 'ⅼ', 'ｌ'],
            'm': ['ｍ'],
            'n': ['ｎ'],
            'o': ['о', 'ο', 'ｏ'],
            'p': ['р', 'ｐ'],
            'q': ['ԛ', 'ｑ'],
            'r': ['ｒ'],
            's': ['ѕ', 'ｓ'],
            't': ['т', 'ｔ'],
            'u': ['υ', 'ｕ'],
            'v': ['ν', 'ｖ'],
            'w': ['ѡ', 'ｗ'],
            'x': ['х', 'ｘ'],
            'y': ['у', 'ｙ'],
            'z': ['ｚ'],
            '.': ['․', '。', '｡'],
            '_': ['＿'],
            '-': ['−', '－', '﹣', '‐', '‑'],
            ':': ['︓', '：'],
            '/': ['∕', '／'],
            '\\': ['＼'],
        }
        
        # Add any additional homoglyphs from config
        if config and 'additional_homoglyphs' in config:
            for ascii_char, similar_chars in config['additional_homoglyphs'].items():
                if ascii_char in self.homoglyphs:
                    self.homoglyphs[ascii_char].extend(similar_chars)
                else:
                    self.homoglyphs[ascii_char] = similar_chars
        
        # Compile regex for detecting various obfuscation techniques
        self.invisible_regex = re.compile(r'[' + ''.join(self.invisible_chars) + r']')
        
        # Regex for detecting potential URL obfuscation
        self.url_obfuscation_regex = re.compile(r'(?:h(?:t(?:t(?:p(?:s)?)?)?)?)[: ]*(?://|\\\\|[/\\])(?:[a-zA-Z0-9_-]+\.)+(?:[a-zA-Z]{2,})')
        
        # Regex for detecting backslash escapes
        self.escape_sequence_regex = re.compile(r'\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3})')
        
        # Regex for detecting non-ASCII characters
        self.non_ascii_regex = re.compile(r'[^\x00-\x7F]')
        
        # Regex for RTL and LTR override characters
        self.direction_override_regex = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
    
    def _validate_config(self) -> None:
        """Validate the configuration."""
        if 'risk_thresholds' in self.config:
            thresholds = self.config['risk_thresholds']
            if not isinstance(thresholds, dict):
                raise ValueError("risk_thresholds must be a dictionary")
            
            required_levels = ['low', 'medium', 'high']
            for level in required_levels:
                if level not in thresholds:
                    raise ValueError(f"risk_thresholds must contain '{level}'")
                if not isinstance(thresholds[level], (int, float)):
                    raise ValueError(f"risk_threshold for '{level}' must be a number")
    
    def update_config(self, config: TextAnalyzerConfig) -> None:
        """Update the configuration."""
        self.config.update(config)
        self._validate_config()
        
        # Update invisible characters if provided
        if 'additional_invisible_chars' in config:
            self.invisible_chars.extend(config['additional_invisible_chars'])
            # Re-compile regex
            self.invisible_regex = re.compile(r'[' + ''.join(self.invisible_chars) + r']')
            
        # Update homoglyphs if provided
        if 'additional_homoglyphs' in config:
            for ascii_char, similar_chars in config['additional_homoglyphs'].items():
                if ascii_char in self.homoglyphs:
                    self.homoglyphs[ascii_char].extend(similar_chars)
                else:
                    self.homoglyphs[ascii_char] = similar_chars

    def detect(self, data: str) -> Dict[str, Any]:
        """
        Detect security issues in text.
        This is the main method required by DetectorBase.
        
        Args:
            data: The text to analyze
            
        Returns:
            Dictionary with analysis results
        """
        return self.analyze_text(data)
    
    def detect_invisible_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Detects invisible characters and text obfuscation techniques.
        
        Args:
            text: The input text to analyze
            
        Returns:
            List of dictionaries with details of detected invisible characters
        """
        findings = []
        
        # Check for zero-width and invisible characters
        invisible_matches = list(self.invisible_regex.finditer(text))
        if invisible_matches:
            positions = [(m.start(), m.end()) for m in invisible_matches]
            char_codes = [ord(text[pos[0]]) for pos in positions]
            
            findings.append({
                'type': 'invisible_character',
                'count': len(invisible_matches),
                'positions': positions,
                'char_codes': [f"U+{code:04X}" for code in char_codes],
                'risk': 'high',
                'description': 'Invisible or zero-width characters detected, which may be used for obfuscation.'
            })
        
        # Check for direction override characters
        direction_matches = list(self.direction_override_regex.finditer(text))
        if direction_matches:
            positions = [(m.start(), m.end()) for m in direction_matches]
            char_codes = [ord(text[pos[0]]) for pos in positions]
            
            findings.append({
                'type': 'direction_override',
                'count': len(direction_matches),
                'positions': positions,
                'char_codes': [f"U+{code:04X}" for code in char_codes],
                'risk': 'high', 
                'description': 'Text direction override characters detected, which may be used to hide malicious content.'
            })
        
        # Check for escaped unicode/hex sequences
        escape_matches = list(self.escape_sequence_regex.finditer(text))
        if escape_matches:
            findings.append({
                'type': 'escape_sequence',
                'count': len(escape_matches),
                'positions': [(m.start(), m.end()) for m in escape_matches],
                'sequences': [m.group() for m in escape_matches],
                'risk': 'medium',
                'description': 'Escape sequences detected, which may be used to encode malicious content.'
            })
            
        return findings
    
    def detect_homoglyphs(self, text: str) -> List[Dict[str, Any]]:
        """
        Detects homoglyphs (characters that look like Latin characters but are different).
        
        Args:
            text: The input text to analyze
            
        Returns:
            List of dictionaries with details of detected homoglyphs
        """
        findings = []
        homoglyph_positions = []
        
        # Check each character in the text
        for i, char in enumerate(text):
            if char in self.invisible_chars:
                continue  # Already handled by detect_invisible_text
                
            # Check if this is a non-ASCII character
            if ord(char) > 127:
                # Check if it's a known homoglyph
                for ascii_char, similars in self.homoglyphs.items():
                    if char in similars:
                        homoglyph_positions.append((i, char, ascii_char))
                        break
        
        if homoglyph_positions:
            findings.append({
                'type': 'homoglyph',
                'count': len(homoglyph_positions),
                'positions': [(pos, ord(char)) for pos, char, _ in homoglyph_positions],
                'mappings': [(char, ascii_char) for _, char, ascii_char in homoglyph_positions],
                'risk': 'medium',
                'description': 'Homoglyphs detected, which may be used to mimic legitimate text or URLs.'
            })
            
        return findings
    
    def detect_unusual_space_chars(self, text: str) -> List[Dict[str, Any]]:
        """
        Detects unusual space characters.
        
        Args:
            text: The input text to analyze
            
        Returns:
            List of dictionaries with details of detected unusual spaces
        """
        findings = []
        
        # Unusual space characters
        unusual_spaces = [
            '\u00A0',  # Non-breaking space
            '\u1680',  # Ogham space mark
            '\u2000',  # En quad
            '\u2001',  # Em quad
            '\u2002',  # En space
            '\u2003',  # Em space
            '\u2004',  # Three-per-em space
            '\u2005',  # Four-per-em space
            '\u2006',  # Six-per-em space
            '\u2007',  # Figure space
            '\u2008',  # Punctuation space
            '\u2009',  # Thin space
            '\u200A',  # Hair space
            '\u202F',  # Narrow no-break space
            '\u205F',  # Medium mathematical space
            '\u3000',  # Ideographic space
        ]
        
        space_regex = re.compile(r'[' + ''.join(unusual_spaces) + r']')
        space_matches = list(space_regex.finditer(text))
        
        if space_matches:
            findings.append({
                'type': 'unusual_space',
                'count': len(space_matches),
                'positions': [(m.start(), m.end()) for m in space_matches],
                'char_codes': [f"U+{ord(text[m.start()]):04X}" for m in space_matches],
                'risk': 'low',
                'description': 'Unusual space characters detected, which may be used for formatting tricks.'
            })
            
        return findings
    
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Performs comprehensive analysis of text for security risks.
        
        Args:
            text: The input text to analyze
            
        Returns:
            Dictionary with all analysis results
        """
        results: Dict[str, Any] = {
            'invisible_text': self.detect_invisible_text(text),
            'homoglyphs': self.detect_homoglyphs(text),
            'unusual_spaces': self.detect_unusual_space_chars(text),
            'overall_risk': 'low'
        }
        
        # Calculate overall risk
        risk_levels = {'low': 1, 'medium': 2, 'high': 3}
        max_risk = 'low'
        
        for category in ['invisible_text', 'homoglyphs', 'unusual_spaces']:
            for finding in results[category]:
                if risk_levels[finding['risk']] > risk_levels[max_risk]:
                    max_risk = finding['risk']
        
        results['overall_risk'] = max_risk
        results['has_issues'] = bool(any(len(results[key]) > 0 for key in ['invisible_text', 'homoglyphs', 'unusual_spaces']))
        
        return results
    
    def clean_text(self, text: str) -> str:
        """
        Removes or replaces potentially malicious text features.
        
        Args:
            text: The input text to clean
            
        Returns:
            Cleaned text with suspicious elements removed
        """
        # Remove invisible characters
        cleaned = self.invisible_regex.sub('', text)
        
        # Remove direction override characters
        cleaned = self.direction_override_regex.sub('', cleaned)
        
        # Replace homoglyphs with their ASCII equivalents
        for i, char in enumerate(cleaned):
            if ord(char) > 127:  # Non-ASCII
                for ascii_char, similars in self.homoglyphs.items():
                    if char in similars:
                        cleaned = cleaned[:i] + ascii_char + cleaned[i+1:]
                        break
        
        # Normalize Unicode
        cleaned = unicodedata.normalize('NFKC', cleaned)
        
        return cleaned 