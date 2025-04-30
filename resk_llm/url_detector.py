import re
import logging
import urllib.parse
import ipaddress
import socket
from typing import Dict, List, Tuple, Any, Optional, Set, Union
import tldextract

# Import RESK-LLM core components
from resk_llm.core.abc import DetectorBase, PatternProviderBase

logger = logging.getLogger(__name__)

# Config and Result Types
UrlDetectorConfig = Dict[str, Any]
# Define the output type for the detect method - a detailed analysis report
DetectionResult = Dict[str, Any]

class URLDetector(DetectorBase[str, UrlDetectorConfig]):
    """
    Detects and analyzes URLs in text, identifying potentially malicious patterns.
    Inherits from DetectorBase. The detect method returns a dictionary
    containing the analysis results for all found URLs.
    """

    # --- Default Configuration Values ---
    DEFAULT_SUSPICIOUS_TLDS: Set[str] = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'cm', 'co', 'om', 'nx',
        'info', 'ru', 'su', 'ws', 'cc', 'pw', 'top', 'icu', 'cyou', 'buzz'
    }
    DEFAULT_PHISHING_PATTERNS: List[str] = [
        r'paypa[0-9]?\.', r'amaz[0o]n\.', r'fb[0-9]?\.', r'twitt[e3]r\.',
        r'ap[p]?l[e3]\.', r'micr[o0]s[o0]ft\.', r'netfl[i1]x\.',
        r'[a-z0-9]+\-secure\.', r'secure\-[a-z0-9]+\.',
        r'[a-z0-9]+\-verify\.', r'verify\-[a-z0-9]+\.',
        r'[a-z0-9]+\-signin\.', r'signin\-[a-z0-9]+\.',
        r'[a-z0-9]+\-login\.', r'login\-[a-z0-9]+\.',
    ]
    DEFAULT_URL_SHORTENERS: Set[str] = {
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs',
        'ow.ly', 'snurl.com', 'tiny.cc', 'short.to', 'buff.ly',
        'ift.tt', 'j.mp', 'rebrand.ly', 'bl.ink', 'cutt.ly', 'rb.gy',
        'u.nu', 'a.co', 'amzn.to'
    }
    DEFAULT_BRAND_KEYWORDS: Set[str] = {
        'paypal', 'amazon', 'google', 'facebook', 'fb', 'twitter', 'apple',
        'microsoft', 'netflix', 'instagram', 'linkedin', 'ebay', 'chase',
        'wellsfargo', 'bankofamerica', 'citibank'
    }
    DEFAULT_OFFICIAL_BRAND_DOMAINS: Set[str] = {
        'paypal.com', 'amazon.com', 'google.com', 'facebook.com', 'twitter.com',
        'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
        'linkedin.com', 'ebay.com', 'chase.com', 'wellsfargo.com',
        'bankofamerica.com', 'citi.com'
    }
    DEFAULT_SUSPICIOUS_KEYWORDS_IN_URL: Set[str] = {
        'phish', 'login', 'signin', 'secure', 'verify', 'account', 'update',
        'webscr', 'cmd', 'admin', 'confirm', 'support', 'service', 'recovery'
    }
    # Max subdomains before flagging as suspicious
    DEFAULT_MAX_SUBDOMAINS = 3
    # Risk score increments (can be tuned via config)
    DEFAULT_RISK_INCREMENTS: Dict[str, int] = {
        "ip_based": 15,
        "numeric_domain": 10, # Additional risk for IP/numeric domain
        "suspicious_ip_path": 35, # Keywords like /admin on IP URL (Increased from 30)
        "shortener": 20,
        "suspicious_port": 25,
        "excessive_subdomains": 15,
        "suspicious_tld": 30,
        "phishing_pattern": 45, # Increased from 40
        "suspicious_keyword": 25, # Increased from 20
        "encoded_chars": 10,
        "typosquatting": 50,
        "suspicious_extension": 50, # Increased from 30
        "invalid_structure": 100 # Should likely block immediately
    }

    # --- Regex Patterns (initialized in _validate_config) ---
    url_regex: Optional[re.Pattern] = None
    ip_url_regex: Optional[re.Pattern] = None
    obfuscated_url_regex: Optional[re.Pattern] = None
    encoded_url_regex: Optional[re.Pattern] = None
    suspicious_port_regex: Optional[re.Pattern] = None
    phishing_regexes: List[re.Pattern] = []


    def __init__(self, config: Optional[UrlDetectorConfig] = None):
        """
        Initialize the URL detector.

        Args:
            config: Configuration dictionary. Can contain overrides for defaults:
                'suspicious_tlds': Set[str]
                'phishing_patterns': List[str]
                'url_shorteners': Set[str]
                'brand_keywords': Set[str]
                'official_brand_domains': Set[str]
                'suspicious_keywords_in_url': Set[str]
                'max_subdomains': int
                'risk_increments': Dict[str, int]
                'use_defaults': bool (default True)
                # Potentially add 'pattern_provider' integration later if needed
        """
        self.logger = logger
        # Initialize attributes that will be set in _validate_config
        self.suspicious_tlds: Set[str] = set()
        self.phishing_patterns: List[str] = []
        self.url_shorteners: Set[str] = set()
        self.brand_keywords: Set[str] = set()
        self.official_brand_domains: Set[str] = set()
        self.suspicious_keywords_in_url: Set[str] = set()
        self.max_subdomains: int = self.DEFAULT_MAX_SUBDOMAINS
        self.risk_increments: Dict[str, int] = {}

        super().__init__(config) # Calls _validate_config

    def _compile_regex(self) -> None:
        """Compile the necessary regex patterns."""
        try:
            self.url_regex = re.compile(
                    r'(?:(?:https?|ftp):\/\/|www\.)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:[\/?#][^\s]*)?',
                re.IGNORECASE
            )
            self.ip_url_regex = re.compile(
                     r'(?:https?|ftp):\/\/(?:\S+(?::\S*)?@)?(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?::\d{2,5})?(?:[\/?#][^\s]*)?',
                re.IGNORECASE
            )
            self.obfuscated_url_regex = re.compile(
                     r'(?:h(?:t(?:t(?:p(?:s)?)?)?)?)[: ]*(?:\?\/?\?|\\\\|[\/\\]|%2F%2F)(?:[a-zA-Z0-9_-]+\.)+(?:[a-zA-Z]{2,})', # Simplified slightly
                re.IGNORECASE
            )
            self.encoded_url_regex = re.compile(r'(?:%[0-9A-Fa-f]{2})+')
            # Simplified port regex - checks for presence of :port
            self.suspicious_port_regex = re.compile(r':([0-9]{1,5})(?:[\/?#]|$)')

            # Compile phishing patterns from config
            self.phishing_regexes = []
            for pattern in self.phishing_patterns:
                 try:
                     self.phishing_regexes.append(re.compile(pattern, re.IGNORECASE))
                 except re.error as e:
                      self.logger.error(f"Invalid phishing regex pattern '{pattern}' skipped: {e}")

        except re.error as e:
             self.logger.error(f"Fatal error compiling core URL regex patterns: {e}", exc_info=True)
             # This detector might be unusable if core regex fails
             self.url_regex = None # Mark as unusable

    def _validate_config(self) -> None:
        """Validate configuration and load settings."""
        if not isinstance(self.config, dict):
            self.config = {}

        use_defaults = self.config.get('use_defaults', True)

        # Load settings, merging defaults and config values
        self.suspicious_tlds = set(self.config.get('suspicious_tlds', self.DEFAULT_SUSPICIOUS_TLDS if use_defaults else set()))
        self.phishing_patterns = list(self.config.get('phishing_patterns', self.DEFAULT_PHISHING_PATTERNS if use_defaults else []))
        self.url_shorteners = set(self.config.get('url_shorteners', self.DEFAULT_URL_SHORTENERS if use_defaults else set()))
        self.brand_keywords = set(self.config.get('brand_keywords', self.DEFAULT_BRAND_KEYWORDS if use_defaults else set()))
        self.official_brand_domains = set(self.config.get('official_brand_domains', self.DEFAULT_OFFICIAL_BRAND_DOMAINS if use_defaults else set()))
        self.suspicious_keywords_in_url = set(self.config.get('suspicious_keywords_in_url', self.DEFAULT_SUSPICIOUS_KEYWORDS_IN_URL if use_defaults else set()))
        self.max_subdomains = int(self.config.get('max_subdomains', self.DEFAULT_MAX_SUBDOMAINS))

        # Load risk increments, updating defaults with config values
        self.risk_increments = self.DEFAULT_RISK_INCREMENTS.copy()
        custom_increments = self.config.get('risk_increments', {})
        if isinstance(custom_increments, dict):
            self.risk_increments.update(custom_increments)
        else:
            self.logger.warning("Invalid 'risk_increments' format in config, expected dict. Using defaults.")

        # Compile regex patterns based on loaded config
        self._compile_regex()
        self.logger.info("URLDetector configured.")

    def update_config(self, config: UrlDetectorConfig) -> None:
        """Update detector configuration and reload settings/patterns."""
        self.config.update(config)
        self._validate_config()

    def _extract_urls(self, text: str) -> List[str]:
        """Extract potential URLs from text using compiled regex."""
        if not self.url_regex or not self.obfuscated_url_regex:
             self.logger.error("URL regex patterns not compiled. Cannot extract URLs.")
             return []

        try:
            standard_urls = self.url_regex.findall(text)
            obfuscated_urls = self.obfuscated_url_regex.findall(text)
            all_urls_set = set(standard_urls + obfuscated_urls)
            
            # Simple deduplication for now, advanced prefix removal can be complex
            # Consider adding http(s):// prefix if missing www. for better parsing later
            processed_urls = set()
            for url in all_urls_set:
                 if url.lower().startswith('www.'):
                      processed_urls.add(f"http://{url}") # Assume http for www. if no scheme
                 else:
                      processed_urls.add(url)

            # Filter out obvious non-URLs captured by broad regex (e.g. version numbers)
            # A simple check: must contain at least one dot and one letter?
            final_urls = [u for u in processed_urls if '.' in u and any(c.isalpha() for c in u)]

            return final_urls
        except Exception as e:
             self.logger.error(f"Error during URL extraction: {e}", exc_info=True)
             return []


    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics."""
        result: Dict[str, Any] = {
            'url': url, 'is_suspicious': False, 'risk_score': 0, 'reasons': [],
            'parsed': None, 'domain': None, 'tld': None, 'full_domain': None, 'subdomain': None,
            'is_ip_based': False, 'uses_shortener': False, 'has_suspicious_port': False,
            'has_excessive_subdomains': False, 'has_suspicious_tld': False,
            'is_likely_phishing': False, 'is_likely_typosquatting': False,
            'has_encoded_chars': False,
        }
        risk_score = 0
        
        try:
            # --- Parsing ---
            try:
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme and url.startswith('//'): # Handle protocol-relative URLs
                     url = f"http:{url}" # Assume http
                     parsed = urllib.parse.urlparse(url) # Re-parse after adding scheme
                elif not parsed.scheme: # Handle URLs without scheme (e.g., www.example.com)
                     # Already handled in _extract_urls by adding http://
                     pass # No action needed here

                # Use tldextract for robust domain/subdomain/tld extraction
                domain_info = tldextract.extract(url)
                result['domain'] = domain_info.domain
                result['tld'] = domain_info.suffix
                result['full_domain'] = domain_info.registered_domain # Domain + TLD
                result['subdomain'] = domain_info.subdomain

                # Store parsed components
                result['parsed'] = {
                        'scheme': parsed.scheme, 'netloc': parsed.netloc, 'path': parsed.path,
                        'params': parsed.params, 'query': parsed.query, 'fragment': parsed.fragment,
                    }

                # Require scheme and netloc for a valid parsable URL after potential fixes
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError("Invalid URL structure (missing scheme or netloc after parsing)")

            except ValueError as e: # Catch parsing errors
                 result['reasons'].append(f"URL parsing error: {e}")
                 risk_score += self.risk_increments.get("invalid_structure", 100)
                 result['is_suspicious'] = True
                 result['risk_score'] = risk_score
                 # Return early as further analysis is not possible
                 return result 

            # --- Analysis Checks (Continue only if parsing succeeded) ---
                
            # Check 1: IP-based URL
            is_ip_domain = False
            if self.ip_url_regex and self.ip_url_regex.match(url):
                 is_ip_domain = True
            elif domain_info.domain and all(c.isdigit() or c == '.' for c in domain_info.domain):
                 # Check if domain looks like an IP address
                 try:
                     ipaddress.ip_address(domain_info.domain)
                     is_ip_domain = True
                 except ValueError:
                     pass # Not a valid IP format

            if is_ip_domain:
                result['is_ip_based'] = True
                result['reasons'].append("IP-based URL")
                risk_score += self.risk_increments.get("ip_based", 15)
                # Check for suspicious keywords in path for IP URLs
                ip_path_keywords = {'admin', 'login', 'config', 'setup', 'manage', 'console'}
                path_lower = parsed.path.lower()
                found_ip_kw = [kw for kw in ip_path_keywords if f'/{kw}' in path_lower]
                if found_ip_kw:
                    result['reasons'].append(f"Suspicious path keyword(s) on IP URL: {found_ip_kw}")
                    risk_score += self.risk_increments.get("suspicious_ip_path", 35)

            # Check 2: Uses URL Shortener
            if result['full_domain'] and result['full_domain'].lower() in self.url_shorteners:
                result['uses_shortener'] = True
                result['reasons'].append("Uses URL shortener")
                risk_score += self.risk_increments.get("shortener", 20)
                
            # Check 3: Suspicious Port
            if self.suspicious_port_regex:
                 port_match = self.suspicious_port_regex.search(parsed.netloc) # Search netloc directly
                 if port_match:
                     try:
                          port = int(port_match.group(1))
                          # Standard ports are usually OK, flag others or specific ranges
                          if port not in {80, 443, 8080}: # Example common allowed ports
                              result['has_suspicious_port'] = True
                              result['reasons'].append(f"Uses non-standard port: {port}")
                              risk_score += self.risk_increments.get("suspicious_port", 25)
                     except ValueError:
                          pass # Should not happen with regex, but ignore if it does
                
            # Check 4: Excessive Subdomains
            subdomain_parts = result['subdomain'].split('.') if result['subdomain'] else []
            if len(subdomain_parts) > self.max_subdomains:
                result['has_excessive_subdomains'] = True
                result['reasons'].append(f"Excessive subdomains ({len(subdomain_parts)} > {self.max_subdomains})")
                risk_score += self.risk_increments.get("excessive_subdomains", 15)
                
            # Check 5: Suspicious TLD
            if result['tld'] and result['tld'].lower() in self.suspicious_tlds:
                result['has_suspicious_tld'] = True
                result['reasons'].append(f"Suspicious TLD: .{result['tld']}")
                risk_score += self.risk_increments.get("suspicious_tld", 30)

            # Check 6: Phishing Patterns in Domain/Subdomain
            domain_to_check = f"{result['subdomain']}.{result['full_domain']}" if result['subdomain'] else result['full_domain']
            if domain_to_check:
                domain_lower = domain_to_check.lower()
                for pattern in self.phishing_regexes:
                     if pattern.search(domain_lower):
                         result['is_likely_phishing'] = True
                         result['reasons'].append(f"Phishing pattern match: {pattern.pattern}")
                         risk_score += self.risk_increments.get("phishing_pattern", 45)
                         break # One pattern match is enough

            # Check 7: Suspicious Keywords in URL (domain, path, query)
            url_lower = url.lower()
            found_keywords = {kw for kw in self.suspicious_keywords_in_url if kw in url_lower}
            if found_keywords:
                 result['reasons'].append(f"Suspicious keyword(s) in URL: {found_keywords}")
                 risk_score += self.risk_increments.get("suspicious_keyword", 25) * len(found_keywords) # Scale risk by number of keywords?

            # Check 8: Encoded Characters in Path/Query
            if self.encoded_url_regex and (self.encoded_url_regex.search(parsed.path) or self.encoded_url_regex.search(parsed.query)):
                result['has_encoded_chars'] = True
                result['reasons'].append("URL contains encoded characters")
                risk_score += self.risk_increments.get("encoded_chars", 10)

            # Check 9: Potential Typosquatting (Brand keyword in domain, but not official domain)
            if result['full_domain']:
                 domain_lower = result['full_domain'].lower()

                 # Normalize common substitutions (0->o, 1->l, etc.) for comparison
                 def normalize_for_typo(s: str) -> str:
                    return s.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('@', 'a')

                 normalized_domain = normalize_for_typo(domain_lower)

                 # Check if normalized domain contains a normalized brand keyword
                 found_brand_kw = set()
                 for kw in self.brand_keywords:
                    normalized_kw = normalize_for_typo(kw)
                    if normalized_kw in normalized_domain:
                        found_brand_kw.add(kw) # Store the original keyword found

                 #found_brand_kw = {kw for kw in self.brand_keywords if kw in domain_lower} # Original check
                 is_official = domain_lower in self.official_brand_domains
                 if found_brand_kw and not is_official:
                     result['is_likely_typosquatting'] = True
                     result['is_likely_phishing'] = True # Typosquatting is a form of phishing
                     result['reasons'].append(f"Potential typosquatting: Brand keyword(s) {found_brand_kw} found in non-official domain '{result['full_domain']}'")
                     risk_score += self.risk_increments.get("typosquatting", 50)

            # Check 10: Suspicious File Extension in Path
            suspicious_extensions = {'.exe', '.zip', '.rar', '.dmg', '.iso', '.scr', '.msi', '.bat', '.sh'}
            path_lower = parsed.path.lower()
            found_ext = {ext for ext in suspicious_extensions if path_lower.endswith(ext)}
            if found_ext:
                result['reasons'].append(f"URL path ends with suspicious extension(s): {found_ext}")
                risk_score += self.risk_increments.get("suspicious_extension", 50) * len(found_ext) # Updated default

            # Final assessment
            # Check against a defined threshold (e.g., 50 based on test expectation)
            if risk_score >= 50:
                result['is_suspicious'] = True
            result['risk_score'] = risk_score
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL '{url}': {e}", exc_info=True)
            result['is_suspicious'] = True # Mark as suspicious on error
            result['reasons'].append(f"Analysis error: {e}")
            result['risk_score'] = self.risk_increments.get("invalid_structure", 100) # High risk on error
            
        return result
    
    def detect(self, data: str) -> DetectionResult:
        """
        Detects and analyzes URLs within the input text.
        
        Args:
            data: The input string to analyze.
            
        Returns:
            A dictionary containing the analysis results:
            {
                'text': original_input_text,
                'detected_urls_count': number_of_urls_found,
                'suspicious_urls_count': number_of_suspicious_urls,
                'max_risk_score': highest_risk_score_found,
                'urls_analysis': [ list_of_analysis_dicts_for_each_url ]
            }
        """
        if not isinstance(data, str):
             self.logger.warning("URLDetector detect method received non-string input.")
             return {
                 'text': data, 'detected_urls_count': 0, 'suspicious_urls_count': 0,
                 'max_risk_score': 0, 'urls_analysis': []
             }

        extracted_urls = self._extract_urls(data)
        analysis_results = []
        suspicious_count = 0
        max_risk = 0

        for url in extracted_urls:
            analysis = self._analyze_url(url)
            analysis_results.append(analysis)
            if analysis.get('is_suspicious', False):
                suspicious_count += 1
            max_risk = max(max_risk, analysis.get('risk_score', 0))

        return {
            'text': data,
            'detected_urls_count': len(extracted_urls),
            'suspicious_urls_count': suspicious_count,
            'max_risk_score': max_risk,
            'urls_analysis': analysis_results
        }

    # --- Helper Methods (Potentially useful but not part of core detector) ---
    # Removed get_ip_from_hostname and is_private_ip for brevity,
    # can be added back if needed for specific checks.