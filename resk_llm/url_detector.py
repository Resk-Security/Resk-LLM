import re
import logging
import urllib.parse
import ipaddress
import socket
from typing import Dict, List, Tuple, Any, Optional, Set, Union
import tldextract

class URLDetector:
    """
    Detects and analyzes URLs in text, identifying potentially malicious patterns.
    """
    
    def __init__(self):
        """Initialize the URL detector."""
        self.logger = logging.getLogger(__name__)
        
        # Regex for finding URLs
        self.url_regex = re.compile(
            r'(?:(?:https?|ftp):\/\/|www\.)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:\/[^\s]*)?',
            re.IGNORECASE
        )
        
        # Regex for detecting IP-based URLs
        self.ip_url_regex = re.compile(
            r'(?:https?|ftp):\/\/(?:\S+(?::\S*)?@)?(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?::\d{2,5})?(?:\/[^\s]*)?',
            re.IGNORECASE
        )
        
        # Regex for obfuscated URLs
        self.obfuscated_url_regex = re.compile(
            r'(?:h(?:t(?:t(?:p(?:s)?)?)?)?)[: ]*(?:\\?\/\\?\/|\\\\|[\/\\]|%2F%2F)(?:[a-zA-Z0-9_-]+\.)+(?:[a-zA-Z]{2,})',
            re.IGNORECASE
        )
        
        # Regex for hex or encoded URLs
        self.encoded_url_regex = re.compile(
            r'(?:%[0-9A-Fa-f]{2})+',
        )
        
        # Regex for port numbers (suspicious port ranges)
        self.suspicious_port_regex = re.compile(
            r':(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{1,3}|[1-9])',
            re.IGNORECASE
        )
        
        # Known malicious TLDs/domains
        self.suspicious_tlds = {
            # Free TLDs often abused
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz',
            # Typosquatting on common TLDs
            'cm', 'co', 'om', 'nx', 'info',
            # Country TLDs with limited regulation
            'ru', 'su', 'ws', 'cc',
        }
        
        # Known phishing domains patterns
        self.phishing_patterns = [
            r'paypa[0-9]?\.',
            r'amaz[0o]n\.',
            # r'g[0o]{2}gl[e3]\.', # Commented out: Too broad, matches legitimate google.com
            r'fb[0-9]?\.',
            r'twitt[e3]r\.',
            r'ap[p]?l[e3]\.',
            r'micr[o0]s[o0]ft\.',
            r'netfl[i1]x\.',
            r'[a-z0-9]+\-secure\.',
            r'secure\-[a-z0-9]+\.',
            r'[a-z0-9]+\-verify\.',
            r'verify\-[a-z0-9]+\.',
            r'[a-z0-9]+\-signin\.',
            r'signin\-[a-z0-9]+\.',
            r'[a-z0-9]+\-login\.',
            r'login\-[a-z0-9]+\.',
        ]
        
        # Compile phishing patterns
        self.phishing_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.phishing_patterns]
        
        # Shortener services to flag
        self.url_shorteners = {
            'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'pic.gd', 
            'DwarfURL.com', 'ow.ly', 'snurl.com', 'tiny.cc', 'short.to', 'BudURL.com',
            'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 
            'loopt.us', 'doiop.com', 'twitthis.com', 'htxt.it', 'AltURL.com', 
            'RedirX.com', 'DigBig.com', 'u.nu', 'a.co', 'amzn.to'
        }

        # Keywords for common brands
        self.common_brand_keywords = {
            'paypal', 'amazon', 'google', 'facebook', 'fb', 'twitter',
            'apple', 'microsoft', 'netflix', 'instagram', 'linkedin',
            'ebay', 'chase', 'wellsfargo', 'bankofamerica', 'citibank'
            # Add more as needed
        }
        # Corresponding official domains for the brands above
        self.official_brand_domains = {
            'paypal.com', 'amazon.com', 'google.com', 'facebook.com',
            'twitter.com', 'apple.com', 'microsoft.com', 'netflix.com',
            'instagram.com', 'linkedin.com', 'ebay.com', 'chase.com',
            'wellsfargo.com', 'bankofamerica.com', 'citi.com'
            # Add corresponding official domains
        }

        # Keywords often found in phishing URLs
        self.suspicious_keywords = {'phish', 'login', 'signin', 'secure', 'verify', 'account', 'update', 'webscr', 'cmd'}
        
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from the given text.
        
        Args:
            text: The text to scan for URLs
            
        Returns:
            List of extracted URLs
        """
        # Find standard URLs
        standard_urls = self.url_regex.findall(text)
        
        # Find obfuscated URLs 
        obfuscated_urls = self.obfuscated_url_regex.findall(text)
        
        # Combine and deduplicate
        all_urls_set = set(standard_urls + obfuscated_urls)
        
        # Post-processing: Remove shorter URLs that are prefixes of longer ones
        final_urls = list(all_urls_set)
        final_urls.sort(key=len, reverse=True) # Sort by length descending

        urls_to_keep = []
        prefixes_to_remove = set()

        for i, url1 in enumerate(final_urls):
            if url1 in prefixes_to_remove:
                continue
            for j in range(i + 1, len(final_urls)):
                url2 = final_urls[j]
                # Check if url2 is a prefix of url1 (ignoring potential trailing slash differences)
                # And ensure it's not the exact same URL
                if url1.startswith(url2) and len(url1) > len(url2):
                    # Check if the difference is just a path/query component
                    if len(url1) > len(url2) and url1[len(url2)] in ('/', '?', '#'):
                         prefixes_to_remove.add(url2)
                    # Handle case where domain is captured separately, e.g. example.com vs http://example.com/path
                    elif url1.startswith(f"http://{url2}") or url1.startswith(f"https://{url2}"):
                         prefixes_to_remove.add(url2)

        for url in final_urls:
             if url not in prefixes_to_remove:
                 urls_to_keep.append(url)

        # Original order might be preferable for some use cases, but not critical for counting
        # return sorted(urls_to_keep) 
        return urls_to_keep
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for suspicious characteristics.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        result: Dict[str, Any] = {
            'url': url,
            'is_suspicious': False,
            'risk_score': 0,
            'reasons': [],
            'parsed': None,
            'domain': None,
            'tld': None,
            'is_ip_based': False,
            'uses_shortener': False,
            'has_suspicious_port': False,
            'has_excessive_subdomains': False,
            'has_suspicious_tld': False,
            'is_likely_phishing': False, # General phishing indicator
            'is_likely_typosquatting': False, # Specific typosquatting flag
            'has_encoded_chars': False,
        }
        
        # Basic risk scoring system
        risk_score = 0
        
        try:
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            result['parsed'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
            }
            
            # Extract domain info
            domain_info = tldextract.extract(url)
            result['domain'] = domain_info.domain
            result['tld'] = domain_info.suffix
            result['full_domain'] = domain_info.registered_domain
            result['subdomain'] = domain_info.subdomain
            
            # Basic validation: requires scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                result['reasons'].append("Invalid URL structure (missing scheme or netloc)")
                result['is_suspicious'] = True
                result['risk_score'] = 100 # Invalid URLs are highly suspicious
                return result # Early exit for fundamentally broken URLs
                
            # Check 1: IP-based URL
            if self.ip_url_regex.match(url) or (domain_info.domain and all(c.isdigit() or c == '.' for c in domain_info.domain)):
                result['is_ip_based'] = True
                result['reasons'].append("IP-based URL")
                risk_score += 15
                # Check if IP is numeric (already partially covered by regex, but good fallback)
                if any(char.isdigit() for char in result['domain']):
                     result['reasons'].append("Domain contains numeric characters") # Added for IP case too
                     risk_score += 10 # Add extra risk for numeric-only domains/IPs
                
                # Check for suspicious keywords in path for IP-based URLs
                ip_path_keywords = {'admin', 'login', 'config', 'setup', 'manage', 'console'}
                path_lower = parsed.path.lower()
                found_ip_path_keywords = [kw for kw in ip_path_keywords if f'/{kw}' in path_lower] # Check for '/keyword'
                if found_ip_path_keywords:
                    result['reasons'].append(f"Suspicious path keyword(s) {found_ip_path_keywords} found on IP-based URL")
                    risk_score += 30 # Significantly increase risk for this pattern

            # Check 2: Uses URL Shortener
            if result['full_domain'] in self.url_shorteners:
                result['uses_shortener'] = True
                result['reasons'].append("Uses URL shortener")
                risk_score += 20 # Increase risk slightly for shorteners
                
            # Check 3: Suspicious Port
            if self.suspicious_port_regex.search(url):
                result['has_suspicious_port'] = True
                result['reasons'].append("Uses non-standard/suspicious port")
                risk_score += 25
                
            # Check 4: Excessive Subdomains
            subdomain_parts = domain_info.subdomain.split('.') if domain_info.subdomain else []
            if len(subdomain_parts) > 3: # e.g., more than login.secure.account.example.com
                result['has_excessive_subdomains'] = True
                result['reasons'].append("Excessive number of subdomains")
                risk_score += 15
                
            # Check 5: Suspicious TLD
            if result['tld'] in self.suspicious_tlds:
                result['has_suspicious_tld'] = True
                result['reasons'].append(f"Uses potentially suspicious TLD: {result['tld']}")
                risk_score += 20
                
            # Check 6: Encoded Characters
            if self.encoded_url_regex.search(url):
                result['has_encoded_chars'] = True
                result['reasons'].append("URL contains encoded characters")
                risk_score += 10
                
            # Check 7: Typosquatting/Phishing Patterns (Domain)
            if result['full_domain']: # Ensure we have a domain to check
                for regex in self.phishing_regexes:
                    if regex.search(result['full_domain']):
                        result['is_likely_phishing'] = True
                        result['reasons'].append("Domain pattern matches known phishing/typo patterns")
                        risk_score += 35
                        break # One match is enough
                
                # Check for brand keyword in subdomain of unofficial domain
                if result['subdomain'] and result['full_domain'] not in self.official_brand_domains:
                    found_brands = [brand for brand in self.common_brand_keywords if brand in result['subdomain'].lower().split('.')]
                    if found_brands:
                        result['is_likely_phishing'] = True
                        result['reasons'].append(f"Brand keyword(s) {found_brands} in subdomain on unofficial domain {result['full_domain']}")
                        risk_score += 40

                # Check for potential typosquatting (numeric chars in domain, not IP)
                if not result['is_ip_based'] and any(char.isdigit() for char in result['domain']):
                     result['reasons'].append("Domain contains numeric characters")
                     risk_score += 10
                     # Simple check for common brand typos by substituting numbers
                     substitutions = {'0': 'o', '1': 'l', '1': 'i', '3': 'e', '5': 's'} # Add more if needed
                     normalized_domain = result['domain'].lower()
                     for digit, letter in substitutions.items():
                         normalized_domain = normalized_domain.replace(digit, letter)
                     
                     # Check if the normalized domain contains a brand keyword
                     possible_brands = [brand for brand in self.common_brand_keywords if brand in normalized_domain]
                     if possible_brands:
                        result['is_likely_typosquatting'] = True
                        result['reasons'].append(f"Potential typosquatting detected involving possible brand(s): {possible_brands}")
                        risk_score += 40 # Higher risk if numbers are involved with brand names

                # Check for suspicious keywords in domain/subdomain
                domain_parts = (result['subdomain'] + '.' + result['domain']).lower().split('.')
                found_suspicious_domain_keywords = [kw for kw in self.suspicious_keywords if kw in domain_parts]
                if found_suspicious_domain_keywords:
                     result['is_likely_phishing'] = True
                     result['reasons'].append(f"Suspicious keyword(s) {found_suspicious_domain_keywords} found in domain/subdomain")
                     risk_score += 30

            # Check 8: Suspicious Keywords in Path/Query
            path_query = (parsed.path + '?' + parsed.query).lower()
            found_suspicious_keywords = [kw for kw in self.suspicious_keywords if kw in path_query]
            if found_suspicious_keywords:
                result['reasons'].append(f"Suspicious keyword(s) {found_suspicious_keywords} found in path/query")
                risk_score += 20
                if any(kw in ['login', 'signin', 'verify', 'account'] for kw in found_suspicious_keywords):
                    result['is_likely_phishing'] = True # Keywords highly indicative of phishing
                    risk_score += 20 # Extra boost for very common phishing keywords

            # Check 9: Dangerous File Extension in Path
            dangerous_extensions = {'.exe', '.zip', '.rar', '.scr', '.dmg', '.msi', '.bat', '.cmd', '.js', '.vbs'}
            if parsed.path and any(parsed.path.lower().endswith(ext) for ext in dangerous_extensions):
                 result['reasons'].append("URL path points to potentially dangerous file extension")
                 risk_score += 50 # High risk associated with direct executable downloads

            # Final determination
            if risk_score >= 50: # Adjust threshold as needed
                result['is_suspicious'] = True
                
            # Assign risk level based on score
            if risk_score >= 80:
                result['risk_level'] = 'high'
            elif risk_score >= 50:
                result['risk_level'] = 'medium'
            elif risk_score >= 20:
                result['risk_level'] = 'low'
            else:
                result['risk_level'] = 'minimal'
                
            result['risk_score'] = risk_score
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {e}")
            result['reasons'].append(f"Analysis error: {e}")
            result['is_suspicious'] = True # Treat analysis errors as suspicious
            result['risk_score'] = 100 # Max risk score on error
            result['risk_level'] = 'error'
            
        return result
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        """
        Scan text for URLs and analyze each one.
        
        Args:
            text: Text to scan
            
        Returns:
            Dictionary with scan results
        """
        urls = self.extract_urls(text)
        
        results: Dict[str, Any] = {
            'url_count': len(urls),
            'urls': [],
            'has_suspicious_urls': False,
            'highest_risk_score': 0,
            'highest_risk_url': None,
        }
        
        for url in urls:
            analysis = self.analyze_url(url)
            results['urls'].append(analysis)
            
            if analysis['is_suspicious']:
                results['has_suspicious_urls'] = True
                
            if analysis.get('risk_score', 0) > results['highest_risk_score']:
                results['highest_risk_score'] = analysis['risk_score']
                results['highest_risk_url'] = url
        
        return results
    
    def redact_urls(self, text: str, threshold: int = 30, replacement: str = "[URL REDACTED]") -> Tuple[str, Dict[str, Any]]:
        """
        Redact suspicious URLs from text.
        
        Args:
            text: Text to scan and redact
            threshold: Risk score threshold for redaction
            replacement: Text to replace redacted URLs with
            
        Returns:
            Tuple of (redacted text, scan results)
        """
        redacted_text = text
        scan_results = self.scan_text(text)
        
        # Sort URLs by length in descending order to prevent partial replacements
        urls_to_redact = [(url['url'], url) for url in scan_results['urls'] if url.get('risk_score', 0) >= threshold]
        urls_to_redact.sort(key=lambda x: len(x[0]), reverse=True)
        
        # Track which URLs were redacted
        redacted_urls = []
        
        for url, analysis in urls_to_redact:
            if url in redacted_text:
                redacted_text = redacted_text.replace(url, replacement)
                redacted_urls.append(analysis)
        
        scan_results['redacted_count'] = len(redacted_urls)
        scan_results['redacted_urls'] = redacted_urls
        
        return redacted_text, scan_results
    
    def get_ip_from_hostname(self, hostname: str) -> Optional[str]:
        """
        Get IP address for a hostname.
        
        Args:
            hostname: The hostname to resolve
            
        Returns:
            IP address as string or None if resolution failed
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if the IP is private, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False 