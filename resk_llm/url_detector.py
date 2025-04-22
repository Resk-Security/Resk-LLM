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
            r'g[0o]{2}gl[e3]\.',
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
        all_urls = list(set(standard_urls + obfuscated_urls))
        
        return all_urls
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for suspicious characteristics.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        result = {
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
            'is_likely_phishing': False,
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
            result['full_domain'] = domain_info.registered_domain
            result['tld'] = domain_info.suffix
            result['subdomain'] = domain_info.subdomain
            
            # Check if IP-based URL
            if self.ip_url_regex.match(url):
                result['is_ip_based'] = True
                risk_score += 40  # Higher risk for IP-based URLs
                result['reasons'].append('IP-based URL')
            
            # Check for URL shorteners
            if domain_info.registered_domain in self.url_shorteners:
                result['uses_shortener'] = True
                risk_score += 20
                result['reasons'].append('Uses URL shortener')
            
            # Check for suspicious ports
            if self.suspicious_port_regex.search(parsed.netloc):
                result['has_suspicious_port'] = True
                risk_score += 20
                result['reasons'].append('Uses suspicious port')
            
            # Check for excessive subdomains (potential for confusion)
            if domain_info.subdomain and len(domain_info.subdomain.split('.')) > 3:
                result['has_excessive_subdomains'] = True
                risk_score += 15
                result['reasons'].append('Excessive subdomains')
            
            # Check for suspicious TLDs
            if domain_info.suffix in self.suspicious_tlds:
                result['has_suspicious_tld'] = True
                risk_score += 10
                result['reasons'].append(f'Suspicious TLD: {domain_info.suffix}')
            
            # Check for phishing patterns
            for regex in self.phishing_regexes:
                if regex.search(url):
                    result['is_likely_phishing'] = True
                    risk_score += 50
                    result['reasons'].append('Matches phishing pattern')
                    break
            
            # Check for encoded characters
            if self.encoded_url_regex.search(url):
                result['has_encoded_chars'] = True
                risk_score += 15
                result['reasons'].append('Contains URL-encoded characters')
            
            # Check for mixed case domains (typosquatting technique)
            if domain_info.domain and any(c.isupper() for c in domain_info.domain):
                risk_score += 15
                result['reasons'].append('Mixed case domain')
            
            # Check for numeric confusables in domain (e.g., amaz0n)
            if domain_info.domain and any(c.isdigit() for c in domain_info.domain):
                risk_score += 10
                result['reasons'].append('Domain contains numeric characters')
            
            # Check for very long domains
            if len(domain_info.registered_domain) > 25:
                risk_score += 5
                result['reasons'].append('Unusually long domain name')
            
            # Final risk assessment
            result['risk_score'] = min(100, risk_score)  # Cap at 100
            result['is_suspicious'] = risk_score >= 30  # Threshold for suspicion
            
            # Categorize risk level
            if risk_score >= 70:
                result['risk_level'] = 'high'
            elif risk_score >= 40:
                result['risk_level'] = 'medium' 
            elif risk_score >= 20:
                result['risk_level'] = 'low'
            else:
                result['risk_level'] = 'minimal'
                
        except Exception as e:
            self.logger.error(f"Error analyzing URL '{url}': {str(e)}")
            result['error'] = str(e)
            result['is_suspicious'] = True  # Consider it suspicious if we can't analyze it
            result['risk_level'] = 'unknown'
            
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
        
        results = {
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