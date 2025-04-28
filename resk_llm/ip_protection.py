import re
import logging
import ipaddress
import socket
import requests
from typing import Dict, List, Tuple, Any, Optional, Set, Union

class IPProtection:
    """
    Detects and protects against leakage of IP addresses and other network information.
    """
    
    def __init__(self):
        """Initialize the IP protection module."""
        self.logger = logging.getLogger(__name__)
        
        # Regex for IPv4 addresses
        self.ipv4_regex = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # Regex for IPv6 addresses
        self.ipv6_regex = re.compile(
            r'\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b'
        )
        
        # Regex for MAC addresses
        self.mac_regex = re.compile(
            r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
        )
        
        # Regex for CIDR notation
        self.cidr_regex = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[1-2][0-9]|[0-9])\b'
        )
        
        # Network commands that might leak information
        self.network_command_regex = re.compile(
            r'\b(?:ifconfig|ipconfig|netstat|hostname|route|traceroute|tracert|nslookup|dig|host|arp|ping)\b'
        )
        
        # Private IP ranges
        self.private_ipv4_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),  # Localhost
        ]
        
        # Public/private classification cache
        self.ip_classification_cache = {}
        
    def detect_ips(self, text: str) -> Dict[str, List[str]]:
        """
        Detect IP addresses in text.
        
        Args:
            text: Text to check for IP addresses
            
        Returns:
            Dictionary with lists of detected IPv4 and IPv6 addresses
        """
        ipv4_matches = self.ipv4_regex.findall(text)
        ipv6_matches = self.ipv6_regex.findall(text)
        
        # Check for CIDR notation
        cidr_matches = self.cidr_regex.findall(text)
        
        # Check for MAC addresses
        mac_matches = self.mac_regex.findall(text)
        
        return {
            'ipv4': ipv4_matches,
            'ipv6': ipv6_matches,
            'cidr': cidr_matches,
            'mac': mac_matches
        }
    
    def detect_mac_addresses(self, text: str) -> List[str]:
        """
        Detect MAC addresses in text.

        Args:
            text: Text to check for MAC addresses

        Returns:
            List of detected MAC addresses
        """
        return self.mac_regex.findall(text)
    
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if the IP is private, False otherwise
        """
        # Check cache first
        if ip in self.ip_classification_cache:
            self.logger.debug(f"IP Cache hit for {ip}: {self.ip_classification_cache[ip]}")
            return self.ip_classification_cache[ip]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            is_loopback = ip_obj.is_loopback
            is_private = ip_obj.is_private
            self.logger.debug(f"Checking IP: {ip} -> Parsed: {ip_obj}, is_loopback: {is_loopback}, is_private: {is_private}")

            # Localhost is always private
            if is_loopback:
                self.ip_classification_cache[ip] = True
                self.logger.debug(f"IP {ip} classified as PRIVATE (loopback)")
                return True
            
            # Check if it's in a private range
            if is_private:
                self.ip_classification_cache[ip] = True
                self.logger.debug(f"IP {ip} classified as PRIVATE (is_private=True)")
                return True
            
            # It's a public IP
            self.ip_classification_cache[ip] = False
            self.logger.debug(f"IP {ip} classified as PUBLIC")
            return False
            
        except ValueError:
            # If we can't parse it, consider it private to be safe
            self.logger.warning(f"IP {ip} could not be parsed. Classifying as PRIVATE (ValueError)")
            self.ip_classification_cache[ip] = True # Cache the error case as private
            return True
    
    def classify_ips(self, ips: Dict[str, List[str]]) -> Dict[str, Dict[str, List[str]]]:
        """
        Classify IP addresses as public or private.
        
        Args:
            ips: Dictionary with lists of detected IP addresses
            
        Returns:
            Dictionary with classified IP addresses
        """
        result: Dict[str, Dict[str, List[str]]] = {
            'private': {
                'ipv4': [],
                'ipv6': [],
                'cidr': [],
                'mac': []  # MAC addresses are always considered private
            },
            'public': {
                'ipv4': [],
                'ipv6': [],
                'cidr': [],
                'mac': []  # This will remain empty
            }
        }
        
        # Classify IPv4 addresses
        for ip in ips['ipv4']:
            if self.is_private_ip(ip):
                result['private']['ipv4'].append(ip)
            else:
                result['public']['ipv4'].append(ip)
        
        # Classify IPv6 addresses
        for ip in ips['ipv6']:
            if self.is_private_ip(ip):
                result['private']['ipv6'].append(ip)
            else:
                result['public']['ipv6'].append(ip)
        
        # CIDR notation - if it contains a private IP range, it's private
        for cidr in ips['cidr']:
            try:
                ip_part = cidr.split('/')[0]
                if self.is_private_ip(ip_part):
                    result['private']['cidr'].append(cidr)
                else:
                    result['public']['cidr'].append(cidr)
            except Exception:
                # If we can't parse, consider it private to be safe
                result['private']['cidr'].append(cidr)
        
        # MAC addresses are always considered private
        result['private']['mac'] = ips['mac']
        
        return result
    
    def detect_network_commands(self, text: str) -> List[str]:
        """
        Detect network-related commands in text.
        
        Args:
            text: Text to check for network commands
            
        Returns:
            List of detected network commands
        """
        return self.network_command_regex.findall(text)
    
    def detect_ip_leakage(self, text: str) -> Dict[str, Any]:
        """
        Comprehensively check for IP address and network information leakage.
        
        Args:
            text: Text to check
            
        Returns:
            Dictionary with detection results
        """
        result: Dict[str, Any] = {
            'has_ip_leakage': False,
            'ips': {},
            'classified_ips': {},
            'public_ip_count': 0,
            'private_ip_count': 0,
            'mac_address_count': 0,
            'network_commands': [],
            'risk_level': 'none'
        }
        
        # Detect IPs
        result['ips'] = self.detect_ips(text)
        
        # Classify IPs
        result['classified_ips'] = self.classify_ips(result['ips'])
        
        # Count IPs
        public_ip_count = sum(len(ips) for ip_type, ips in result['classified_ips']['public'].items() if ip_type != 'mac')
        private_ip_count = sum(len(ips) for ip_type, ips in result['classified_ips']['private'].items() if ip_type != 'mac')
        mac_address_count = len(result['classified_ips']['private']['mac']) # Count MACs separately
        
        result['public_ip_count'] = public_ip_count
        result['private_ip_count'] = private_ip_count
        result['mac_address_count'] = mac_address_count # Store MAC count
        
        # Detect network commands
        result['network_commands'] = self.detect_network_commands(text)
        network_cmd_count = len(result['network_commands'])
        
        # Determine if there's a leak
        # Reset flags before evaluation
        result['has_ip_leakage'] = False
        result['risk_level'] = 'none'

        if public_ip_count > 0:
            result['has_ip_leakage'] = True
            
            # Determine risk level (considering public IPs and commands)
            if public_ip_count > 5 or network_cmd_count > 2:
                result['risk_level'] = 'high'
            elif public_ip_count > 1 or network_cmd_count > 0:
                result['risk_level'] = 'medium'
            else:
                result['risk_level'] = 'low'
        # Also consider private IPs, MACs, or commands as low risk leakage
        elif private_ip_count > 0 or mac_address_count > 0 or network_cmd_count > 0:
            result['has_ip_leakage'] = True
            result['risk_level'] = 'low'
        
        return result
    
    def redact_ips(self, text: str, redact_private: bool = False, 
                  replacement_public: str = "[PUBLIC IP REDACTED]",
                  replacement_private: str = "[PRIVATE IP REDACTED]",
                  replacement_mac: str = "[MAC ADDRESS REDACTED]",
                  replacement_cmd: str = "[NETWORK COMMAND]") -> Tuple[str, Dict[str, Any]]:
        """
        Redact IP addresses and network information from text.
        
        Args:
            text: Text to redact
            redact_private: Whether to redact private IPs (default: False)
            replacement_public: Text to replace public IPs with
            replacement_private: Text to replace private IPs with
            replacement_mac: Text to replace MAC addresses with
            replacement_cmd: Text to replace network commands with
            
        Returns:
            Tuple of (redacted text, detection results)
        """
        # Detect leakage
        detection = self.detect_ip_leakage(text)
        redacted = text
        
        # List of all elements to redact
        to_redact = []
        
        # Add public IPs to redaction list
        for ip_type in ['ipv4', 'ipv6', 'cidr']:
            for ip in detection['classified_ips']['public'][ip_type]:
                to_redact.append((ip, replacement_public))
        
        # Add private IPs to redaction list if requested
        if redact_private:
            for ip_type in ['ipv4', 'ipv6', 'cidr']:
                for ip in detection['classified_ips']['private'][ip_type]:
                    to_redact.append((ip, replacement_private))
            
            # MAC addresses are always private
            for mac in detection['classified_ips']['private']['mac']:
                to_redact.append((mac, replacement_mac))
        
        # Add network commands to redaction list
        for cmd in detection['network_commands']:
            to_redact.append((cmd, replacement_cmd))
        
        # Sort by length in descending order to avoid partial replacements
        to_redact.sort(key=lambda x: len(x[0]), reverse=True)
        
        # Perform redactions
        for item, replacement in to_redact:
            redacted = redacted.replace(item, replacement)
        
        # Add redaction info to detection results
        detection['redacted'] = {
            'public_ips': len(detection['classified_ips']['public']['ipv4'] + 
                              detection['classified_ips']['public']['ipv6'] + 
                              detection['classified_ips']['public']['cidr']),
            'private_ips': len(detection['classified_ips']['private']['ipv4'] + 
                               detection['classified_ips']['private']['ipv6'] + 
                               detection['classified_ips']['private']['cidr']) if redact_private else 0,
            'mac_addresses': len(detection['classified_ips']['private']['mac']) if redact_private else 0,
            'network_commands': len(detection['network_commands'])
        }
        
        return redacted, detection
    
    def get_system_ips(self) -> Dict[str, Union[str, List[str], None]]:
        """
        Get IP addresses of the current system.
        
        Returns:
            Dictionary with lists of system IP addresses
        """
        system_ips: Dict[str, Union[str, List[str], None]] = {
            'hostname': socket.gethostname(),
            'local_ips': [],
            'public_ip': None
        }
        
        try:
            # Get local IPs
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            system_ips['local_ips'] = local_ips
        except Exception as e:
            self.logger.error(f"Error getting local IPs: {str(e)}")
        
        try:
            # Try to get public IP (if internet access is available)
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                system_ips['public_ip'] = response.text
        except Exception:
            # It's okay if this fails, we just won't have a public IP
            pass
        
        return system_ips 