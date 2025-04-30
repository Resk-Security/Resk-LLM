# resk_llm/ip_detector.py
# (Replaces ip_protection.py)

import re
import logging
import ipaddress
from typing import Dict, List, Tuple, Any, Optional, Set, Union, Sequence

# Import RESK-LLM core components
from resk_llm.core.abc import DetectorBase

logger = logging.getLogger(__name__)

# Config and Result Types
IpDetectorConfig = Dict[str, Any]
# Define the output type for the detect method - a detailed analysis report
DetectionResult = Dict[str, Any]

class IPDetector(DetectorBase[str, IpDetectorConfig]):
    """
    Detects IP addresses (IPv4, IPv6), CIDR notation, MAC addresses, and
    network commands within text, classifying IPs as public or private.

    Inherits from DetectorBase. The detect method returns a dictionary
    containing counts and lists of detected items.
    """

    # --- Default Regex Patterns ---
    # Improved IPv4 with stricter boundary checks
    IPV4_REGEX = re.compile(
        r'(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])'
    )
    # Standard complex IPv6 regex (often good enough)
    IPV6_REGEX = re.compile(
        r'\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b',
        re.IGNORECASE
    )
    MAC_REGEX = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b')
    # Improved CIDR Regex
    CIDR_REGEX = re.compile(
         r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])\b'
    )
    NETWORK_COMMAND_REGEX = re.compile(
        r'\b(?:ifconfig|ipconfig|netstat|hostname|route|traceroute|tracert|nslookup|dig|host|arp|ping)\b',
        re.IGNORECASE
    )

    # --- Default Private Ranges ---
    DEFAULT_PRIVATE_IPV4_RANGES_STR: List[str] = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8', # Localhost range
        '169.254.0.0/16' # Link-local
    ]
    # IPv6 private ranges (simplified view)
    DEFAULT_PRIVATE_IPV6_RANGES_STR: List[str] = [
        '::1/128', # Localhost
        'fc00::/7', # Unique Local Addresses
        'fe80::/10' # Link-local
    ]

    def __init__(self, config: Optional[IpDetectorConfig] = None):
        """
        Initialize the IP detector.

        Args:
            config: Configuration dictionary. Can contain:
                'private_ipv4_ranges': List[str] of private IPv4 CIDR ranges.
                'private_ipv6_ranges': List[str] of private IPv6 CIDR ranges.
                'use_defaults': bool (default True) to use default private ranges.
        """
        self.logger = logger
        # Compiled private networks
        self.private_ipv4_networks: List[ipaddress.IPv4Network] = []
        self.private_ipv6_networks: List[ipaddress.IPv6Network] = []
        # Internal cache for classification results
        self.ip_classification_cache: Dict[str, bool] = {}
        super().__init__(config) # Calls _validate_config

    def _compile_private_ranges(self, range_list: List[str], ip_version: int) -> Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Compile string CIDR ranges into network objects."""
        networks = []
        network_class = ipaddress.IPv4Network if ip_version == 4 else ipaddress.IPv6Network
        for cidr_str in range_list:
             try:
                 networks.append(network_class(cidr_str, strict=False))
             except ValueError as e:
                 self.logger.error(f"Invalid private IP range '{cidr_str}' skipped: {e}")
        return networks

    def _validate_config(self) -> None:
        """Validate configuration and load settings."""
        if not isinstance(self.config, dict):
            self.config = {}

        use_defaults = self.config.get('use_defaults', True)

        # Load private IPv4 ranges
        ipv4_ranges_str = self.config.get('private_ipv4_ranges', self.DEFAULT_PRIVATE_IPV4_RANGES_STR if use_defaults else [])
        if not isinstance(ipv4_ranges_str, list):
            self.logger.warning("Invalid 'private_ipv4_ranges' format, expected List[str]. Using defaults.")
            ipv4_ranges_str = self.DEFAULT_PRIVATE_IPV4_RANGES_STR if use_defaults else []
        self.private_ipv4_networks = self._compile_private_ranges(ipv4_ranges_str, 4) # type: ignore

        # Load private IPv6 ranges
        ipv6_ranges_str = self.config.get('private_ipv6_ranges', self.DEFAULT_PRIVATE_IPV6_RANGES_STR if use_defaults else [])
        if not isinstance(ipv6_ranges_str, list):
            self.logger.warning("Invalid 'private_ipv6_ranges' format, expected List[str]. Using defaults.")
            ipv6_ranges_str = self.DEFAULT_PRIVATE_IPV6_RANGES_STR if use_defaults else []
        self.private_ipv6_networks = self._compile_private_ranges(ipv6_ranges_str, 6) # type: ignore

        # Clear cache on re-config
        self.ip_classification_cache = {}
        self.logger.info(f"IPDetector configured with {len(self.private_ipv4_networks)} IPv4 and "
                         f"{len(self.private_ipv6_networks)} IPv6 private ranges.")

    def update_config(self, config: IpDetectorConfig) -> None:
        """Update detector configuration and reload settings."""
        self.config.update(config)
        self._validate_config()

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address string is private, using cache."""
        if ip_str in self.ip_classification_cache:
            return self.ip_classification_cache[ip_str]

        try:
            ip_obj = ipaddress.ip_address(ip_str)

            # Check built-in properties first (more efficient for common cases)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_private:
                 self.ip_classification_cache[ip_str] = True
                 return True

            # Check against custom ranges if built-ins don't match
            # Explicitly type the local variable to handle both versions
            # Use Sequence to satisfy covariance rules
            private_networks: Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
            if isinstance(ip_obj, ipaddress.IPv4Address):
                private_networks = self.private_ipv4_networks
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                private_networks = self.private_ipv6_networks
            else:
                 self.ip_classification_cache[ip_str] = False # Should not happen
                 return False

            for network in private_networks:
                if ip_obj in network:
                    self.ip_classification_cache[ip_str] = True
                    return True

            # If not in any private range, it's public
            self.ip_classification_cache[ip_str] = False
            return False

        except ValueError:
            # If parsing fails, treat as private/suspicious for safety
            self.logger.debug(f"IP address '{ip_str}' could not be parsed. Classifying as private.")
            self.ip_classification_cache[ip_str] = True
            return True


    def detect(self, data: str) -> DetectionResult:
        """
        Detects IP addresses, MACs, CIDR, and network commands in the input text.

        Args:
            data: The input string to analyze.

        Returns:
            A dictionary containing counts and lists of detected items:
            {
                'text': original_input_text,
                'detected_ipv4': [...],
                'detected_ipv6': [...],
                'detected_cidr': [...],
                'detected_mac': [...],
                'detected_commands': [...],
                'classified_ips': {
                    'private': {'ipv4':[], 'ipv6':[], 'cidr':[]},
                    'public': {'ipv4':[], 'ipv6':[], 'cidr':[]}
                 },
                'counts': {
                    'public_ip': int,
                    'private_ip': int,
                    'mac': int,
                    'command': int
                },
                 'has_ip_leakage': bool # True if any public IP, MAC, or command found
            }
        """
        if not isinstance(data, str):
             self.logger.warning("IPDetector detect method received non-string input.")
             return {
                 'text': data, 'detected_ipv4': [], 'detected_ipv6': [], 'detected_cidr': [],
                 'detected_mac': [], 'detected_commands': [], 'classified_ips': {},
                 'counts': {'public_ip': 0, 'private_ip': 0, 'mac': 0, 'command': 0},
                 'has_ip_leakage': False
             }

        # --- Detection ---
        ipv4_matches = list(set(self.IPV4_REGEX.findall(data))) # Use set for unique IPs
        ipv6_matches = list(set(self.IPV6_REGEX.findall(data)))
        cidr_matches = list(set(self.CIDR_REGEX.findall(data)))
        mac_matches = list(set(self.MAC_REGEX.findall(data)))
        command_matches = list(set(self.NETWORK_COMMAND_REGEX.findall(data)))

        # --- Classification ---
        classified: Dict[str, Dict[str, List[str]]] = {
            'private': {'ipv4': [], 'ipv6': [], 'cidr': []},
            'public': {'ipv4': [], 'ipv6': [], 'cidr': []}
        }
        public_count = 0
        private_count = 0

        for ip in ipv4_matches:
            if self._is_private_ip(ip):
                classified['private']['ipv4'].append(ip)
                private_count += 1
            else:
                classified['public']['ipv4'].append(ip)
                public_count += 1

        for ip in ipv6_matches:
            if self._is_private_ip(ip):
                classified['private']['ipv6'].append(ip)
                private_count += 1
            else:
                classified['public']['ipv6'].append(ip)
                public_count += 1

        # Classify CIDR based on the network address part
        for cidr in cidr_matches:
            try:
                # Use ipaddress.ip_network to parse and check base address
                network = ipaddress.ip_network(cidr, strict=False)
                if self._is_private_ip(str(network.network_address)):
                     classified['private']['cidr'].append(cidr)
                     # Note: Counting CIDR ranges themselves as 'private' or 'public' can be ambiguous.
                     # We count based on the base address here.
                     # Consider if a public range containing private addresses should be flagged differently.
                else:
                     classified['public']['cidr'].append(cidr)
            except ValueError:
                # If CIDR parsing fails, classify as private for safety
                self.logger.warning(f"Could not parse CIDR '{cidr}'. Classifying as private.")
                classified['private']['cidr'].append(cidr)


        # --- Result Assembly ---
        mac_count = len(mac_matches)
        command_count = len(command_matches)

        # Define leakage if public IPs, MACs, or network commands are present
        has_leakage = bool(public_count > 0 or mac_count > 0 or command_count > 0)

        return {
            'text': data,
            'detected_ipv4': ipv4_matches,
            'detected_ipv6': ipv6_matches,
            'detected_cidr': cidr_matches,
            'detected_mac': mac_matches,
            'detected_commands': command_matches,
            'classified_ips': classified,
            'counts': {
                'public_ip': public_count,
                'private_ip': private_count, # Includes private IPs within detected CIDRs
                'mac': mac_count,
                'command': command_count
            },
            'has_ip_leakage': has_leakage
        } 