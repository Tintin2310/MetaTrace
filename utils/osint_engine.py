import socket
import requests
from src.utils.helpers import setup_logger

logger = setup_logger("osint_engine")

class OSINTEngine:
    def __init__(self):
        self.dns_cache = {}
        self.threat_cache = {}

    def get_passive_dns(self, ip):
        """Resolves IP to hostname using Reverse DNS."""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
            
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            # Fallback to a "characterized" name based on prefix if real DNS fails
            # In a real tool, this would query historical DNS databases
            self.dns_cache[ip] = "Unknown Host"
            return "Unknown Host"

    def get_tor_node_type(self, ip):
        """
        Differentiates Tor node types.
        In a real scenario, this would check against the current Tor consensus.
        """
        # Improved Mock logic with specific ranges often used for different nodes
        if ip.startswith("198.51.100.1"): return "Tor Exit Node"
        if ip.startswith("198.51.100.2"): return "Tor Guard Node"
        if ip.startswith("198.51.100.3"): return "Tor Relay Node"
        
        # Simulated live check for demonstration
        if hash(ip) % 10 == 0: return "Tor Exit Node"
        if hash(ip) % 15 == 0: return "Tor Guard Node"
        return None

    def reverse_whois(self, ip):
        """
        Performs breadcrumbing by finding related infrastructure.
        Mocked for real-time demonstration.
        """
        related = {
            "45.33.2.1": ["attacker-c2.net", "staging-db.top"],
            "185.12.34.5": ["malware-host.biz", "phish-login.com"]
        }
        return related.get(ip, ["No related infra found"])

    def subdomain_enumeration(self, domain):
        """
        Basic subdomain enumeration for breadcrumbing.
        """
        common = ["api", "dev", "vpn", "mail", "internal", "secure"]
        # In real-time, we'd do DNS lookups. Here we simulate the process.
        results = [f"{sub}.{domain}" for sub in common if hash(f"{sub}.{domain}") % 3 == 0]
        return results if results else [f"www.{domain}"]

    def correlate_threats(self, ip):
        """Checks IP against threat intelligence signatures."""
        if ip in self.threat_cache:
            return self.threat_cache[ip]
            
        threat_data = {
            "score": 0,
            "status": "Clean",
            "threat_type": None,
            "tor_type": self.get_tor_node_type(ip)
        }
        
        if threat_data["tor_type"]:
            threat_data["score"] = 70 if "Exit" in threat_data["tor_type"] else 30
            threat_data["threat_type"] = threat_data["tor_type"]
            threat_data["status"] = "Suspicious"

        # Mock logic for other threats
        risk_ips = {
            "45.33.": {"score": 40, "type": "Known VPN Range", "status": "Neutral"},
            "185.12.34": {"score": 95, "type": "Malware C2", "status": "Malicious"}
        }
        
        for prefix, info in risk_ips.items():
            if ip.startswith(prefix):
                threat_data.update(info)
                break
                
        self.threat_cache[ip] = threat_data
        return threat_data
