import ipaddress
import json
import os
from src.utils.config import METADATA_FILE

class AppDetector:
    """
    Detects specific applications (like Telegram) based on IP ranges and port signatures.
    """
    def __init__(self, telegram_ips_path="data/telegram_ips.json"):
        self.telegram_networks = []
        try:
            if os.path.exists(telegram_ips_path):
                with open(telegram_ips_path, "r") as f:
                    data = json.load(f)
                    self.telegram_networks = [ipaddress.ip_network(cidr) for cidr in data.get("telegram_cidrs", [])]
        except Exception as e:
            print(f"Error loading Telegram IP ranges: {e}")

    def is_telegram(self, ip):
        """Checks if an IP belongs to Telegram infra."""
        try:
            addr = ipaddress.ip_address(ip)
            for network in self.telegram_networks:
                if addr in network:
                    return True
        except ValueError:
            pass
        return False

    def detect_apps(self, packet_metadata):
        """
        Analyzes a list of packet metadata for app signatures.
        """
        results = []
        for meta in packet_metadata:
            dst_ip = meta.get("dst_ip")
            if self.is_telegram(dst_ip):
                results.append({
                    "timestamp": meta.get("time"),
                    "source_ip": meta.get("src_ip"),
                    "dest_ip": dst_ip,
                    "app": "Telegram",
                    "type": "Messaging Traffic",
                    "severity": "LOW"
                })
        return results
