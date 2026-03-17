from scapy.all import ARP, Ether, srp
import socket
from src.utils.helpers import setup_logger

logger = setup_logger("network_scanner")

import subprocess
import re

def scan_wifi_networks():
    """
    Scans for available WiFi networks using Windows netsh.
    """
    logger.info("Scanning for available WiFi networks...")
    try:
        # Run netsh command to get available networks
        result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], stderr=subprocess.STDOUT, shell=True).decode('utf-8', errors='ignore')
        
        networks = []
        current_network = {}
        
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("SSID"):
                if current_network:
                    networks.append(current_network)
                ssid = line.split(":", 1)[1].strip() if ":" in line else "Hidden Network"
                current_network = {"ssid": ssid or "Hidden Network", "bssids": []}
            elif line.startswith("BSSID"):
                bssid = line.split(":", 1)[1].strip() if ":" in line else "Unknown"
                current_network.setdefault("bssids", []).append(bssid)
            elif "Signal" in line:
                signal = line.split(":", 1)[1].strip() if ":" in line else "0%"
                current_network["signal"] = signal
            elif "Authentication" in line:
                auth = line.split(":", 1)[1].strip() if ":" in line else "Open"
                current_network["auth"] = auth

        if current_network:
            networks.append(current_network)
            
        logger.info(f"Found {len(networks)} WiFi networks.")
        return networks
    except Exception as e:
        logger.error(f"WiFi Scan failed: {e}")
        # Fallback to some dummy data if netsh fails (e.g. no wifi adapter)
        return [{"ssid": "Offline_Demo_Net", "signal": "80%", "auth": "WPA2"}]

def start_arp_scan(interface=None, timeout=2):
    """
    Performs a real-time ARP scan on the local network.
    """
    logger.info("Starting real-time ARP scan...")
    try:
        # Get local IP and subnet
        # A more robust way would be using psutil or netifaces, 
        # but we'll try to derive from hostname for simplicity in this demo.
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_prefix = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        
        logger.info(f"Scanning subnet: {ip_prefix}")
        
        # Craft ARP packet
        arp = ARP(pdst=ip_prefix)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=timeout, iface=interface, verbose=False)[0]

        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": "Unknown" # In real tool, do reverse DNS here
            })
        
        logger.info(f"Found {len(devices)} devices nearby.")
        return devices
    except Exception as e:
        logger.error(f"ARP Scan failed: {e}")
        return []

if __name__ == "__main__":
    print(start_arp_scan())
