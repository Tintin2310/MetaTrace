import os
import sys
import time
import pandas as pd
from scapy.all import sniff, IP, UDP, TCP, DNS
from threading import Thread, Event

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from BACKEND.demo_utils import (
    print_header, print_success, print_error,
    print_info, print_warning, print_table, ConsoleColors
)
from src.analysis.vpn_analyzer import VPNForensicAnalyzer

class RealTimeVPNUnmasker:
    def __init__(self):
        self.analyzer = VPNForensicAnalyzer()
        self.captured_packets = []
        self.stop_event = Event()
        self.unmasked_leaks = []
        self.detected_tunnels = set()

    def process_packet(self, packet):
        if self.stop_event.is_set():
            return

        # 1. Look for VPN Tunnels
        vpn_info = self.analyzer.detect_vpn_signature(packet)
        if vpn_info and IP in packet:
            ip = packet[IP].dst
            if ip not in self.detected_tunnels:
                self.detected_tunnels.add(ip)
                print_warning(f"ACTIVE TUNNEL DETECTED: {ip} [{vpn_info['type']}] - Level: {vpn_info['level']}")

        # 2. Look for Hidden Metadata Leaks
        leak = self.analyzer.extract_hidden_metadata(packet)
        if leak:
            self.unmasked_leaks.append(leak)
            print_success(f"UNMASKED DATA REVEALED: {leak['data']} (Via {leak['source']})")

    def start_capture(self, duration=30):
        print_info(f"Starting Live Forensic Monitor for {duration}s...")
        print_info("Monitoring for Encrypted Tunnels and Side-Channel Leaks...")
        
        sniff(prn=self.process_packet, timeout=duration, store=False)
        self.stop_event.set()

    def show_final_report(self):
        print_header("VPN FORENSIC EXFILTRATION REPORT")
        
        if not self.unmasked_leaks:
            print_error("No metadata leaks detected bypass protection.")
            return

        headers = ["TIMESTAMP", "SOURCE", "REVEALED METADATA", "RISK"]
        rows = []
        for l in self.unmasked_leaks[-10:]:
            rows.append([l['timestamp'], l['source'], l['data'], l['severity']])

        print_table(headers, rows)
        print_success(f"Total Unmasked Data Points: {len(self.unmasked_leaks)}")
        print_info(f"Unique Tunnels Identified: {len(self.detected_tunnels)}")

def run_unmasker_demo():
    unmasker = RealTimeVPNUnmasker()
    try:
        unmasker.start_capture(duration=45)
        unmasker.show_final_report()
    except KeyboardInterrupt:
        print_warning("\nCapture stopped by user.")
        unmasker.show_final_report()

if __name__ == "__main__":
    run_unmasker_demo()
