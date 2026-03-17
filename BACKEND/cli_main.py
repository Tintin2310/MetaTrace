import os
import sys
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from BACKEND.demo_utils import (
    print_banner, print_header, print_success, print_error,
    print_info, print_warning, print_table, ConsoleColors
)

from src.analysis.endpoint_attribution import EndpointAttributor
from src.analysis.burst_detection import BurstDetector
from src.utils.osint_engine import OSINTEngine
from src.analysis.correlation_engine import CorrelationEngine


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


class MetaTraceCLI:

    def __init__(self):
        self.attributor = EndpointAttributor()
        self.detector = BurstDetector()
        self.osint = OSINTEngine()
        self.correlation = CorrelationEngine()

        self.df = pd.DataFrame(columns=[
            "time", "src_ip", "dst_ip", "port", "packet_size"
        ])

    # -------------------------------
    # LIVE PACKET CAPTURE
    # -------------------------------
    def capture_packets(self, count=30):

        captured_rows = []

        def process_packet(packet):

            if IP in packet:

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                port = None

                if TCP in packet:
                    port = packet[TCP].dport
                elif UDP in packet:
                    port = packet[UDP].dport

                packet_size = len(packet)

                captured_rows.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": port,
                    "packet_size": packet_size
                })

        print_info("Capturing live packets from network...")

        sniff(prn=process_packet, count=count, store=False)

        self.df = pd.DataFrame(captured_rows)
        if not self.df.empty:
            self.df['datetime_full'] = pd.to_datetime('2000-01-01 ' + self.df['time'])

        print_success(f"Captured {len(self.df)} packets successfully.")

    # -------------------------------
    # NETWORK OVERVIEW
    # -------------------------------
    def show_network_overview(self):

        print_header("NETWORK FORENSIC OVERVIEW")

        self.capture_packets()

        if self.df.empty:
            print_warning("No packets captured.")
            return

        headers = ["TIMESTAMP", "SRC IP", "DST IP", "PORT", "SIZE (B)"]

        rows = []

        for _, row in self.df.tail(10).iterrows():
            rows.append([
                row['time'],
                row['src_ip'],
                row['dst_ip'],
                row['port'],
                row['packet_size']
            ])

        print_table(headers, rows)

        print_info(f"Total Capture Volume: {len(self.df)} packets")
        print_info(f"Unique Endpoints Detected: {self.df['dst_ip'].nunique()}")

    # -------------------------------
    # ENDPOINT ATTRIBUTION
    # -------------------------------
    def show_endpoint_attribution(self):

        print_header("ENDPOINT FORENSIC ATTRIBUTION (ML)")

        if self.df.empty:
            print_warning("Capture packets first.")
            return

        results = self.attributor.run_attribution(self.df)

        if not results:
            print_warning("No high confidence attributions found.")
            return

        headers = ["TARGET IP", "NETWORK CLASS", "CONFIDENCE"]

        rows = []

        attribution_items = list(results.items())
        for ip, data in attribution_items[:10]:

            conf = f"{data['confidence']*100:.1f}%"

            rows.append([
                ip,
                data['predicted_network'],
                conf
            ])

        print_table(headers, rows)

        print_success("Behavioral ML classification completed.")

    # -------------------------------
    # BURST DETECTION
    # -------------------------------
    def show_burst_detection(self):

        print_header("TRAFFIC BURST & ANOMALY DETECTION")

        if self.df.empty:
            print_warning("Capture packets first.")
            return

        sessions = self.df.groupby("dst_ip")

        all_bursts = []

        for ip, group in sessions:

            bursts = self.detector.detect_bursts(group, threshold=10)

            for b in bursts:
                all_bursts.append([
                    ip,
                    b['burst_start'],
                    b['burst_end'],
                    b['packet_count'],
                    b['burst_intensity']
                ])

        if not all_bursts:
            print_warning("No burst anomalies detected.")
            return

        headers = ["TARGET IP", "START", "END", "PACKETS", "INTENSITY"]

        print_table(headers, all_bursts)

    # -------------------------------
    # THREAT CORRELATION
    # -------------------------------
    def show_threat_correlation(self):

        print_header("PASSIVE DNS & THREAT CORRELATION")

        if self.df.empty:
            print_warning("Capture packets first.")
            return

        unique_ips = self.df['dst_ip'].unique()[:8]

        headers = ["IP ADDRESS", "PASSIVE DNS", "THREAT SCORE", "STATUS"]

        rows = []

        for ip in unique_ips:

            hostname = self.osint.get_passive_dns(ip)

            intel = self.osint.correlate_threats(ip)

            score = f"{intel['score']}/100"

            status = intel['status']

            rows.append([ip, hostname, score, status])

        print_table(headers, rows)

        print_success("Threat intelligence correlation complete.")

    # -------------------------------
    # CLI MENU
    # -------------------------------
    def run(self):

        while True:

            clear_screen()

            print_banner()

            print(" [1] Network Forensic Overview (Live Capture)")
            print(" [2] Endpoint Attribution Analysis")
            print(" [3] Traffic Burst & Anomaly Detection")
            print(" [4] Passive DNS & Threat Correlation")
            print(" [5] Real-Time VPN Tunnel De-anonymization")
            print(" [6] Exit")

            choice = input(f"\n{ConsoleColors.BOLD}Select Operation > {ConsoleColors.ENDC}")

            if choice == '1':
                self.show_network_overview()

            elif choice == '2':
                self.show_endpoint_attribution()

            elif choice == '3':
                self.show_burst_detection()

            elif choice == '4':
                self.show_threat_correlation()

            elif choice == '5':
                from BACKEND.vpn_monitor import run_unmasker_demo
                run_unmasker_demo()

            elif choice == '6':
                print_info("Exiting MetaTrace Suite.")
                break

            else:
                print_error("Invalid selection.")

            input(f"\n{ConsoleColors.OKBLUE}Press Enter to return to menu...{ConsoleColors.ENDC}")


if __name__ == "__main__":

    try:

        cli = MetaTraceCLI()

        cli.run()

    except KeyboardInterrupt:

        print("\nAborted.")

    except Exception as e:

        print(f"\nError: {e}")