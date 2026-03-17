from scapy.all import sniff, wrpcap
import pandas as pd
from datetime import datetime
import os

from src.utils.config import METADATA_FILE, PCAP_FILE
from src.utils.helpers import setup_logger

logger = setup_logger("packet_capture")

def process_packet(packet, metadata_list):
    """Extracts metadata from a single packet without payload inspection."""
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        packet_size = len(packet)
        protocol = "TCP" if packet.haslayer('TCP') else "UDP" if packet.haslayer('UDP') else "Other"
        
        # Get port info if TCP/UDP
        port = 0
        if packet.haslayer('TCP'):
            port = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            port = packet['UDP'].dport

        metadata = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_size": packet_size,
            "port": port,
            "protocol": protocol
        }
        metadata_list.append(metadata)

def start_capture(interface=None, packet_count=100, save_to_csv=True):
    """Starts packet capture on a specified interface."""
    logger.info(f"Starting packet capture (Target count: {packet_count})...")
    metadata_list = []
    packet_list = []
    
    def packet_callback(pkt):
        packet_list.append(pkt)
        process_packet(pkt, metadata_list)

    sniff(iface=interface, count=packet_count, prn=packet_callback, store=True, timeout=5)
    
    # Save PCAP evidence
    if packet_list:
        wrpcap(PCAP_FILE, packet_list)
        logger.info(f"Raw packets saved to {PCAP_FILE}")
    
    if save_to_csv and metadata_list:
        df = pd.DataFrame(metadata_list)
        # Append to existing csv or create new
        if os.path.exists(METADATA_FILE):
            df.to_csv(METADATA_FILE, mode='a', header=False, index=False)
        else:
            df.to_csv(METADATA_FILE, index=False)
        logger.info(f"Captured {len(metadata_list)} packets and saved to {METADATA_FILE}")
        
    return metadata_list

if __name__ == "__main__":
    # Test capture
    start_capture(packet_count=50)
