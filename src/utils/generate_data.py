import pandas as pd
import numpy as np
import random
import os

from src.utils.config import TRAINING_DATA_FILE, METADATA_FILE, NETWORK_LABELS

def generate_training_data(num_samples=600):
    """Generates synthetic network features for ML training."""
    data = []
    
    # 0: Messaging, 1: VPN, 2: CDN, 3: Cloud, 4: Tor, 5: Unknown
    for _ in range(num_samples):
        label = random.randint(0, 4) # Focus mainly on 0-4 for training
        
        if label == 0: # Messaging (small packets, bursts, standard ports)
            avg_ps = np.random.normal(150, 30)
            pf = np.random.normal(5, 2)
            sd = np.random.normal(300, 100)
            br = np.random.normal(12, 4)
            port = random.choice([443, 5222, 5228])
            
        elif label == 1: # VPN (large packet variance, constant flow, high duration)
            avg_ps = np.random.normal(800, 200)
            pf = np.random.normal(15, 5)
            sd = np.random.normal(3600, 1000)
            br = np.random.normal(5, 2)
            port = random.choice([1194, 500, 4500, 443])
            
        elif label == 2: # CDN (large packets, short sessions, bursts)
            avg_ps = np.random.normal(1200, 150)
            pf = np.random.normal(25, 8)
            sd = np.random.normal(120, 50)
            br = np.random.normal(20, 8)
            port = random.choice([443, 80])
            
        elif label == 3: # Cloud (mixed packet size, persistent connection)
            avg_ps = np.random.normal(600, 300)
            pf = np.random.normal(10, 4)
            sd = np.random.normal(7200, 2000)
            br = np.random.normal(8, 3)
            port = random.choice([443, 22, 3389])
            
        else: # Tor (small continuous packets, very long sessions, specific ports)
            avg_ps = np.random.normal(512, 50)
            pf = np.random.normal(8, 2)
            sd = np.random.normal(10000, 2000)
            br = np.random.normal(3, 1)
            port = random.choice([9001, 9030, 443])
            
        data.append({
            "avg_packet_size": max(40, avg_ps),
            "packet_frequency": max(0.1, pf),
            "session_duration": max(1, sd),
            "burst_rate": max(0, br),
            "port": port,
            "label": NETWORK_LABELS[label]
        })
        
    df = pd.DataFrame(data)
    df.to_csv(TRAINING_DATA_FILE, index=False)
    print(f"Generated {num_samples} training samples at {TRAINING_DATA_FILE}")

def generate_mock_metadata(num_samples=200):
    """Generates mock packet metadata (as if extracted from PCAP)."""
    data = []
    
    src_ips = [f"192.168.1.{i}" for i in range(2, 10)]
    dst_ips = {
        "104.244.42.1": "Messaging Infrastructure",
        "172.217.16.206": "CDN Node",
        "185.12.34.56": "VPN Network",
        "13.250.12.1": "Cloud Service",
        "198.51.100.10": "Tor Exit Node"
    }
    
    start_time = pd.Timestamp.now() - pd.Timedelta(hours=2)
    
    for _ in range(num_samples):
        dst_ip = random.choice(list(dst_ips.keys()))
        label = dst_ips[dst_ip]
        
        # Reverse mapping roughly to logic above to create realistic-looking individual packets
        if label == "Messaging Infrastructure":
            ps = max(40, np.random.normal(150, 50))
            port = 443
        elif label == "VPN Network":
            ps = max(40, np.random.normal(800, 300))
            port = 1194
        elif label == "CDN Node":
            ps = max(40, np.random.normal(1200, 200))
            port = 443
        elif label == "Cloud Service":
            ps = max(40, np.random.normal(600, 400))
            port = random.choice([22, 443])
        else:
            ps = 512 + int(np.random.normal(0, 10))
            port = 9001
            
        data.append({
            "time": (start_time + pd.Timedelta(seconds=random.randint(0, 7200))).strftime("%H:%M:%S"),
            "src_ip": random.choice(src_ips),
            "dst_ip": dst_ip,
            "packet_size": int(ps),
            "port": port,
            "protocol": "TCP" if port not in [1194, 500] else "UDP"
        })
        
    df = pd.DataFrame(data)
    df = df.sort_values(by="time").reset_index(drop=True)
    df.to_csv(METADATA_FILE, index=False)
    print(f"Generated {num_samples} mock metadata records at {METADATA_FILE}")

if __name__ == "__main__":
    generate_training_data()
    generate_mock_metadata()
