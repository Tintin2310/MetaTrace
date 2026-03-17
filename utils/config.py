import os

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, "data")
ML_DIR = os.path.join(BASE_DIR, "src", "ml")

# File paths
METADATA_FILE = os.path.join(DATA_DIR, "metadata.csv")
TRAINING_DATA_FILE = os.path.join(DATA_DIR, "training_dataset.csv")
MODEL_FILE = os.path.join(ML_DIR, "model.pkl")
PCAP_FILE = os.path.join(DATA_DIR, "capture_evidence.pcap")
GEO_CACHE_FILE = os.path.join(DATA_DIR, "geo_cache.json")
REPORT_FILE = os.path.join(DATA_DIR, "forensic_report.pdf")
SIMULATION_PCAP = os.path.join(DATA_DIR, "forensic_simulation.pcap")

# ML Labels
NETWORK_LABELS = {
    0: "Messaging Infrastructure",
    1: "VPN Network",
    2: "CDN Node",
    3: "Cloud Service",
    4: "Tor Exit Node",
    5: "Unknown Endpoint"
}

# Burst Detection Thresholds
BURST_TIME_WINDOW_SEC = 60
BURST_PACKET_THRESHOLD = 50

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(ML_DIR, exist_ok=True)
