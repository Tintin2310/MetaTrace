# MetaTrace 🛡️

**MetaTrace** is an advanced cybersecurity forensic suite designed for **Real-Time Endpoint Attribution** and **VPN De-anonymization**. By analyzing encrypted network traffic through static communication signatures and side-channel leakage, MetaTrace can unmask hidden identities and provide a granular view of your network's security posture.

---

## 🚀 Key Features

### 📡 Real-Time Dashboard
A high-fidelity command center providing instant visibility into network throughput, packet-per-second metrics, and active endpoint counts.
- **Throughput & PPS**: Live monitoring of network activity with dynamic visualizations.
- **Nearby Scanning**: Discovery of proximity network nodes and behavioral OS fingerprinting.
- **Unified Metadata Table**: Aggregated intelligence from automated scans and manual forensic probes.

### 🧪 Forensic Lab
A specialized environment for deep-packet investigation and targeted unmasking.
- **DNS Leak Probe**: Targeted `nslookup` simulations that break through split-tunneling and VPN headers.
- **VPN De-anonymization**: Identification of real source IPs linked to specific VPN providers (ProtonVPN, etc.).
- **Tor Exit Node Correlation**: Instant cross-referencing of incoming traffic with known Onion routing exit points.
- **Bypass Detection**: Specialized monitoring for STUN/TURN packets to detect WebRTC-based IP leaks.

### 🧠 Intelligent Analysis
- **NLP Attribution**: Uses Spacy-powered extraction to identify high-risk endpoints in your traffic metadata.
- **Infrastructure Mapping**: Automated Reverse Whois and Subdomain Enumeration for malicious IP nodes.
- **Severity Scoring**: Dynamic risk assessment (CRITICAL, HIGH, INFO) for every detected communication event.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React (Vite), Tailwind CSS, Lucide Icons, Plotly.js |
| **Backend** | Python, FastAPI, Scapy, Pandas, NumPy |
| **Analysis** | Spacy (NLP), Joblib, Sklearn |
| **Networking** | Socket API, WHOIS, DNS-Resolver |

---

## 📦 Installation & Setup

### 1. Prerequisites
- Python 3.9+ 🐍
- Node.js & npm 📦
- Admin/Root privileges (Required for live packet capture via Scapy)

### 2. Backend Configuration
```bash
# Install dependencies
pip install -r requirements.txt

# Start the API server
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Frontend Configuration
```bash
cd web
# Install assets
npm install

# Launch the dashboard
npm run dev
```

## 🔒 Security Disclaimer
*MetaTrace is intended for authorized cybersecurity research, network troubleshooting, and educational purposes. Always ensure you have explicit permission before capturing or analyzing traffic on a network you do not own.*

---
