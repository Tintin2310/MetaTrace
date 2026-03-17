from src.processing.metadata_extractor import MetadataExtractor
from src.processing.feature_engineering import FeatureEngineer
from src.ml.predict_endpoint import EndpointPredictor
from src.utils.osint_engine import OSINTEngine
from src.utils.helpers import setup_logger
import pandas as pd

logger = setup_logger("endpoint_attribution")

class EndpointAttributor:
    def __init__(self):
        self.extractor = MetadataExtractor()
        self.predictor = EndpointPredictor()
        self.osint = OSINTEngine()
        
    def fingerprint_os(self, df):
        """
        Passive OS Fingerprinting based on TCP/IP heuristics:
        TTL and Window Size analysis.
        """
        if df.empty:
            return "Unknown Device"
            
        # Common TTL values: 64 (Linux/UNIX/Android), 128 (Windows), 255 (Cisco/Network devices)
        avg_ttl = df['ttl'].mean() if 'ttl' in df.columns else 0
        
        # Heuristics
        if avg_ttl > 64 and avg_ttl <= 128:
            return "Windows Workstation"
        elif avg_ttl <= 64:
            # Differentiate Android/Linux vs iOS/MacOS if we had window size or options
            return "Android/Linux Device"
        elif avg_ttl > 128:
            return "Network Infrastructure"
            
        return "Unknown Endpoint"

    def run_attribution(self, external_df=None):
        """Runs the full attribution pipeline on available metadata (CSV or external DF)."""
        if external_df is not None:
            df = external_df.copy()
            if 'datetime_full' not in df.columns and 'time' in df.columns:
                df['datetime_full'] = pd.to_datetime('2000-01-01 ' + df['time'])
            
            sessions = {ip: group.sort_values(by='datetime_full') 
                        for ip, group in df.groupby('dst_ip')}
        else:
            if not self.extractor.load_data():
                return {}
            sessions = self.extractor.group_by_destination()
            
        results = {}
        
        for ip, df in sessions.items():
            features = FeatureEngineer.calculate_features(df)
            if not features:
                continue
                
            pred, probs = self.predictor.predict(features)
            hostname = self.osint.get_passive_dns(ip)
            threat_intel = self.osint.correlate_threats(ip)
            os_type = self.fingerprint_os(df)
            
            context = {
                "interaction_count": int(len(df)),
                "session_start": str(df['time'].iloc[0]),
                "session_end": str(df['time'].iloc[-1]),
                "communication_duration": float(features.get("session_duration", 0.0)),
                "hostname": hostname,
                "threat_score": threat_intel["score"],
                "threat_status": threat_intel["status"],
                "threat_type": threat_intel["threat_type"],
                "device_type": os_type
            }
            
            results[ip] = {
                "predicted_network": str(pred),
                "confidence": float(max(probs.values())) if probs else 0.0,
                "probabilities": probs,
                "features": features,
                "context": context
            }
            
        return results
        
    def generate_ai_summary(self, ip, attribution_data):
        """Generates a human-readable investigation summary for a specific IP."""
        context = attribution_data.get("context", {})
        count = context.get("interaction_count", 0)
        start = context.get("session_start", "Unknown")
        end = context.get("session_end", "Unknown")
        pred = attribution_data.get("predicted_network", "Unknown")
        conf = attribution_data.get("confidence", 0) * 100
        hostname = context.get("hostname", "Unknown")
        status = context.get("threat_status", "Clean")
        device = context.get("device_type", "Unknown Device")
        
        # Build structured HTML parts
        obs = f"Suspect device interacted with **{ip}** ({hostname}) **{count} times**."
        
        forensic_info = ""
        if pred == "Messaging Infrastructure":
            forensic_info = "Traffic characteristics indicate possible use of an encrypted messaging platform."
        elif pred == "VPN Network":
            forensic_info = "Traffic matches structural signatures of an encrypted VPN tunnel."
        elif pred == "Tor Exit Node":
            forensic_info = "High probability of onion routing communication."
        else:
            forensic_info = f"Flow identified as standard communication from a **{device}**."

        summary = (
            f"<div class='summary-section'><div class='summary-label'>OBSERVATION</div><p>{obs}</p></div>"
            f"<div class='summary-grid'>"
            f"<div class='summary-item'><div class='summary-label'>DEVICE</div><strong>{device}</strong></div>"
            f"<div class='summary-item'><div class='summary-label'>CLASS</div><strong>{pred}</strong></div>"
            f"<div class='summary-item'><div class='summary-label'>CONFIDENCE</div><strong>{conf:.1f}%</strong></div>"
            f"</div>"
            f"<div class='summary-section'><div class='summary-label'>FORENSIC ANALYSIS</div><p>{forensic_info}</p></div>"
        )
        
        return summary

if __name__ == "__main__":
    attributor = EndpointAttributor()
    results = attributor.run_attribution()
    for ip, data in list(results.items())[:2]:
        logger.info(f"Attribution for {ip}: {data['predicted_network']} ({data['confidence']:.2f})")
        print(attributor.generate_ai_summary(ip, data))
