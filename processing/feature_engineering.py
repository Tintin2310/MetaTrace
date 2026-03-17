import pandas as pd
import numpy as np
from src.utils.helpers import setup_logger

logger = setup_logger("feature_engineering")

class FeatureEngineer:
    @staticmethod
    def calculate_features(ip_group_df):
        """
        Calculates ML features from an IP group dataframe.
        Expected columns: time, src_ip, dst_ip, packet_size, port, protocol, datetime_full
        """
        if ip_group_df.empty:
            return None
            
        # Time-based features
        time_diffs = ip_group_df['datetime_full'].diff().dt.total_seconds().dropna()
        
        session_duration = 0
        if len(ip_group_df) > 1:
            session_duration = (ip_group_df['datetime_full'].iloc[-1] - ip_group_df['datetime_full'].iloc[0]).total_seconds()
            
        # Frequency (packets per second)
        packet_frequency = len(ip_group_df) / max(1.0, session_duration)
        
        # Burst rate (max packets in a 1-second window rough estimate)
        # Using simple density approximation
        burst_rate = len(ip_group_df) / max(1.0, len(time_diffs[time_diffs > 1]) + 1)
        
        # Packet size stats
        avg_packet_size = ip_group_df['packet_size'].mean()
        packet_size_variance = ip_group_df['packet_size'].var()
        if pd.isna(packet_size_variance):
            packet_size_variance = 0.0

        # Most common port
        mode_port_series = ip_group_df['port'].mode()
        port = mode_port_series.iloc[0] if not mode_port_series.empty else 0
        
        return {
            "avg_packet_size": float(avg_packet_size),
            "packet_frequency": float(packet_frequency),
            "session_duration": float(session_duration),
            "burst_rate": float(burst_rate),
            "packet_size_variance": float(packet_size_variance),
            "port": int(port),
            "interaction_count": int(len(ip_group_df))
        }

if __name__ == "__main__":
    # Test with dummy data
    from src.processing.metadata_extractor import MetadataExtractor
    extractor = MetadataExtractor()
    if extractor.load_data():
        sessions = extractor.group_by_destination()
        for ip, df in list(sessions.items())[:2]:
            features = FeatureEngineer.calculate_features(df)
            logger.info(f"Features for {ip}: {features}")
