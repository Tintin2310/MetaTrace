import pandas as pd
from src.utils.config import BURST_TIME_WINDOW_SEC, BURST_PACKET_THRESHOLD
from src.utils.helpers import setup_logger

logger = setup_logger("burst_detection")

class BurstDetector:
    @staticmethod
    def detect_bursts(df, window_sec=BURST_TIME_WINDOW_SEC, threshold=BURST_PACKET_THRESHOLD):
        """
        Detects bursts of communication in a dataframe of network metadata.
        Returns a list of detected bursts.
        """
        if df is None or df.empty or 'datetime_full' not in df.columns:
            return []
            
        # Sort by time
        df_sorted = df.sort_values(by='datetime_full')
        
        # Set datetime as index for rolling window calculation
        df_indexed = df_sorted.set_index('datetime_full')
        
        # Count packets within rolling windows
        rolling_counts = df_indexed.rolling(f'{window_sec}s').count()['time']
        
        bursts = []
        in_burst = False
        burst_start = None
        max_intensity = 0
        current_count = 0
        
        for timestamp, count in rolling_counts.items():
            if count >= threshold:
                if not in_burst:
                    in_burst = True
                    burst_start = timestamp
                    current_count = count
                    max_intensity = count
                else:
                    max_intensity = max(max_intensity, count)
                    current_count += 1
            else:
                if in_burst:
                    # Burst ended
                    bursts.append({
                        "burst_start": burst_start.strftime("%H:%M:%S"),
                        "burst_end": timestamp.strftime("%H:%M:%S"),
                        "packet_count": int(current_count),
                        "burst_intensity": int(max_intensity),
                        "window_sec": int(window_sec)
                    })
                    in_burst = False
                    burst_start = None
                    max_intensity = 0
                    current_count = 0
                    
        # Handle burst active at the end of the dataframe
        if in_burst:
            bursts.append({
                "burst_start": burst_start.strftime("%H:%M:%S"),
                "burst_end": df_sorted['datetime_full'].iloc[-1].strftime("%H:%M:%S"),
                "packet_count": int(current_count),
                "burst_intensity": int(max_intensity),
                "window_sec": int(window_sec)
            })
            
        return bursts

if __name__ == "__main__":
    from src.processing.metadata_extractor import MetadataExtractor
    extractor = MetadataExtractor()
    if extractor.load_data():
        sessions = extractor.group_by_destination()
        # Find an IP that likely has bursts (e.g. Messaging or CDN)
        for ip, df in list(sessions.items())[:3]:
            # Lower threshold for testing synthetic data
            bursts = BurstDetector.detect_bursts(df, threshold=10)
            logger.info(f"Bursts for {ip}: {len(bursts)} bursts found.")
