import pandas as pd
from src.utils.config import METADATA_FILE
from src.utils.helpers import setup_logger

logger = setup_logger("metadata_extractor")

class MetadataExtractor:
    def __init__(self, metadata_path=METADATA_FILE):
        self.metadata_path = metadata_path
        self.df = None
        
    def load_data(self):
        """Loads metadata from CSV."""
        try:
            self.df = pd.read_csv(self.metadata_path)
            # Ensure time is datetime dtype for time-based calculations
            self.df['time_obj'] = pd.to_datetime(self.df['time'], format="%H:%M:%S").dt.time
            # For duration math, we create a full dummy datetime
            self.df['datetime_full'] = pd.to_datetime('2000-01-01 ' + self.df['time'])
            logger.info(f"Loaded {len(self.df)} metadata records.")
            return True
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
            return False

    def group_by_destination(self):
        """Groups packets by destination IP to analyze sessions."""
        if self.df is None:
            return {}
            
        grouped = self.df.groupby('dst_ip')
        sessions = {}
        
        for ip, group in grouped:
            sessions[ip] = group.sort_values(by='datetime_full')
            
        return sessions
        
if __name__ == "__main__":
    extractor = MetadataExtractor()
    if extractor.load_data():
        sessions = extractor.group_by_destination()
        logger.info(f"Extracted {len(sessions)} unique destination IPs.")
