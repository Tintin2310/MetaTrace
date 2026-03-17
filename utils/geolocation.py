import requests
import json
import os
from src.utils.config import GEO_CACHE_FILE
from src.utils.helpers import setup_logger

logger = setup_logger("geolocation")

class GeoLocator:
    def __init__(self):
        self.cache = self._load_cache()
        
    def _load_cache(self):
        if os.path.exists(GEO_CACHE_FILE):
            try:
                with open(GEO_CACHE_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
        
    def _save_cache(self):
        with open(GEO_CACHE_FILE, 'w') as f:
            json.dump(self.cache, f, indent=4)
            
    def get_location(self, ip):
        """Fetches geolocation data for an IP. Uses cache if possible."""
        # Skip local/private IPs
        if ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("10."):
             return {"city": "Local Network", "country": "Internal", "isp": "Private", "countryCode": "LOC"}

        if ip in self.cache:
            return self.cache[ip]
            
        try:
            # Using free ip-api.com (no key needed for limited requests)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            
            if data.get("status") == "success":
                geo_info = {
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "countryCode": data.get("countryCode", "UN")
                }
                self.cache[ip] = geo_info
                self._save_cache()
                return geo_info
        except Exception as e:
            logger.error(f"Geo lookup failed for {ip}: {str(e)}")
            
        return {"city": "Unknown", "country": "Unknown", "isp": "Unknown", "countryCode": "UN"}

if __name__ == "__main__":
    locator = GeoLocator()
    print(locator.get_location("8.8.8.8"))
    print(locator.get_location("1.1.1.1"))
