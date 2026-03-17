import logging
import psutil

def setup_logger(name, level=logging.INFO):
    """Sets up a standardized logger."""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate logs if instantiated multiple times
    if not logger.handlers:
        logger.addHandler(ch)
        
    return logger

def check_vpn_status():
    """Checks if a VPN connection is likely active (looking for tunnel interfaces)."""
    vpn_keywords = ['tun', 'tap', 'vpn', 'ppp', 'wireguard', 'tailscale']
    try:
        stats = psutil.net_if_stats()
        for iface, data in stats.items():
            if any(key in iface.lower() for key in vpn_keywords) and data.isup:
                return True, iface
    except:
        pass
    return False, None
