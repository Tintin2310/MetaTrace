import sys
import os
import unittest
from scapy.all import IP, UDP
try:
    from scapy.contrib.stun import STUN
except ImportError:
    STUN = None

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.analysis.vpn_analyzer import VPNForensicAnalyzer
from src.analysis.app_detector import AppDetector
from src.utils.osint_engine import OSINTEngine

class TestRealTimeFeatures(unittest.TestCase):
    def setUp(self):
        self.vpn_analyzer = VPNForensicAnalyzer()
        self.app_detector = AppDetector(telegram_ips_path="data/telegram_ips.json")
        self.osint = OSINTEngine()

    def test_telegram_detection(self):
        # Known Telegram IP
        self.assertTrue(self.app_detector.is_telegram("149.154.167.51"))
        # Non-Telegram IP
        self.assertFalse(self.app_detector.is_telegram("8.8.8.8"))

    def test_tor_differentiation(self):
        # Test Exit Node
        threat = self.osint.correlate_threats("198.51.100.1")
        self.assertEqual(threat["tor_type"], "Tor Exit Node")
        self.assertEqual(threat["status"], "Suspicious")
        
        # Test Guard Node
        threat = self.osint.correlate_threats("198.51.100.2")
        self.assertEqual(threat["tor_type"], "Tor Guard Node")

    @unittest.skipIf(STUN is None, "Scapy STUN contrib not available")
    def test_stun_leak_detection(self):
        # Create a mock STUN Binding Request
        # 0x0001 is Binding Request
        pkt = IP(src="192.168.1.5", dst="3.4.5.6")/UDP(sport=3478, dport=3478)/STUN(stun_message_type=0x0001)
        
        # We need to set VPN status to active for leak detection
        # This requires mocking check_vpn_status or ensuring environment allows it.
        # For this test, we assume the logic flows if we bypass the guard or mock it.
        
        # Mocking check_vpn_status in vpn_analyzer for test
        import src.utils.helpers
        original_check = src.utils.helpers.check_vpn_status
        src.utils.helpers.check_vpn_status = lambda: (True, "tun0")
        
        leak = self.vpn_analyzer.extract_hidden_metadata(pkt)
        src.utils.helpers.check_vpn_status = original_check
        
        self.assertIsNotNone(leak)
        self.assertEqual(leak["source"], "STUN/TURN Leak (WebRTC Bypass)")
        self.assertEqual(leak["real_ip"], "192.168.1.5")

if __name__ == '__main__':
    unittest.main()
