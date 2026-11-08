import unittest
import network_monitor_gui as network


class BehaviorTests(unittest.TestCase):
    def test_nmap_hostnames_and_mac(self):
        devices = network.parse_nmap_output('Nmap scan report for router (192.168.1.1)\nHost is up.\nMAC Address: AA:BB:CC:DD:EE:FF (Vendor)\nNmap scan report for 192.168.1.2\nHost is up.\n')
        self.assertEqual(devices['192.168.1.1']['hostname'], 'router')
        self.assertEqual(devices['192.168.1.1']['vendor'], 'Vendor')
        self.assertIsNone(devices['192.168.1.2']['mac'])
