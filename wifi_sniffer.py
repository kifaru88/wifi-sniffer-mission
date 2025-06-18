# wifi_sniffer.py
from scapy.all import *
import time

# Store unique SSIDs
networks = {}

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        bssid = pkt[Dot11].addr2
        if bssid not in networks:
            networks[bssid] = ssid
            print(f"[+] Detected SSID: {ssid} | BSSID: {bssid}")

def start_sniff(interface):
    print(f"[*] Starting Wi-Fi scan on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simple Wi-Fi Sniffer using Scapy")
    parser.add_argument("interface", help="Wi-Fi interface in monitor mode")
    args = parser.parse_args()

    try:
        start_sniff(args.interface)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        print("[*] Found networks:")
        for bssid, ssid in networks.items():
            print(f"{bssid} - {ssid}")


