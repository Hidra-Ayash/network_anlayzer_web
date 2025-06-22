import sys
import pyshark
import requests
import folium
import time
from folium.plugins import MarkerCluster
import socket

# ... (بقية الاستيرادات كما هي)

def analyze_pcap(pcap_file):
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter='ip')
        unique_ips = set()
        
        print("\n🔍 Analyzing network traffic...")
        for packet in capture:
            try:
                ip = packet.ip.dst
                if is_valid_ip(ip):
                    unique_ips.add(ip)
            except AttributeError:
                continue
                
        return sorted(unique_ips)
    except Exception as e:
        print(f"❌ Error reading PCAP file: {e}")
        return []

def main(pcap_file):
    unique_ips = analyze_pcap(pcap_file)
    
    if not unique_ips:
        print("❌ No valid IP addresses found in the capture file.")
        return

    # ... (بقية الدوال كما هي)
    
    # إنشاء الخريطة
    if geo_data:
        m = create_map(geo_data)
        if m:
            m.save("network_map.html")
            print(f"\n✅ Map successfully saved to 'network_map.html'")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python network_analyzer.py <pcap_file>")