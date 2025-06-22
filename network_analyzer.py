import sys
import pyshark
import requests
import folium
import time
from folium.plugins import MarkerCluster
import socket
from collections import defaultdict
import json
import os
def is_valid_ip(ip):
    """تحقق من أن عنوان IP صالح وغير محلي"""
    try:
        # تحقق من أن العنوان يتكون من 4 أجزاء رقمية
        parts = list(map(int, ip.split('.')))
        if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
            return False
        
        # استبعاد العناوين الخاصة (Private IPs)
        private_ranges = [
            ("10.", 1),
            ("172.16.", 2),
            ("192.168.", 2),
            ("169.254.", 2)
        ]
        return not any(ip.startswith(prefix) for prefix, _ in private_ranges)
    
    except (ValueError, AttributeError):
        return False

def analyze_pcap(pcap_file):
    """تحليل ملف PCAP واستخراج عناوين IP صالحة"""
    try:
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter='ip',
            keep_packets=False  # لتقليل استخدام الذاكرة
        )
        unique_ips = set()
        
        print("\n🔍 Analyzing network traffic...")
        for packet in capture:
            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                if is_valid_ip(src_ip):
                    unique_ips.add(src_ip)
                if is_valid_ip(dst_ip):
                    unique_ips.add(dst_ip)
                    
            except AttributeError:
                continue
            except Exception as e:
                print(f"⚠️ Packet error: {e}")
        
        capture.close()
        return sorted(unique_ips) if unique_ips else None
    
    except Exception as e:
        print(f"❌ Error reading PCAP file: {e}")
        return None

def fetch_geolocation(ip):
    """جلب البيانات الجغرافية لعنوان IP"""
    try:
        response = requests.get(f'https://ipwhois.app/json/{ip}', timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('success', False):
                return {
                    'ip': ip,
                    'lat': data.get('latitude'),
                    'lon': data.get('longitude'),
                    'country': data.get('country'),
                    'city': data.get('city')
                }
        return None
    except Exception as e:
        print(f"⚠️ Geolocation failed for {ip}: {e}")
        return None

def create_map(geo_data):
    """إنشاء خريطة تفاعلية من البيانات الجغرافية"""
    if not geo_data:
        return None
    
    m = folium.Map(
        location=[geo_data[0]['lat'], geo_data[0]['lon']],
        zoom_start=2,
        tiles="CartoDB dark_matter"
    )
    
    marker_cluster = MarkerCluster().add_to(m)
    
    for loc in geo_data:
        popup_text = f"""
        <b>IP:</b> {loc['ip']}<br>
        <b>Location:</b> {loc.get('city', 'N/A')}, {loc.get('country', 'N/A')}<br>
        <b>Coordinates:</b> {loc['lat']:.4f}, {loc['lon']:.4f}
        """
        folium.Marker(
            location=[loc['lat'], loc['lon']],
            popup=folium.Popup(popup_text, max_width=250),
            icon=folium.Icon(color="lightblue", icon="globe")
        ).add_to(marker_cluster)
    
    return m
def save_results(data, filename='analysis_results.json'):
    """حفظ نتائج التحليل في ملف JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"✅ Results saved to {filename}")
    except Exception as e:
        print(f"❌ Failed to save results: {e}")

def main(pcap_file):
    """الدالة الرئيسية لتحليل ملف PCAP"""
    if not (pcap_file.endswith('.pcap') or pcap_file.endswith('.pcapng')):
        print("❌ Only PCAP/PCAPNG files are supported")
        return
    
    unique_ips = analyze_pcap(pcap_file)
    if not unique_ips:
        print("❌ No valid IP addresses found in the capture file.")
        return
    
    print(f"\n🌍 Found {len(unique_ips)} unique external IPs. Fetching locations...")
    
    geo_data = []
    country_distribution = defaultdict(int)
    for ip in unique_ips:
        location = fetch_geolocation(ip)
        if location:
            geo_data.append(location)
            country_distribution[location['country']] += 1
        time.sleep(1.2)  # تجنب حظر API
    
    if not geo_data:
        print("❌ No geolocation data available for the IPs.")
        return
    
    # إنشاء مجلد النتائج إذا لم يكن موجوداً
    os.makedirs('results', exist_ok=True)
    
    # حفظ النتائج في ملف JSON
    results_data = {
        'filename': os.path.basename(pcap_file),
        'filesize': f"{os.path.getsize(pcap_file)/1024/1024:.2f} MB",
        'analysis_time': '10 ثواني',  # يمكن استبدالها بوقت حقيقي
        'packets_count': len(unique_ips),
        'ip_count': len(unique_ips),
        'country_count': len(country_distribution),
        'country_distribution': country_distribution,
        'geo_data': geo_data
    }
    
    with open('results/analysis_results.json', 'w') as f:
        json.dump(results_data, f, indent=4)
    
    print("\n📍 Geolocation results:")
    for loc in geo_data:
        print(f"- {loc['ip']}: {loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}")

    print("\n🗺️ Generating map...")
    m = create_map(geo_data)
    if m:
        m.save("templates/network_map.html")
        print(f"\n✅ Map successfully saved to 'templates/network_map.html'")
        
        print("\n🌐 Country Distribution:")
        for country, count in country_distribution.items():
            print(f"- {country}: {count} IPs")
if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python network_analyzer.py <pcap_file>")