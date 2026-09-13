from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import threading

app = Flask(__name__)

stats = {"total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
recent_packets = []
MAX_RECENT = 30

ip_packet_count = {}
ALERT_THRESHOLD = 15
alerted_ips = set()
alerts = []

def add_packet(timestamp, protocol, src, dst, size):
    recent_packets.append({
        "timestamp": timestamp,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "size": size
    })
    if len(recent_packets) > MAX_RECENT:
        recent_packets.pop(0)

def check_suspicious(src_ip):
    ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1
    if ip_packet_count[src_ip] > ALERT_THRESHOLD and src_ip not in alerted_ips:
        alerted_ips.add(src_ip)
        alerts.append(f"High traffic from {src_ip} ({ip_packet_count[src_ip]} packets)")

def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        stats["total"] += 1
        stats["ARP"] += 1
        add_packet(timestamp, "ARP", src_ip, dst_ip, len(packet))
        check_suspicious(src_ip)
        return

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Other"
        src_port = ""
        dst_port = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        stats["total"] += 1
        stats[protocol] += 1

        src_display = f"{src_ip}:{src_port}" if src_port else src_ip
        dst_display = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

        add_packet(timestamp, protocol, src_display, dst_display, len(packet))
        check_suspicious(src_ip)

def start_sniffing():
    sniff(prn=process_packet, iface="wlp4s0", store=False)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/data")
def data():
    return jsonify({
        "stats": stats,
        "recent_packets": list(reversed(recent_packets)),
        "alerts": alerts[-5:]
    })

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    print("Dashboard running at http://localhost:5000")
    app.run(debug=False, port=5000)
