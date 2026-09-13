from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import matplotlib.pyplot as plt
import csv
from colorama import Fore, Style, init

init(autoreset=True)

# Statistics tracking
stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "Other": 0
}

# List to store packet details for CSV export
captured_packets = []

# Track how many packets each source IP has sent (for suspicious activity detection)
ip_packet_count = {}
ALERT_THRESHOLD = 15  # if one IP sends more than this many packets, flag it
alerted_ips = set()

# Colors for each protocol
protocol_colors = {
    "TCP": Fore.BLUE,
    "UDP": Fore.YELLOW,
    "ICMP": Fore.RED,
    "ARP": Fore.MAGENTA,
    "Other": Fore.GREEN
}

def check_suspicious(src_ip, protocol):
    ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1

    if ip_packet_count[src_ip] > ALERT_THRESHOLD and src_ip not in alerted_ips:
        alerted_ips.add(src_ip)
        print(f"{Fore.RED}{Style.BRIGHT}[ALERT] Unusually high traffic from {src_ip} "
              f"({ip_packet_count[src_ip]} packets) - possible scan or flood{Style.RESET_ALL}")

def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    # ARP works differently - it doesn't have an IP layer
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        stats["total"] += 1
        stats["ARP"] += 1

        color = protocol_colors["ARP"]
        print(f"{color}[{timestamp}] ARP   | {src_ip} -> {dst_ip} | Who has {dst_ip}?{Style.RESET_ALL}")

        check_suspicious(src_ip, "ARP")

        captured_packets.append({
            "timestamp": timestamp,
            "protocol": "ARP",
            "src_ip": src_ip,
            "src_port": "",
            "dst_ip": dst_ip,
            "dst_port": "",
            "size_bytes": len(packet)
        })
        return

    # Everything else needs the IP layer
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

        packet_size = len(packet)

        stats["total"] += 1
        stats[protocol] += 1

        color = protocol_colors[protocol]

        if protocol == "ICMP":
            print(f"{color}[{timestamp}] {protocol:5} | {src_ip} -> {dst_ip} | Size: {packet_size} bytes{Style.RESET_ALL}")
        else:
            print(f"{color}[{timestamp}] {protocol:5} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Size: {packet_size} bytes{Style.RESET_ALL}")

        check_suspicious(src_ip, protocol)

        captured_packets.append({
            "timestamp": timestamp,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "size_bytes": packet_size
        })

def save_to_csv():
    if not captured_packets:
        print("No packets to save.")
        return

    filename = "captured_packets.csv"
    fieldnames = ["timestamp", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "size_bytes"]

    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(captured_packets)

    print(f"Packet data saved to {filename}")

def show_chart():
    labels = []
    values = []

    for protocol in ["TCP", "UDP", "ICMP", "ARP", "Other"]:
        if stats[protocol] > 0:
            labels.append(protocol)
            values.append(stats[protocol])

    if not values:
        print("No data to chart.")
        return

    color_map = {"TCP": "#3B82F6", "UDP": "#F97316", "ICMP": "#EF4444", "ARP": "#A855F7", "Other": "#10B981"}
    colors = [color_map[label] for label in labels]

    plt.style.use("seaborn-v0_8-darkgrid")
    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(labels, values, color=colors, width=0.5, edgecolor="white", linewidth=1.5)

    ax.set_title("Network Traffic by Protocol", fontsize=16, fontweight="bold", pad=20)
    ax.set_xlabel("Protocol", fontsize=12, labelpad=10)
    ax.set_ylabel("Number of Packets", fontsize=12, labelpad=10)
    ax.tick_params(axis="both", labelsize=11)

    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.02,
                 str(value), ha="center", fontsize=12, fontweight="bold")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.savefig("traffic_chart.png", dpi=150)
    print("Chart saved as traffic_chart.png")
    plt.show()

print("=" * 80)
print(f"{Style.BRIGHT}Network Traffic Analyzer - Started{Style.RESET_ALL}")
print("Capturing for 10 seconds...")
print("=" * 80)

sniff(prn=process_packet, iface="wlp4s0", timeout=10)

print("\n" + "=" * 80)
print(f"{Style.BRIGHT}CAPTURE SUMMARY{Style.RESET_ALL}")
print("=" * 80)
print(f"Total packets captured : {stats['total']}")
print(f"{Fore.BLUE}TCP packets             : {stats['TCP']}{Style.RESET_ALL}")
print(f"{Fore.YELLOW}UDP packets             : {stats['UDP']}{Style.RESET_ALL}")
print(f"{Fore.RED}ICMP packets            : {stats['ICMP']}{Style.RESET_ALL}")
print(f"{Fore.MAGENTA}ARP packets             : {stats['ARP']}{Style.RESET_ALL}")
print(f"{Fore.GREEN}Other packets           : {stats['Other']}{Style.RESET_ALL}")
print("=" * 80)

save_to_csv()
show_chart()
