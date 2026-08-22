from datetime import datetime
import time

from scapy.all import (
    sniff,
    wrpcap,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR
)


# ==========================================
# CONFIGURATION
# ==========================================

PCAP_FILE = "captures/traffic.pcap"

# Port scan detection settings
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 10


# ==========================================
# SERVICE / PORT MAPPING
# ==========================================

SERVICE_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}


# ==========================================
# TRAFFIC STATISTICS
# ==========================================

stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "Other": 0,
    "DNS": 0,
    "Alerts": 0
}


# ==========================================
# PORT SCAN TRACKING
# ==========================================

port_scan_tracker = {}

port_scan_alerted = set()


# ==========================================
# SERVICE IDENTIFICATION
# ==========================================

def get_service(source_port, destination_port):

    if destination_port in SERVICE_MAP:
        return SERVICE_MAP[destination_port]

    if source_port in SERVICE_MAP:
        return SERVICE_MAP[source_port]

    return "Unknown"


# ==========================================
# PORT SCAN DETECTION
# ==========================================

def detect_port_scan(packet):

    if IP not in packet or TCP not in packet:
        return

    tcp_flags = packet[TCP].flags

    # Detect initial TCP SYN packets.
    # SYN = 1 and ACK = 0
    if not (tcp_flags & 0x02):
        return

    if tcp_flags & 0x10:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    # Create tracking record for this source
    if source_ip not in port_scan_tracker:
        port_scan_tracker[source_ip] = []

    port_scan_tracker[source_ip].append(
        (current_time, destination_ip, destination_port)
    )

    # Remove entries older than our detection window
    recent_packets = []

    for packet_time, dst_ip, dst_port in port_scan_tracker[source_ip]:

        if current_time - packet_time <= PORT_SCAN_WINDOW:

            recent_packets.append(
                (packet_time, dst_ip, dst_port)
            )

    port_scan_tracker[source_ip] = recent_packets

    # Count unique destination ports
    unique_ports = set()

    for packet_time, dst_ip, dst_port in recent_packets:

        unique_ports.add(dst_port)

    # Trigger alert
    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        alert_key = (
            source_ip,
            destination_ip
        )

        if alert_key not in port_scan_alerted:

            port_scan_alerted.add(alert_key)

            stats["Alerts"] += 1

            print("\n")
            print("!" * 70)
            print("              🚨 SECURITY ALERT 🚨")
            print("!" * 70)

            print("Possible TCP Port Scan Detected")

            print(f"Source IP       : {source_ip}")
            print(f"Target IP       : {destination_ip}")
            print(f"Ports Scanned   : {len(unique_ports)}")

            sorted_ports = sorted(unique_ports)

            print(f"Destination Ports: {sorted_ports}")

            print(f"Detection Window: {PORT_SCAN_WINDOW} seconds")
            print(f"Threshold       : {PORT_SCAN_THRESHOLD} ports")

            print("Severity        : HIGH")

            print("!" * 70)
            print("\n")


# ==========================================
# DNS ANALYSIS
# ==========================================

def analyze_dns(packet):

    if DNS not in packet:
        return

    stats["DNS"] += 1

    dns_layer = packet[DNS]

    # DNS query
    if dns_layer.qr == 0 and DNSQR in packet:

        query = packet[DNSQR].qname

        if isinstance(query, bytes):
            query = query.decode(errors="ignore")

        print(f"DNS Query       : {query}")

    # DNS response
    elif dns_layer.qr == 1:

        print("DNS Message     : Response")


# ==========================================
# PACKET ANALYSIS
# ==========================================

def show_packet(packet):

    stats["total"] += 1

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    packet_size = len(packet)

    print("\n" + "=" * 70)

    print(f"Timestamp       : {timestamp}")
    print(f"Packet Size     : {packet_size} bytes")


    # --------------------------------------
    # IP PACKETS
    # --------------------------------------

    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        print(f"Source IP       : {source}")
        print(f"Destination IP  : {destination}")


        # ----------------------------------
        # TCP
        # ----------------------------------

        if TCP in packet:

            stats["TCP"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print("Protocol        : TCP")
            print(f"Source Port     : {source_port}")
            print(f"Destination Port: {destination_port}")

            service = get_service(
                source_port,
                destination_port
            )

            print(f"Service         : {service}")

            # Check for port scan
            detect_port_scan(packet)


        # ----------------------------------
        # UDP
        # ----------------------------------

        elif UDP in packet:

            stats["UDP"] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print("Protocol        : UDP")
            print(f"Source Port     : {source_port}")
            print(f"Destination Port: {destination_port}")

            service = get_service(
                source_port,
                destination_port
            )

            print(f"Service         : {service}")

            # DNS analysis
            if DNS in packet:

                analyze_dns(packet)


        # ----------------------------------
        # ICMP
        # ----------------------------------

        elif ICMP in packet:

            stats["ICMP"] += 1

            print("Protocol        : ICMP")


        # ----------------------------------
        # OTHER IP PROTOCOLS
        # ----------------------------------

        else:

            stats["Other"] += 1

            print("Protocol        : Other")


    # --------------------------------------
    # ARP PACKETS
    # --------------------------------------

    elif ARP in packet:

        stats["ARP"] += 1

        print("Protocol        : ARP")
        print(f"Source IP       : {packet[ARP].psrc}")
        print(f"Destination IP  : {packet[ARP].pdst}")


# ==========================================
# TRAFFIC STATISTICS
# ==========================================

def show_statistics():

    print("\n")
    print("=" * 70)
    print("                 NETWORK TRAFFIC STATISTICS")
    print("=" * 70)

    print(f"Total Packets   : {stats['total']}")
    print(f"TCP Packets     : {stats['TCP']}")
    print(f"UDP Packets     : {stats['UDP']}")
    print(f"ICMP Packets    : {stats['ICMP']}")
    print(f"ARP Packets     : {stats['ARP']}")
    print(f"Other Packets   : {stats['Other']}")
    print(f"DNS Messages    : {stats['DNS']}")
    print(f"Security Alerts : {stats['Alerts']}")

    print("=" * 70)


# ==========================================
# PROGRAM START
# ==========================================

print("=" * 70)
print("                 NETWORK TRAFFIC ANALYZER")
print("=" * 70)

print(f"Saving packets to: {PCAP_FILE}")

print("\nPort Scan Detection:")
print(f"  Threshold : {PORT_SCAN_THRESHOLD} unique ports")
print(f"  Window    : {PORT_SCAN_WINDOW} seconds")

print("\nStarting packet capture...")
print("Press CTRL+C to stop.")


# ==========================================
# PACKET CAPTURE
# ==========================================

captured_packets = []

try:

    captured_packets = sniff(
        iface=["eth0","lo"],
        prn=show_packet
)

finally:

    if captured_packets:

        wrpcap(PCAP_FILE, captured_packets)

        print(f"\nPCAP saved to: {PCAP_FILE}")

    show_statistics()

    print("\nCapture stopped.")
