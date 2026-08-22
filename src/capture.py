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

# Port scan detection
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 10

# SYN flood detection
SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 5
SYN_FLOOD_MAX_PORTS = 3


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
# SYN FLOOD TRACKING
# ==========================================

syn_tracker = {}
syn_flood_alerted = set()


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

    tcp_flags = int(packet[TCP].flags)

    # SYN must be set
    if not (tcp_flags & 0x02):
        return

    # ACK must NOT be set
    if tcp_flags & 0x10:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    if source_ip not in port_scan_tracker:
        port_scan_tracker[source_ip] = []

    port_scan_tracker[source_ip].append(
        (current_time, destination_ip, destination_port)
    )

    recent_packets = []

    for packet_time, dst_ip, dst_port in port_scan_tracker[source_ip]:

        if current_time - packet_time <= PORT_SCAN_WINDOW:

            recent_packets.append(
                (packet_time, dst_ip, dst_port)
            )

    port_scan_tracker[source_ip] = recent_packets

    unique_ports = set()

    for packet_time, dst_ip, dst_port in recent_packets:

        unique_ports.add(dst_port)

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

            print(f"Source IP        : {source_ip}")
            print(f"Target IP        : {destination_ip}")
            print(f"Ports Scanned    : {len(unique_ports)}")

            print(
                f"Destination Ports: "
                f"{sorted(unique_ports)}"
            )

            print(
                f"Detection Window : "
                f"{PORT_SCAN_WINDOW} seconds"
            )

            print(
                f"Threshold        : "
                f"{PORT_SCAN_THRESHOLD} ports"
            )

            print("Severity         : HIGH")

            print("!" * 70)
            print()


# ==========================================
# SYN FLOOD DETECTION
# ==========================================

def detect_syn_flood(packet):

    if IP not in packet or TCP not in packet:
        return

    tcp_flags = int(packet[TCP].flags)

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport

    current_time = time.time()

    # --------------------------------------
    # SYN PACKET
    # --------------------------------------

    is_syn = bool(tcp_flags & 0x02)
    is_ack = bool(tcp_flags & 0x10)

    # Pure SYN: SYN=1, ACK=0
    if is_syn and not is_ack:

        connection_key = (
            source_ip,
            destination_ip
        )

        if connection_key not in syn_tracker:

            syn_tracker[connection_key] = []

        syn_tracker[connection_key].append(
            (
                current_time,
                destination_port
            )
        )

    # --------------------------------------
    # REMOVE OLD SYN ENTRIES
    # --------------------------------------

    connection_key = (
        source_ip,
        destination_ip
    )

    if connection_key in syn_tracker:

        recent_syns = []

        for packet_time, dst_port in syn_tracker[connection_key]:

            if current_time - packet_time <= SYN_FLOOD_WINDOW:

                recent_syns.append(
                    (
                        packet_time,
                        dst_port
                    )
                )

        syn_tracker[connection_key] = recent_syns

    # --------------------------------------
    # CHECK FOR POSSIBLE SYN FLOOD
    # --------------------------------------

    if connection_key not in syn_tracker:
        return

    recent_syns = syn_tracker[connection_key]

    syn_count = len(recent_syns)

    unique_ports = set()

    for packet_time, dst_port in recent_syns:

        unique_ports.add(dst_port)

    # A flood-like pattern should generally
    # concentrate on a small number of ports.

    if (
        syn_count >= SYN_FLOOD_THRESHOLD
        and len(unique_ports) <= SYN_FLOOD_MAX_PORTS
    ):

        if connection_key not in syn_flood_alerted:

            syn_flood_alerted.add(connection_key)

            stats["Alerts"] += 1

            print("\n")
            print("!" * 70)
            print("              🚨 SECURITY ALERT 🚨")
            print("!" * 70)

            print("Possible TCP SYN Flood Detected")

            print(f"Source IP        : {source_ip}")
            print(f"Target IP        : {destination_ip}")
            print(f"SYN Attempts     : {syn_count}")

            print(
                f"Unique Ports     : "
                f"{sorted(unique_ports)}"
            )

            print(
                f"Detection Window : "
                f"{SYN_FLOOD_WINDOW} seconds"
            )

            print(
                f"Threshold        : "
                f"{SYN_FLOOD_THRESHOLD} SYNs"
            )

            print("Severity         : HIGH")

            print("!" * 70)
            print()


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

    print(f"Timestamp        : {timestamp}")
    print(f"Packet Size      : {packet_size} bytes")

    # --------------------------------------
    # IP PACKETS
    # --------------------------------------

    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        print(f"Source IP        : {source}")
        print(f"Destination IP   : {destination}")

        # ----------------------------------
        # TCP
        # ----------------------------------

        if TCP in packet:

            stats["TCP"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print("Protocol         : TCP")
            print(f"Source Port      : {source_port}")
            print(f"Destination Port : {destination_port}")

            service = get_service(
                source_port,
                destination_port
            )

            print(f"Service          : {service}")

            # Security detection
            detect_port_scan(packet)
            detect_syn_flood(packet)

        # ----------------------------------
        # UDP
        # ----------------------------------

        elif UDP in packet:

            stats["UDP"] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print("Protocol         : UDP")
            print(f"Source Port      : {source_port}")
            print(f"Destination Port : {destination_port}")

            service = get_service(
                source_port,
                destination_port
            )

            print(f"Service          : {service}")

            if DNS in packet:

                analyze_dns(packet)

        # ----------------------------------
        # ICMP
        # ----------------------------------

        elif ICMP in packet:

            stats["ICMP"] += 1

            print("Protocol         : ICMP")

        # ----------------------------------
        # OTHER IP
        # ----------------------------------

        else:

            stats["Other"] += 1

            print("Protocol         : Other")

    # --------------------------------------
    # ARP
    # --------------------------------------

    elif ARP in packet:

        stats["ARP"] += 1

        print("Protocol         : ARP")
        print(f"Source IP        : {packet[ARP].psrc}")
        print(f"Destination IP   : {packet[ARP].pdst}")


# ==========================================
# TRAFFIC STATISTICS
# ==========================================

def show_statistics():

    print("\n")
    print("=" * 70)
    print("                 NETWORK TRAFFIC STATISTICS")
    print("=" * 70)

    print(f"Total Packets    : {stats['total']}")
    print(f"TCP Packets      : {stats['TCP']}")
    print(f"UDP Packets      : {stats['UDP']}")
    print(f"ICMP Packets     : {stats['ICMP']}")
    print(f"ARP Packets      : {stats['ARP']}")
    print(f"Other Packets    : {stats['Other']}")
    print(f"DNS Messages     : {stats['DNS']}")
    print(f"Security Alerts  : {stats['Alerts']}")

    print("=" * 70)


# ==========================================
# PROGRAM START
# ==========================================

def main():

    print("=" * 70)
    print("                 NETWORK TRAFFIC ANALYZER")
    print("=" * 70)

    print(f"Saving packets to: {PCAP_FILE}")

    print("\nDetection Rules:")

    print(
        f"  Port Scan : "
        f"{PORT_SCAN_THRESHOLD}+ unique ports / "
        f"{PORT_SCAN_WINDOW}s"
    )

    print(
        f"  SYN Flood : "
        f"{SYN_FLOOD_THRESHOLD}+ SYNs / "
        f"{SYN_FLOOD_WINDOW}s"
    )

    print("\nStarting packet capture...")
    print("Press CTRL+C to stop.")

    captured_packets = []

    try:

        captured_packets = sniff(
            iface=["eth0", "lo"],
            prn=show_packet
        )

    finally:

        if captured_packets:

            wrpcap(
                PCAP_FILE,
                captured_packets
            )

            print(
                f"\nPCAP saved to: "
                f"{PCAP_FILE}"
            )

        show_statistics()

        print("\nCapture stopped.")


if __name__ == "__main__":

    main()

