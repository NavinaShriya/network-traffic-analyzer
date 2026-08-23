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

from src.config_loader import load_config
from src.dns_detector import analyze_dns_query
from src.security_logger import log_security_alert


# ==========================================
# LOAD CONFIGURATION
# ==========================================

CONFIG = load_config()


# ==========================================
# CAPTURE CONFIGURATION
# ==========================================

PCAP_FILE = CONFIG["capture"]["pcap_file"]

CAPTURE_INTERFACES = CONFIG["capture"]["interfaces"]


# ==========================================
# PORT SCAN CONFIGURATION
# ==========================================

PORT_SCAN_THRESHOLD = (
    CONFIG["port_scan"]["threshold"]
)

PORT_SCAN_WINDOW = (
    CONFIG["port_scan"]["window_seconds"]
)


# ==========================================
# SYN FLOOD CONFIGURATION
# ==========================================

SYN_FLOOD_THRESHOLD = (
    CONFIG["syn_flood"]["threshold"]
)

SYN_FLOOD_WINDOW = (
    CONFIG["syn_flood"]["window_seconds"]
)

SYN_FLOOD_MAX_PORTS = (
    CONFIG["syn_flood"]["max_ports"]
)

SYN_ACK_RESPONSE_RATIO = (
    CONFIG["syn_flood"]["syn_ack_response_ratio"]
)


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
syn_ack_tracker = {}
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

    if not (tcp_flags & 0x02):
        return

    if tcp_flags & 0x10:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    if source_ip not in port_scan_tracker:
        port_scan_tracker[source_ip] = []

    port_scan_tracker[source_ip].append(
        (
            current_time,
            destination_ip,
            destination_port
        )
    )

    recent_packets = [
        entry
        for entry in port_scan_tracker[source_ip]
        if current_time - entry[0] <= PORT_SCAN_WINDOW
    ]

    port_scan_tracker[source_ip] = recent_packets

    targets = {}

    for packet_time, dst_ip, dst_port in recent_packets:

        if dst_ip not in targets:
            targets[dst_ip] = set()

        targets[dst_ip].add(dst_port)

    for target_ip, unique_ports in targets.items():

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:

            alert_key = (
                source_ip,
                target_ip
            )

            if alert_key in port_scan_alerted:
                continue

            port_scan_alerted.add(alert_key)

            stats["Alerts"] += 1

            details = {
                "ports_scanned": len(unique_ports),
                "destination_ports": sorted(unique_ports),
                "detection_window": PORT_SCAN_WINDOW,
                "threshold": PORT_SCAN_THRESHOLD
            }

            log_security_alert(
                alert_type="TCP_PORT_SCAN",
                source_ip=source_ip,
                target_ip=target_ip,
                severity="HIGH",
                details=details
            )

            print("\n")
            print("!" * 70)
            print("              🚨 SECURITY ALERT 🚨")
            print("!" * 70)

            print(
                "Possible TCP Port Scan Detected"
            )

            print(
                f"Source IP        : "
                f"{source_ip}"
            )

            print(
                f"Target IP        : "
                f"{target_ip}"
            )

            print(
                f"Ports Scanned    : "
                f"{len(unique_ports)}"
            )

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

            print(
                "Severity         : HIGH"
            )

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

    destination_port = packet[TCP].dport

    current_time = time.time()

    is_syn = bool(tcp_flags & 0x02)
    is_ack = bool(tcp_flags & 0x10)

    # --------------------------------------
    # SYN-ACK RESPONSE
    # --------------------------------------

    if is_syn and is_ack:

        response_key = (
            destination_ip,
            source_ip
        )

        if response_key not in syn_ack_tracker:
            syn_ack_tracker[response_key] = []

        syn_ack_tracker[response_key].append(
            current_time
        )

        syn_ack_tracker[response_key] = [
            response_time
            for response_time
            in syn_ack_tracker[response_key]
            if current_time - response_time <= SYN_FLOOD_WINDOW
        ]

        return

    # --------------------------------------
    # PURE SYN
    # --------------------------------------

    if not is_syn or is_ack:
        return

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

    syn_tracker[connection_key] = [
        entry
        for entry in syn_tracker[connection_key]
        if current_time - entry[0] <= SYN_FLOOD_WINDOW
    ]

    recent_syns = syn_tracker[connection_key]

    syn_count = len(recent_syns)

    # --------------------------------------
    # SYN-ACK RESPONSES
    # --------------------------------------

    response_key = (
        source_ip,
        destination_ip
    )

    recent_syn_acks = syn_ack_tracker.get(
        response_key,
        []
    )

    recent_syn_acks = [
        response_time
        for response_time
        in recent_syn_acks
        if current_time - response_time <= SYN_FLOOD_WINDOW
    ]

    syn_ack_tracker[response_key] = recent_syn_acks

    syn_ack_count = len(recent_syn_acks)

    # --------------------------------------
    # UNIQUE PORTS
    # --------------------------------------

    unique_ports = {
        dst_port
        for packet_time, dst_port
        in recent_syns
    }

    # --------------------------------------
    # RESPONSE RATIO
    # --------------------------------------

    response_ratio = (
        syn_ack_count / syn_count
        if syn_count > 0
        else 0
    )

    # --------------------------------------
    # DETECTION
    # --------------------------------------

    if (
        syn_count >= SYN_FLOOD_THRESHOLD
        and len(unique_ports) <= SYN_FLOOD_MAX_PORTS
        and response_ratio <= SYN_ACK_RESPONSE_RATIO
    ):

        alert_key = (
            source_ip,
            destination_ip
        )

        if alert_key in syn_flood_alerted:
            return

        syn_flood_alerted.add(alert_key)

        stats["Alerts"] += 1

        details = {
            "syn_attempts": syn_count,
            "syn_ack_responses": syn_ack_count,
            "response_ratio": response_ratio,
            "unique_ports": sorted(unique_ports),
            "detection_window": SYN_FLOOD_WINDOW,
            "syn_threshold": SYN_FLOOD_THRESHOLD,
            "response_limit": SYN_ACK_RESPONSE_RATIO
        }

        log_security_alert(
            alert_type="TCP_SYN_FLOOD",
            source_ip=source_ip,
            target_ip=destination_ip,
            severity="HIGH",
            details=details
        )

        print("\n")
        print("!" * 70)
        print("              🚨 SECURITY ALERT 🚨")
        print("!" * 70)

        print(
            "Possible TCP SYN Flood Detected"
        )

        print(
            f"Source IP        : "
            f"{source_ip}"
        )

        print(
            f"Target IP        : "
            f"{destination_ip}"
        )

        print(
            f"SYN Attempts     : "
            f"{syn_count}"
        )

        print(
            f"SYN-ACK Responses: "
            f"{syn_ack_count}"
        )

        print(
            f"Response Ratio   : "
            f"{response_ratio:.2%}"
        )

        print(
            f"Unique Ports     : "
            f"{sorted(unique_ports)}"
        )

        print(
            f"Detection Window : "
            f"{SYN_FLOOD_WINDOW} seconds"
        )

        print(
            f"SYN Threshold    : "
            f"{SYN_FLOOD_THRESHOLD}"
        )

        print(
            f"Response Limit   : "
            f"{SYN_ACK_RESPONSE_RATIO:.0%}"
        )

        print(
            "Severity         : HIGH"
        )

        print("!" * 70)
        print()


# ==========================================
# DNS ANALYSIS
# ==========================================

def analyze_dns(packet):

    if DNS not in packet:
        return

    dns_layer = packet[DNS]

    if dns_layer.qr != 0:
        return

    if DNSQR not in packet:
        return

    query = packet[DNSQR].qname

    if isinstance(query, bytes):
        query = query.decode(
            errors="ignore"
        )

    source_ip = packet[IP].src

    print(
        f"DNS Query        : "
        f"{query}"
    )

    alerts = analyze_dns_query(
        source_ip=source_ip,
        domain=query
    )

    stats["DNS"] += 1
    stats["Alerts"] += alerts


# ==========================================
# PACKET ANALYSIS
# ==========================================

def show_packet(packet):

    stats["total"] += 1

    timestamp = datetime.now().strftime(
        "%H:%M:%S.%f"
    )[:-3]

    packet_size = len(packet)

    print("\n" + "=" * 70)

    print(
        f"Timestamp        : "
        f"{timestamp}"
    )

    print(
        f"Packet Size      : "
        f"{packet_size} bytes"
    )

    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        print(
            f"Source IP        : "
            f"{source}"
        )

        print(
            f"Destination IP   : "
            f"{destination}"
        )

        if TCP in packet:

            stats["TCP"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print("Protocol         : TCP")

            print(
                f"Source Port      : "
                f"{source_port}"
            )

            print(
                f"Destination Port : "
                f"{destination_port}"
            )

            service = get_service(
                source_port,
                destination_port
            )

            print(
                f"Service          : "
                f"{service}"
            )

            detect_port_scan(packet)
            detect_syn_flood(packet)

        elif UDP in packet:

            stats["UDP"] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print("Protocol         : UDP")

            print(
                f"Source Port      : "
                f"{source_port}"
            )

            print(
                f"Destination Port : "
                f"{destination_port}"
            )

            service = get_service(
                source_port,
                destination_port
            )

            print(
                f"Service          : "
                f"{service}"
            )

            if DNS in packet:
                analyze_dns(packet)

        elif ICMP in packet:

            stats["ICMP"] += 1

            print(
                "Protocol         : "
                "ICMP"
            )

        else:

            stats["Other"] += 1

            print(
                "Protocol         : "
                "Other"
            )

    elif ARP in packet:

        stats["ARP"] += 1

        print(
            "Protocol         : "
            "ARP"
        )

        print(
            f"Source IP        : "
            f"{packet[ARP].psrc}"
        )

        print(
            f"Destination IP   : "
            f"{packet[ARP].pdst}"
        )


# ==========================================
# STATISTICS
# ==========================================

def show_statistics():

    print("\n")
    print("=" * 70)

    print(
        "                 "
        "NETWORK TRAFFIC STATISTICS"
    )

    print("=" * 70)

    print(
        f"Total Packets    : "
        f"{stats['total']}"
    )

    print(
        f"TCP Packets      : "
        f"{stats['TCP']}"
    )

    print(
        f"UDP Packets      : "
        f"{stats['UDP']}"
    )

    print(
        f"ICMP Packets     : "
        f"{stats['ICMP']}"
    )

    print(
        f"ARP Packets      : "
        f"{stats['ARP']}"
    )

    print(
        f"Other Packets    : "
        f"{stats['Other']}"
    )

    print(
        f"DNS Queries      : "
        f"{stats['DNS']}"
    )

    print(
        f"Security Alerts  : "
        f"{stats['Alerts']}"
    )

    print("=" * 70)


# ==========================================
# MAIN
# ==========================================

def main():

    print("=" * 70)

    print(
        "                 "
        "NETWORK TRAFFIC ANALYZER"
    )

    print("=" * 70)

    print(
        f"Saving packets to: "
        f"{PCAP_FILE}"
    )

    print("\nConfiguration loaded:")

    print(
        f"  Interfaces      : "
        f"{CAPTURE_INTERFACES}"
    )

    print(
        f"  Port Scan       : "
        f"{PORT_SCAN_THRESHOLD} ports / "
        f"{PORT_SCAN_WINDOW}s"
    )

    print(
        f"  SYN Flood       : "
        f"{SYN_FLOOD_THRESHOLD} SYNs / "
        f"{SYN_FLOOD_WINDOW}s"
    )

    print(
        f"  Max SYN Ports   : "
        f"{SYN_FLOOD_MAX_PORTS}"
    )

    print(
        f"  SYN-ACK Limit   : "
        f"{SYN_ACK_RESPONSE_RATIO:.0%}"
    )

    print(
        "\nStarting packet capture..."
    )

    print(
        "Press CTRL+C to stop."
    )

    captured_packets = []

    try:

        captured_packets = sniff(
            iface=CAPTURE_INTERFACES,
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


# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
