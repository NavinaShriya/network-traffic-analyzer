from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


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
    "Other": 0
}


# ==========================================
# SERVICE IDENTIFICATION
# ==========================================

def get_service(port):
    return SERVICE_MAP.get(port, "Unknown")


# ==========================================
# PACKET ANALYSIS
# ==========================================

def show_packet(packet):

    stats["total"] += 1

    print("\n" + "=" * 60)

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

            service = get_service(destination_port)

            print(f"Service         : {service}")

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

            service = get_service(destination_port)

            print(f"Service         : {service}")

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
    print("=" * 60)
    print("           NETWORK TRAFFIC STATISTICS")
    print("=" * 60)

    print(f"Total Packets   : {stats['total']}")
    print(f"TCP Packets     : {stats['TCP']}")
    print(f"UDP Packets     : {stats['UDP']}")
    print(f"ICMP Packets    : {stats['ICMP']}")
    print(f"ARP Packets     : {stats['ARP']}")
    print(f"Other Packets   : {stats['Other']}")

    print("=" * 60)


# ==========================================
# PROGRAM START
# ==========================================

print("=" * 60)
print("          NETWORK TRAFFIC ANALYZER")
print("=" * 60)

print("Starting packet capture...")
print("Press CTRL+C to stop.")


try:

    sniff(prn=show_packet)


finally:

    show_statistics()

    print("\nCapture stopped.")
