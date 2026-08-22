from scapy.all import IP, TCP

from src.capture import (
    detect_syn_flood,
    syn_tracker,
    syn_flood_alerted,
    stats
)


# Clear previous state
syn_tracker.clear()
syn_flood_alerted.clear()
stats["Alerts"] = 0


# Simulate 50 SYN attempts
# from the same source to the same target.

for source_port in range(40000, 40050):

    packet = (
        IP(
            src="10.10.10.50",
            dst="10.10.10.100"
        )
        /
        TCP(
            sport=source_port,
            dport=80,
            flags="S"
        )
    )

    detect_syn_flood(packet)


print("Alerts generated:", stats["Alerts"])

assert stats["Alerts"] == 1

print("SYN flood detection test PASSED")
