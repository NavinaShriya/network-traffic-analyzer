import time
from collections import defaultdict


# ==========================================
# DNS DETECTION CONFIGURATION
# ==========================================

DNS_QUERY_THRESHOLD = 20
DNS_QUERY_WINDOW = 10

MAX_DOMAIN_LENGTH = 100


# ==========================================
# DNS TRACKING
# ==========================================

dns_query_tracker = defaultdict(list)

dns_alerted_sources = set()


# ==========================================
# DNS QUERY RATE DETECTION
# ==========================================

def detect_dns_query_rate(source_ip, current_time=None):

    if current_time is None:
        current_time = time.time()

    # Add current query
    dns_query_tracker[source_ip].append(current_time)

    # Keep only recent queries
    dns_query_tracker[source_ip] = [
        query_time
        for query_time in dns_query_tracker[source_ip]
        if current_time - query_time <= DNS_QUERY_WINDOW
    ]

    query_count = len(
        dns_query_tracker[source_ip]
    )

    # --------------------------------------
    # HIGH DNS QUERY RATE
    # --------------------------------------

    if query_count >= DNS_QUERY_THRESHOLD:

        if source_ip not in dns_alerted_sources:

            dns_alerted_sources.add(source_ip)

            print("\n")
            print("!" * 70)
            print("              🚨 SECURITY ALERT 🚨")
            print("!" * 70)

            print(
                "Possible High-Rate DNS Activity"
            )

            print(
                f"Source IP        : "
                f"{source_ip}"
            )

            print(
                f"DNS Queries      : "
                f"{query_count}"
            )

            print(
                f"Detection Window : "
                f"{DNS_QUERY_WINDOW} seconds"
            )

            print(
                f"Threshold        : "
                f"{DNS_QUERY_THRESHOLD} queries"
            )

            print("Severity         : MEDIUM")

            print("!" * 70)
            print()


            return True

    return False


# ==========================================
# DOMAIN LENGTH DETECTION
# ==========================================

def detect_long_domain(domain, source_ip):

    if not domain:
        return False

    # Remove trailing DNS dot
    domain = domain.rstrip(".")

    domain_length = len(domain)

    if domain_length > MAX_DOMAIN_LENGTH:

        print("\n")
        print("!" * 70)
        print("              🚨 SECURITY ALERT 🚨")
        print("!" * 70)

        print(
            "Unusually Long DNS Domain"
        )

        print(
            f"Source IP        : "
            f"{source_ip}"
        )

        print(
            f"Domain           : "
            f"{domain}"
        )

        print(
            f"Domain Length    : "
            f"{domain_length}"
        )

        print(
            f"Length Threshold : "
            f"{MAX_DOMAIN_LENGTH}"
        )

        print(
            "Severity         : MEDIUM"
        )

        print("!" * 70)
        print()

        return True

    return False


# ==========================================
# COMPLETE DNS ANALYSIS
# ==========================================

def analyze_dns_query(
    source_ip,
    domain,
    current_time=None
):

    alerts = 0

    # Detect high query rate
    if detect_dns_query_rate(
        source_ip,
        current_time
    ):

        alerts += 1

    # Detect unusually long domain
    if detect_long_domain(
        domain,
        source_ip
    ):

        alerts += 1

    return alerts


# ==========================================
# RESET DETECTOR
# ==========================================

def reset_dns_detector():

    dns_query_tracker.clear()

    dns_alerted_sources.clear()
