from src.dns_detector import (
    analyze_dns_query,
    reset_dns_detector
)


# ==========================================
# TEST 1 — NORMAL DNS ACTIVITY
# ==========================================

reset_dns_detector()

alerts = 0

for i in range(5):

    alerts += analyze_dns_query(
        source_ip="10.10.10.50",
        domain="example.com",
        current_time=i
    )

assert alerts == 0

print("Test 1 PASSED: Normal DNS activity")


# ==========================================
# TEST 2 — HIGH DNS QUERY RATE
# ==========================================

reset_dns_detector()

alerts = 0

for i in range(20):

    alerts += analyze_dns_query(
        source_ip="10.10.10.50",
        domain="example.com",
        current_time=i * 0.1
    )

assert alerts >= 1

print("Test 2 PASSED: High DNS query rate detected")


# ==========================================
# TEST 3 — LONG DOMAIN
# ==========================================

reset_dns_detector()

long_domain = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "cccccccccccccccccccccccccccccccc"
    ".example.com"
)

alerts = analyze_dns_query(
    source_ip="10.10.10.50",
    domain=long_domain,
    current_time=0
)

assert alerts >= 1

print("Test 3 PASSED: Long DNS domain detected")


# ==========================================
# FINAL RESULT
# ==========================================

print()
print("=" * 60)
print("ALL DNS DETECTION TESTS PASSED")
print("=" * 60)
