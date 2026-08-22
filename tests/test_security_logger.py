import json
import os

from src.security_logger import (
    log_security_alert,
    read_security_alerts,
    LOG_FILE
)


# ==========================================
# CLEAN PREVIOUS TEST LOG
# ==========================================

if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)


# ==========================================
# TEST 1 — WRITE ALERT
# ==========================================

log_security_alert(
    alert_type="TCP_PORT_SCAN",
    source_ip="10.10.10.50",
    target_ip="10.10.10.100",
    severity="HIGH",
    details={
        "ports_scanned": 15
    }
)


# ==========================================
# TEST 2 — FILE EXISTS
# ==========================================

assert os.path.exists(LOG_FILE)

print("Test 1 PASSED: Alert log created")


# ==========================================
# TEST 3 — READ ALERT
# ==========================================

alerts = read_security_alerts()

assert len(alerts) == 1

alert = alerts[0]

assert alert["alert_type"] == "TCP_PORT_SCAN"
assert alert["source_ip"] == "10.10.10.50"
assert alert["target_ip"] == "10.10.10.100"
assert alert["severity"] == "HIGH"


print("Test 2 PASSED: Alert data stored correctly")


# ==========================================
# TEST 4 — VALID JSON
# ==========================================

with open(
    LOG_FILE,
    "r",
    encoding="utf-8"
) as file:

    data = json.load(file)


assert isinstance(data, list)
assert len(data) == 1

print("Test 3 PASSED: Valid JSON generated")


# ==========================================
# FINAL RESULT
# ==========================================

print()
print("=" * 60)
print("ALL SECURITY LOGGER TESTS PASSED")
print("=" * 60)
