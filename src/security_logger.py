import json
import os
from datetime import datetime


LOG_FILE = "logs/security_alerts.json"


def log_security_alert(
    alert_type,
    source_ip,
    target_ip=None,
    severity="MEDIUM",
    details=None
):
    """
    Save a security alert to a JSON log file.
    """

    os.makedirs(
        os.path.dirname(LOG_FILE),
        exist_ok=True
    )

    alert = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "alert_type": alert_type,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "severity": severity,
        "details": details or {}
    }

    existing_alerts = []

    if os.path.exists(LOG_FILE):

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                existing_alerts = json.load(file)

        except (
            json.JSONDecodeError,
            OSError
        ):

            existing_alerts = []

    existing_alerts.append(alert)

    with open(
        LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            existing_alerts,
            file,
            indent=4
        )


def read_security_alerts():
    """
    Return all stored security alerts.
    """

    if not os.path.exists(LOG_FILE):
        return []

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []
