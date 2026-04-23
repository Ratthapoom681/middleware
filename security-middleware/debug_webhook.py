"""
Debug script to simulate a Wazuh Integration push event.
Sends a mock Wazuh alert JSON to the local Middleware Webhook endpoint.
"""

import requests
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# A realistic Wazuh JSON alert payload
MOCK_ALERT = {
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
    "rule": {
        "level": 12,
        "description": "sshd: Insecure connection attempt (Test Alert)",
        "id": "5710",
        "mitre": {
            "id": ["T1110.001"],
            "tactic": ["Credential Access"]
        },
        "groups": ["syslog", "sshd", "authentication_failure"]
    },
    "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "10.0.0.45"
    },
    "manager": {
        "name": "wazuh-manager"
    },
    "id": "1675849301.29384",
    "cluster": {
        "name": "wazuh",
        "node": "worker1"
    },
    "location": "/var/log/auth.log"
}

WEBHOOK_URL = "http://127.0.0.1:5000/api/webhook/wazuh"

def main():
    logging.info(f"Sending mock alert to {WEBHOOK_URL}")
    try:
        resp = requests.post(
            WEBHOOK_URL,
            json=MOCK_ALERT,     # Single object, not a list (matches integration behavior)
            timeout=10
        )
        resp.raise_for_status()
        logging.info(f"Success! Response: {resp.text}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Connection Failed. Is the server running? (python -m app.server)")
    except Exception as e:
        logging.error(f"Failed to post: {e}")
        if 'resp' in locals():
            logging.error(f"Status Code: {resp.status_code}")
            logging.error(f"Response Body: {resp.text}")

if __name__ == "__main__":
    main()
