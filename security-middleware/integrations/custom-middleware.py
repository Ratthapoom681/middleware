#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Custom Wazuh Integration Script to Push to Security Middleware Webhook.

To use:
1. Place this file in: /var/ossec/integrations/custom-middleware.py
2. Make it executable: chmod 750 /var/ossec/integrations/custom-middleware.py
3. Set permissions: chown root:wazuh /var/ossec/integrations/custom-middleware.py
4. Add to /var/ossec/etc/ossec.conf:
  <integration>
    <name>custom-middleware</name>
    <hook_url>http://YOUR_MIDDLEWARE_IP:5000/api/webhook/wazuh</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
5. Restart Wazuh: systemctl restart wazuh-manager
"""

import sys
import os
import json
import requests
import logging

# Set up logging for troubleshooting
LOG_FILE = "/var/ossec/logs/integrations.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: custom-middleware: %(message)s"
)

def main():
    if len(sys.argv) < 4:
        logging.error("Missing arguments. Expected: <alert_file> <user> <hook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    _user = sys.argv[2]  # Unused, but passed by Wazuh
    hook_url = sys.argv[3]

    if not hook_url.startswith("http"):
        logging.error(f"Invalid hook URL: {hook_url}")
        sys.exit(1)

    # Read the alert.json file passed by Wazuh
    try:
        with open(alert_file, "r") as f:
            alert_data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read alert file {alert_file}: {e}")
        sys.exit(1)

    # Post it to the Middleware Hub
    try:
        logging.info(f"Pushing alert {alert_data.get('id', 'unknown')} to {hook_url}")
        
        # Wazuh passes a single alert dict. We send it as JSON.
        response = requests.post(
            hook_url, 
            json=alert_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        
        # Log response statistics if provided
        result = response.json()
        logging.info(f"Successfully processed. Stats: {result.get('stats', {})}")
        
    except Exception as e:
        logging.error(f"Failed to push alert to middleware: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
