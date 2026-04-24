# Wazuh Integration Guide

This guide explains how to configure Wazuh to send alerts directly to the Security Middleware in real-time.

## 1. Deploy Integration Scripts

On your **Wazuh Manager**, copy the integration scripts from this repository to the Wazuh integrations directory:

```bash
# Copy scripts
cp integrations/wazuh/custom-middleware /var/ossec/integrations/
cp integrations/wazuh/custom-middleware.py /var/ossec/integrations/

# Set permissions
chown root:wazuh /var/ossec/integrations/custom-middleware*
chmod 750 /var/ossec/integrations/custom-middleware*
```

## 2. Configure Wazuh Manager

Edit `/var/ossec/etc/ossec.conf` and add the following `<integration>` block inside the `<ossec_config>` section:

```xml
<ossec_config>
  <integration>
    <name>custom-middleware</name>
    <hook_url>http://YOUR_MIDDLEWARE_IP:8000/api/webhook/wazuh</hook_url>
    <api_key>YOUR_SECRET_API_KEY</api_key>
    <alert_format>json</alert_format>
    <level>7</level>
  </integration>
</ossec_config>
```

- **hook_url**: The full URL to your middleware's webhook endpoint.
- **api_key**: A shared secret. Ensure this matches the `webhook_api_key` in your Middleware settings.
- **level**: Minimum alert level (0-15) to forward.

## 3. Configure Middleware

1. Go to the Middleware Settings UI.
2. Under **Wazuh**, set:
   - **Webhook API Key**: Match the `api_key` used in `ossec.conf`.
   - **Polling Enabled**: Set to `OFF` (False) once you've verified the push integration works.
3. Save Configuration.

## 4. Restart Wazuh

Restart the Wazuh Manager to apply the changes:

```bash
systemctl restart wazuh-manager
```

## 5. Verification

1. Check Wazuh logs to ensure the integration is loaded:
   ```bash
   grep "custom-middleware" /var/ossec/logs/ossec.log
   ```
2. Trigger a test alert or use the `debug_webhook.py` script:
   ```bash
   python debug_webhook.py
   ```
3. Monitor the Middleware Dashboard and Redmine for new findings.
4. Check `/var/ossec/logs/integrations.log` on the Wazuh Manager for delivery status.
