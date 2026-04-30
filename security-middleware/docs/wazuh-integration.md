# Wazuh Custom Integration

The middleware webhook receives Wazuh alerts at:

```text
POST http://<middleware-host>:<middleware-port>/api/webhook/wazuh
```

Wazuh still needs a custom integration script on the Wazuh manager so alerts are pushed to that endpoint in real time.

## Install The Script

Run these commands on the Wazuh manager:

```bash
sudo cp integrations/custom-security-middleware /var/ossec/integrations/custom-security-middleware
sudo chown root:wazuh /var/ossec/integrations/custom-security-middleware
sudo chmod 750 /var/ossec/integrations/custom-security-middleware
```

If the repository is not present on the Wazuh manager, copy only the `integrations/custom-security-middleware` file there first.

## Configure ossec.conf

Edit `/var/ossec/etc/ossec.conf` and add this inside an `<ossec_config>` block:

```xml
<integration>
  <name>custom-security-middleware</name>
  <hook_url>http://MIDDLEWARE_HOST:5000/api/webhook/wazuh</hook_url>
  <level>0</level>
  <group>authentication_failed,authentication_failures,authentication_failure,invalid_login,sshd</group>
  <alert_format>json</alert_format>
  <timeout>10</timeout>
  <retries>3</retries>
</integration>
```

Use a middleware URL that is reachable from the Wazuh manager. If middleware runs on another server or inside Docker, do not use `127.0.0.1` unless Wazuh and middleware share the same network namespace.

For broader Wazuh ingestion, remove the `<group>` line or raise `<level>` to the minimum Wazuh rule level you want to forward.

## Restart Wazuh

```bash
sudo systemctl restart wazuh-manager
```

## Test Manually

You can test the script before waiting for a real alert:

```bash
sudo /var/ossec/integrations/custom-security-middleware \
  /var/ossec/logs/alerts/alerts.json \
  "" \
  http://MIDDLEWARE_HOST:5000/api/webhook/wazuh
```

For the brute-force detection flow, keep the middleware rule `drop-raw-wazuh-failed-logins` enabled. Wazuh sends the raw failed-login alerts immediately, the detection engine counts them, and only the generated `brute_force` alert should create a Redmine ticket.
