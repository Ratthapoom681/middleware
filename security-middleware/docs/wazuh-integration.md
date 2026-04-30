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

For local simulation from the repository path, either make the repo copy executable too:

```bash
chmod +x integrations/custom-security-middleware
```

or call it through Python:

```bash
python3 integrations/custom-security-middleware /path/to/alert.json "" http://MIDDLEWARE_HOST:5000/api/webhook/wazuh
```

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

## Test Like Wazuh From This Repo

Start the middleware webhook receiver:

```bash
python -m web.server --host 0.0.0.0 --port 5000
```

In another shell, simulate Wazuh calling the integration script for one failed-login event:

```bash
python tools/simulate_wazuh_integration.py \
  --url http://127.0.0.1:5000/api/webhook/wazuh \
  --usecase brute-force \
  --count 1
```

By default the simulator sends a Wazuh indexer-style hit with `_index`, `_id`, and `_source`, matching the Fortigate alert shape in `samples/wazuh_fortigate_failed_login_indexer_hit.json`.

Expected result: middleware returns success, unwraps `_source`, stores the raw Wazuh event, and does not create a Redmine ticket because one failed login does not match the brute-force threshold.

Then simulate five unique failed-login alerts from the same source IP:

```bash
python tools/simulate_wazuh_integration.py \
  --url http://127.0.0.1:5000/api/webhook/wazuh \
  --usecase brute-force \
  --srcip 10.0.0.50 \
  --count 5
```

Expected result: the first four alerts are stored/evaluated only; the fifth alert matches the `brute_force` rule and only the generated detection alert is sent to Redmine.

## Simulate Every Detection Use Case

All simulator use cases are based on the Fortigate indexer-hit sample. The script only changes fields that the relevant rule needs.

```bash
# Brute force: 5 failed Fortigate admin logins from the same source IP.
python tools/simulate_wazuh_integration.py --usecase brute-force

# Abnormal port: one Fortigate event with data.dstport=4444.
python tools/simulate_wazuh_integration.py --usecase abnormal-port

# Impossible travel: two Fortigate admin login events from different GeoLocation countries.
python tools/simulate_wazuh_integration.py --usecase impossible-travel

# Port scan: 16 Fortigate events from one srcip with different data.dstport values.
python tools/simulate_wazuh_integration.py --usecase port-scan

# Run all of the above in sequence.
python tools/simulate_wazuh_integration.py --usecase all
```

Current default ticketing behavior: only `brute-force` has `create_ticket: true` in `config/config.yaml`, so only that use case should create a Redmine issue. The other use cases should be stored as detection alerts but will not create Redmine tickets unless their rule has `create_ticket: true`.

To test a raw Wazuh alert shape instead of the indexer/search-hit wrapper:

```bash
python tools/simulate_wazuh_integration.py --format raw --count 1
```

For the brute-force detection flow, keep the middleware rule `drop-raw-wazuh-failed-logins` enabled. Wazuh sends the raw failed-login alerts immediately, the detection engine counts them, and only the generated `brute_force` alert should create a Redmine ticket.
