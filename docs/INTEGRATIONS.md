# Integration guide

SOCForge accepts representative JSON event payloads from Wazuh, Suricata EVE and Sysmon through signed adapter endpoints. The adapters are examples and should be validated against the exact event schema/version deployed in a lab.

## Supported endpoints

- `POST /api/events` - SOCForge canonical event schema
- `POST /api/adapters/wazuh` - representative Wazuh alert JSON
- `POST /api/adapters/suricata` - representative Suricata EVE JSON
- `POST /api/adapters/sysmon` - representative Sysmon JSON

All ingest endpoints require `X-SOCForge-Signature` by default. The signature is HMAC-SHA256 over the exact raw HTTP request bytes using the local `SOCFORGE_HMAC_SECRET`. The sender and receiver must share the secret securely. Do not disable signature verification outside isolated debugging.

## Example canonical event

```json
{
  "timestamp": "2026-11-09T10:00:00Z",
  "source": "training-sensor-01",
  "event_type": "authentication_failure",
  "severity": "low",
  "host": "demo-workstation",
  "src_ip": "192.0.2.44",
  "username": "training.user",
  "message": "Synthetic failed authentication for rule validation",
  "attributes": {"simulation": true}
}
```

## Integration validation checklist

- Confirm time zones and timestamps are parsed correctly.
- Verify that source IP, destination IP, username, host and event type map to expected fields.
- Preserve the original source event identifier and metadata where possible.
- Test missing and malformed fields.
- Confirm duplicate events do not create duplicate records in any upstream replay process.
- Verify signature failures are rejected.
- Confirm the source sensor time is synchronised.
