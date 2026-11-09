# Development roadmap

## Delivered in this repository

- Canonical event schema and HMAC-protected ingestion
- Representative Wazuh, Suricata and Sysmon JSON normalisers
- Six transparent detection rules with ATT&CK references
- Alert deduplication and analyst status workflow
- Incident creation and status tracking
- Vulnerability finding registry and status tracking
- SHA-256 hash-chained audit log and verification endpoint
- Browser dashboard, synthetic telemetry generator and automated tests

## Recommended next increments

1. Add OIDC authentication and analyst/admin roles before multi-user use.
2. Add a message queue and asynchronous workers for high-volume ingestion.
3. Add per-tenant retention policies, backups and database migrations.
4. Add richer Wazuh rule mapping and Suricata signature context.
5. Add an analyst case timeline and evidence attachment hashes.
6. Add detection-as-code tests and a labelled evaluation dataset.
7. Add an authorised scanner export importer and remediation SLA reporting.
8. Add external immutable audit archival and alert notification integration.
9. Add a human-reviewed AI summarisation module only after baseline detection metrics are established.

## Explicit non-goals

- No exploit automation or unauthorised scanning.
- No autonomous destructive containment.
- No public-internet deployment without substantial hardening.
- No claims of production SIEM/EDR equivalence.
