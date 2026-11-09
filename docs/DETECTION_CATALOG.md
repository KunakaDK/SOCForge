# Detection catalogue

All rules are intentionally transparent and designed for defensive triage in a controlled lab. They are starting points, not production-ready detections. Tune thresholds using the environment's baseline and validate with labelled data.

| Rule | Event condition | Default severity | MITRE ATT&CK reference | Analyst question |
|---|---|---|---|---|
| SF-AUTH-001 | At least five failed authentication events from one source IP in ten minutes | High | T1110 - Brute Force | Is this a user error, a misconfigured service or suspicious authentication activity? |
| SF-NET-001 | A normalised IDS/network event is high or critical severity | High | T1046 - Network Service Discovery (context dependent) | Does the IDS signature match the asset's expected role and traffic? |
| SF-END-001 | Endpoint protection health event contains disabled/stopped/unhealthy state | High | T1562 - Impair Defenses | Is the agent intentionally under maintenance or unexpectedly unhealthy? |
| SF-PRIV-001 | Privileged group or role membership change event | Medium | T1098 - Account Manipulation | Was the change approved and tied to a change ticket? |
| SF-FIM-001 | File-integrity change event | Medium | T1565 - Data Manipulation (context dependent) | Is the file change expected, signed and attributable to an approved update? |
| SF-VULN-001 | Vulnerability finding has CVSS >= 9.0 | Critical | T1190 - Exploit Public-Facing Application (only if exposure/context supports it) | Is the affected asset exposed, exploitable and business-critical? |

## Tuning and false-positive handling

1. Establish a baseline before increasing severity or reducing thresholds.
2. Exclude known test identities and approved maintenance sources only through documented, reviewed allowlists.
3. Preserve raw event references and analyst rationale when closing an alert.
4. Avoid treating one event as proof of compromise. Correlate endpoint, identity, network and asset context.
5. Track detection precision, recall and false-positive rate against a labelled dataset.
6. Review ATT&CK mapping for contextual accuracy; a technique label is a hypothesis aid, not proof that a technique occurred.

## Current rule limitations

- The authentication detector uses a simple fixed threshold and ten-minute lookback; it does not yet implement user-risk baselines, geolocation, authentication protocol context or suppression by known service accounts.
- The network rule trusts the normalised source severity; validate IDS signature confidence and sensor coverage before operational use.
- Endpoint health, privilege change and file-integrity events require a correctly mapped source schema.
- The CVSS threshold is a prioritisation trigger only. Exploitability, exposure, compensating controls and asset criticality must be considered separately.
