# SOC analyst runbooks

These are investigation checklists for a controlled defensive environment. They intentionally do not automate destructive containment actions.

## RB-01: Repeated authentication failures

**Trigger:** SF-AUTH-001.

1. Confirm the source IP, destination asset, usernames, time range and event count.
2. Compare the activity with the account's historical pattern and expected service behaviour.
3. Check whether successful authentication followed the failures.
4. Correlate with endpoint, VPN, identity-provider and network records where available.
5. Check maintenance windows, password rotation and known service-account issues.
6. Record evidence, impact, confidence and a recommended next step.
7. Escalate according to the organisation's incident policy. Do not disable an account solely because this threshold fired.

## RB-02: High-severity network IDS alert

**Trigger:** SF-NET-001.

1. Review the IDS signature, signature ID, sensor, interface, source/destination addresses and time.
2. Validate sensor health, signature context and whether the traffic is expected.
3. Correlate the event with asset ownership, network zone and endpoint telemetry.
4. Determine whether the activity is blocked, allowed or merely observed.
5. Preserve relevant event IDs and a concise timeline.
6. Escalate when evidence supports a likely incident; otherwise document the tuning rationale.

## RB-03: Endpoint protection health issue

**Trigger:** SF-END-001.

1. Confirm the endpoint identity and last successful agent check-in.
2. Check whether a documented maintenance, upgrade or outage explains the state.
3. Review endpoint change records and other telemetry for the same period.
4. Contact the asset owner or endpoint operations team through the approved channel.
5. Document the duration of degraded visibility and any compensating monitoring.

## RB-04: Critical vulnerability

**Trigger:** SF-VULN-001.

1. Validate the scanner result and affected software/package version.
2. Confirm asset owner, business criticality, exposure and compensating controls.
3. Review vendor advisory and the applicable CVE record from trusted sources.
4. Prioritise using CVSS plus exposure, exploitability, asset criticality and business impact.
5. Record a remediation owner, target date and mitigation plan.
6. Verify remediation with a subsequent authorised scan or version check.

## Minimum incident record

- Incident identifier and title
- Detection source and related event/alert identifiers
- UTC timeline
- Affected assets and accounts
- Evidence and confidence
- Business impact assessment
- Actions taken and approvals
- Owner, status and next review time
- Closure reason and lessons learned
