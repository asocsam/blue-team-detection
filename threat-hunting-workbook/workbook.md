# Threat Hunting Workbook

This workbook captures the core hunts associated with the detections in this repository. Each section follows a consistent structure:

- **Hypothesis** – What malicious behaviour are we looking for?
- **Data Required** – Telemetry needed to prove or disprove the hypothesis.
- **Procedure** – Step-by-step actions with queries.
- **Observations** – Space to document findings or tuning considerations.
- **Escalation** – Criteria for raising an incident.

---

## Hunt 1 – IAM Credential Misuse
- **Hypothesis:** An attacker has obtained IAM user credentials and is attempting to bypass MFA.
- **Data Required:** AWS CloudTrail events (ConsoleLogin), GuardDuty findings, GeoIP context.
- **Procedure:**
  1. Run the Splunk search `queries/splunk_iam_mfa_bypass.spl` or the Elastic query `queries/elastic_iam_mfa_bypass.kql`.
  2. Pivot on `sourceIPAddress` to review geolocation and reputation metadata.
  3. Check GuardDuty findings for the same principal in the past 24 hours.
  4. Validate with the account owner whether the login attempt was expected.
- **Observations:**
  - Note any IP ranges that belong to legitimate third parties.
  - Document service accounts that do not use MFA and justify exceptions.
- **Escalation:**
  - Escalate if MFA bypass attempts originate from high-risk regions or coincide with GuardDuty alerts.

---

## Hunt 2 – DNS Tunnelling
- **Hypothesis:** An endpoint is exfiltrating data using DNS queries with high entropy subdomains.
- **Data Required:** Sysmon Event ID 22, VPC Flow Logs (optional), DNS resolver logs.
- **Procedure:**
  1. Use the Kibana dashboard `DNS Tunneling Investigation` to identify hosts with abnormal query length.
  2. Run the Splunk query `queries/splunk_dns_long_queries.spl` to validate volume.
  3. Extract suspicious domains and cross-reference with threat intelligence feeds.
  4. Capture packet captures if available to confirm payload.
- **Observations:**
  - Record legitimate services (e.g., antivirus) that generate long DNS names.
  - Note time-of-day patterns that differentiate malicious activity.
- **Escalation:**
  - Escalate if queries resolve to unknown infrastructure and the host shows lateral movement indicators.

---

## Hunt 3 – RDP Brute Force
- **Hypothesis:** A remote actor is attempting to brute force RDP credentials against internal assets.
- **Data Required:** Sysmon Event ID 4625, VPC Flow Logs, firewall logs.
- **Procedure:**
  1. Run the Splunk search `queries/splunk_rdp_bruteforce.spl` for the last 24 hours.
  2. Validate the source IP reputation and check if it overlaps with prior incidents.
  3. Correlate with VPC Flow Logs to confirm network attempts on TCP/3389.
  4. Review successful logons from the same source following the burst of failures.
- **Observations:**
  - Track administrative scanners that routinely probe RDP.
  - Record hosts that frequently trigger this detection for tuning.
- **Escalation:**
  - Escalate if failures are followed by a successful logon, privilege escalation, or lateral movement.

---

## Runbook Template
Use the template below for documenting new hunts.

```
### Hunt Title
- **Hypothesis:**
- **Data Required:**
- **Procedure:**
- **Observations:**
- **Escalation:**
```
