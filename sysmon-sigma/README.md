# Sysmon & Sigma Rules

This directory contains Sigma rules tailored to the telemetry emitted by the `mini-siem` sample data. Each rule includes MITRE ATT&CK mapping, false-positive guidance, and deployment notes.

## Rules
- `powershell_encoded_command.yml` – Flags PowerShell processes launching with encoded commands.
- `rdp_bruteforce.yml` – Detects repeated failed logons (Event ID 4625) that indicate brute-force activity.
- `dns_tunneling.yml` – Identifies large DNS queries with suspicious subdomain entropy.

## Usage
1. Install [Sigma tooling](https://github.com/SigmaHQ/sigma) and convert the rules:
   ```bash
   sigmac -t splunk rules/dns_tunneling.yml
   ```
2. Deploy the converted searches to Splunk, Elastic, or your preferred backend.
3. Tune the thresholds referenced in the `detection` section to your environment's baseline.

## Testing
Sample Sysmon events are available under `tests/sample_events/` to validate rule behaviour.
