# Splunk & Elastic Dashboards

Dashboards aligned with the detections surfaced by the mini SIEM pipeline.

## Contents
- `splunk/credential-abuse-dashboard.json` – Splunk Dashboard Studio export visualising failed logons, MFA bypass, and GuardDuty context.
- `kibana/dns-tunneling.ndjson` – Kibana saved object showing query distribution, entropy trends, and host pivots.

## Usage
### Splunk
1. Open **Dashboards** → **Import**.
2. Upload `splunk/credential-abuse-dashboard.json`.
3. Update the macros `macro_rdp_index` and `macro_cloudtrail_index` to point at your indexes.

### Kibana
1. Navigate to **Stack Management** → **Saved Objects**.
2. Click **Import** and upload `kibana/dns-tunneling.ndjson`.
3. Point the visualisations at an index pattern containing DNS logs.

Both dashboards expect fields identical to the pipeline output but can be adapted to your schema by editing the searches.
