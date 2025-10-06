# Blue Team & Detection Engineering 🔵

## Overview
This repository packages several practical blue-team projects that I built to explore end-to-end detection engineering. It contains:

- A **mini SIEM pipeline** that ingests sample AWS, network, and Sysmon telemetry before running lightweight analytics.
- A collection of **Sigma rules** derived from real incidents that can be pushed to Splunk, Elastic, or any Sigma-aware backend.
- **Splunk and Kibana dashboards** designed to triage common threats such as credential abuse and DNS tunneling.
- A **threat hunting workbook** that documents hypotheses, pivot tables, and investigation notes.

## Highlights
- Pipeline normalises CloudTrail, GuardDuty, VPC Flow Logs, and Sysmon data before applying correlation logic for IAM misuse, S3 exposure, DNS tunnelling, and RDP brute-force.
- Sigma rules map directly to Sysmon events with MITRE ATT&CK annotations and deployment guidance for both Windows and cross-platform sensors.
- Dashboards accelerate investigations by surfacing enriched context (geo-IP, prevalence, asset criticality) without overwhelming analysts.
- Workbook walks through repeatable hunts with ready-to-run queries and decision trees for escalation.

## Repository Structure
```
mini-siem-pipeline/      Python-based enrichment and detection pipeline with sample data
sysmon-sigma/            Sigma rules, testing data, and deployment notes for Sysmon detections
splunk-elastic-dashboards/  Saved objects for Splunk (JSON) and Kibana (NDJSON)
threat-hunting-workbook/ Investigation workbook and supporting hunt runbooks
```

## Getting Started
1. Install Python 3.11 or newer.
2. Navigate to `mini-siem-pipeline/` and install dependencies (standard library only by default).
3. Execute the pipeline:
   ```bash
   python -m mini_siem.main
   ```
4. Import the Sigma rules into your preferred backend or test them with `sigmac`.
5. Load the dashboards into Splunk or Kibana using their native import interfaces.

## Development Notes
- The project intentionally uses only standard-library modules to keep the demo portable.
- Sample telemetry is anonymised but follows the real schema from AWS and Sysmon documentation.
- Feel free to replace the sample JSON files with your own telemetry to extend detections.
