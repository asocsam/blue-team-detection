# Mini SIEM Pipeline

A lightweight Python pipeline that simulates ingesting multiple telemetry sources, enriches the events, and emits alerts for common attack techniques. Everything runs locally with sample data so you can explore the detection logic without needing a full SIEM stack.

## Features
- Ingests JSON events for **AWS CloudTrail**, **GuardDuty**, **VPC Flow Logs**, and **Sysmon**
- Normalises records into a shared schema with timestamps, assets, and activity categories
- Applies correlation logic for:
  - IAM credential misuse (MFA bypass, suspicious source IPs)
  - S3 bucket public exposure
  - DNS tunnelling and data exfiltration behaviour
  - RDP brute-force attempts across hosts
- Produces analyst-friendly alerts with enrichment notes and MITRE ATT&CK mappings

## Running the Pipeline
```bash
cd mini-siem-pipeline
python -m mini_siem.main --data-dir data --output alerts.json
```

The script prints a table of detections and writes a JSON alert file for downstream tooling.

## Extending
- Drop additional JSONL files into `data/` and update the loader configuration in `mini_siem/config.py`
- Modify or extend the detection functions under `mini_siem/detections.py`
- Use the provided unit tests as a template for validating new logic (coming soon)

## Data Format
Each telemetry file is a JSON lines (`.jsonl`) document. Schemas follow the public documentation for each service with only the fields required by the demo. Add fields as needed—unknown keys are preserved in the event payload.
