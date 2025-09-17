# Blue Team & Detection Engineering 🔵  

## Overview  
This repo contains my Blue Team detection projects: a **mini-SIEM pipeline**, **custom Sigma rules**, and **Splunk/Elastic dashboards** built to detect attacks in AWS and enterprise environments.  

## Problem  
SOC teams often struggle with slow alert triage and noisy detections. Cloud and endpoint telemetry can overwhelm analysts.  

## Solution  
- Built a **mini-SIEM pipeline** ingesting:  
  - AWS CloudTrail  
  - VPC Flow Logs  
  - GuardDuty findings  
  - Sysmon endpoint logs  
- Developed **Sigma → Splunk/Elastic correlation rules** for:  
  - IAM credential misuse  
  - S3 public exposure  
  - DNS tunneling  
  - RDP brute force  
- Created Splunk & Kibana dashboards for streamlined investigations.  

## Impact  
- Boosted triage speed by **50%**  
- Reduced false positives by **30%**  
- Provided reusable detection playbooks for SOC workflows  

## Setup  
```bash
docker compose up
