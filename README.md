

### **Blue Team & Detection Engineering** (blue-team-detection)  
```markdown
# Blue Team & Detection Engineering 🔵  

## Overview  
This repo contains my Blue Team projects: a mini-SIEM pipeline, Sigma detection rules, and Splunk/Elastic dashboards built for AWS + Sysmon logs.  

## Features  
- Mini-SIEM ingesting **AWS CloudTrail, VPC Flow Logs, GuardDuty**  
- Sigma → Splunk rules for **IAM misuse, S3 public exposure, DNS tunneling**  
- Splunk & Elastic dashboards for triage and hunting  

## Setup  
```bash
docker compose up
