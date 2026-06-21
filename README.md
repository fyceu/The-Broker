## Incident Brief

## Tech Stack 
- Microsoft Azure
- Azure Sentinel 
- Microsoft Defender for Endpoint
- Windows 11

## Executive Summary
Incident ID: INC0001-2026-0221 <br>
Severity: Critical <br>
Status: Ongoing <br>
Analyst Assigned: `Fasi Sika` <br>

### Key Findings

This investigation confirmed an attacker gained unauthorized access to internal systems within Ashford Sterling Recruitment to conduct malicious activity. This activity includes social engineering, malicious code and process injection, remote access trojan, credential theft, persistence, lateral movement, and potential data staging for exfiltration. The attacker successfully established access across multiple systems including workstations `as-pc1`, `as-pc2`, and file server `as-srv`.

The full investigation report for these findings can be read [here](https://github.com/fyceu/The-Broker/blob/main/Threat%20Hunt%20Report.md)

### Immediate Response

### Business Impact
Confirmation of this incident significantly increasing Ashford Sterling's risk exposure as the file server is known to host sensitive business files. Although full exfiltration could not be confimed, the attacker's actions demonstrate clear intent to collect sensitive data and maintain persistence within the environment. 

A detailed analysis on business impact can be read [here](https://github.com/fyceu/The-Broker/blob/main/Threat%20Hunt%20Report.md#business-impact)
