# SASE Remote Workforce Security Monitoring Lab

A Bash-based Zero Trust / SASE access simulator with Splunk SIEM integration for
SOC-style monitoring of remote workforce access decisions.

## Overview

Remote workforces break the old "trusted network perimeter" model — every access
request now has to be evaluated on its own merits, regardless of where it comes
from. This lab simulates that evaluation: a policy engine written in Bash that
scores and decides on remote access requests the way a SASE/ZTNA platform
(Zscaler, Netskope, Palo Alto Prisma Access, etc.) would, then feeds the
resulting access events into Splunk for SOC-style monitoring and investigation.

## Architecture

```
[Simulated Access Request] → [Bash Policy Engine] → [ALLOW / DENY Decision]
        → [Structured Access Log] → [Splunk SIEM] → [SPL Searches & Dashboards]
```

## Zero Trust Evaluation Factors

Each access request is evaluated against:

- **Identity** — who is requesting access
- **Role** — job function / entitlement level
- **Device trust** — is the originating device compliant/trusted
- **MFA status** — was multi-factor authentication satisfied
- **Location** — geolocation of the request
- **Target application** — what resource is being accessed
- **Risk level** — a calculated composite risk score

Based on these, the engine issues an **ALLOW** or **DENY** decision following
Zero Trust principles — no implicit trust, least privilege, verify explicitly.

## Features

- Policy-based access control evaluating 6+ risk factors per request
- Zero Trust enforcement logic (no implicit trust, continuous verification)
- Structured access logs, ready for SIEM ingestion
- Splunk SPL searches for:
  - High-risk user activity
  - Denied access attempts by reason
  - Access trends by role / location / application
- Dashboard panels for SOC-style investigation

## Tech Stack

Bash · Splunk SIEM · SPL

## Repo Contents

| File | Description |
|---|---|
| `sase_policy.sh` | Core Bash policy engine — evaluates requests and issues ALLOW/DENY |
| `users.csv` | Simulated user/identity dataset (role, device trust, MFA status, etc.) |
| `access.log` | Raw simulated access requests |
| `sase.log` | Structured access decision log, ingested into Splunk |

## Setup

```bash
git clone https://github.com/suhail-00/cybersecurity-projects.git
cd cybersecurity-projects/sase-remote-workforce
chmod +x sase_policy.sh
./sase_policy.sh
```

This generates `sase.log`, a structured log of access decisions ready to be
ingested into Splunk (**Settings → Add Data → Upload**, or point a monitor
input at the file for continuous ingestion).

## Sample SPL Queries

**High-risk users:**
```spl
index=sase_logs risk_level=high
| stats count by user, role, location
| sort -count
```

**Denied access attempts by reason:**
```spl
index=sase_logs decision=DENY
| stats count by deny_reason, user
| sort -count
```

**Access trend by application:**
```spl
index=sase_logs
| timechart span=1h count by application
```

## Key Learning Outcomes

- Applied Zero Trust / SASE principles in a practical, testable simulation
- Practiced SIEM log ingestion and SPL query authoring
- Built SOC-relevant investigation dashboards from raw access logs

## Author

**Mohammed Suhail** — Final-year B.Tech CSE (Cybersecurity) student, Alliance University
[GitHub](https://github.com/suhail-00) · [LinkedIn](#)
