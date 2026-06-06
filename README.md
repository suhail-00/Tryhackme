# TryHackMe - ItsyBitsy Write-Up

## Overview

**Room:** ItsyBitsy
**Platform:** TryHackMe
**Category:** Threat Hunting / Log Analysis
**Tools Used:** Kibana, Elastic Stack

## Objective

The objective of this challenge was to investigate network connection logs using Kibana, identify suspicious activity, and uncover the hidden flag by following indicators of compromise.

---

## Step 1: Reviewing the Logs

After accessing Kibana, I examined the `connection_logs` index, which contained approximately 1,482 connection records.

The available fields included:

* source_ip
* destination_ip
* user_agent
* uri
* timestamp

<img width="1906" height="977" alt="Screenshot 2026-06-05 183005" src="https://github.com/user-attachments/assets/32e7ef18-6170-4a7a-ae53-a1f7294aa14d" />



The dashboard displayed all network connections collected during the investigation period.

---

## Step 2: Analyzing Source IP Addresses

To identify anomalies, I added the `source_ip` field and reviewed the top values.

<img width="1907" height="976" alt="Screenshot 2026-06-05 183124" src="https://github.com/user-attachments/assets/97484551-0cff-4ece-bb0e-468a2f9e2832" />


### Observation

Most traffic originated from:

192.166.65.52 (99.6%)

However, another source IP appeared:

192.166.65.54 (0.4%)

Since it generated only a small number of events, it was selected for further investigation.

---

## Step 3: Filtering the Suspicious Host

I filtered the logs using:

```kql
source_ip: 192.166.65.54
```
<img width="1907" height="972" alt="Screenshot 2026-06-05 183426" src="https://github.com/user-attachments/assets/bf29fc59-6a51-4291-aaa6-52228d3075a8" />


The filter returned only two records.

### Findings

| Field          | Value         |
| -------------- | ------------- |
| Source IP      | 192.166.65.54 |
| Destination IP | 104.23.99.190 |
| User Agent     | bitsadmin     |

The user agent `bitsadmin` was particularly interesting because it is often abused by attackers for downloading or transferring files in the background.

---

## Step 4: Investigating the URI

To gather more information, I added the `uri` field to the results table.

<img width="1912" height="965" alt="Screenshot 2026-06-05 183917" src="https://github.com/user-attachments/assets/c1d09de6-25fc-44fe-9e73-aafb94a362d1" />



The URI value was:

```text
/yTg0Ah6a
```

This appeared to be a resource hosted on an external service.

---

## Step 5: Following the Lead

Using the URI, I navigated to the corresponding Pastebin page.

<img width="1908" height="930" alt="Screenshot 2026-06-05 184206" src="https://github.com/user-attachments/assets/b80379ca-541a-4f60-9fb1-8cbbca1eb7d1" />


The page contained a hidden text file revealing the challenge flag.

---

## Flag

```text
THM{REDACTED}
```

*Flag redacted to avoid spoilers.*

---

## Indicators of Compromise (IOCs)

| Type           | Value         |
| -------------- | ------------- |
| Source IP      | 192.166.65.54 |
| Destination IP | 104.23.99.190 |
| User Agent     | bitsadmin     |
| URI            | /yTg0Ah6a     |

---

## Skills Practiced

* Kibana Log Analysis
* Threat Hunting
* Security Monitoring
* IOC Investigation
* Network Traffic Analysis
* Blue Team Methodology

---

## Conclusion

This room provided hands-on experience with investigating network logs using Kibana. By identifying anomalous source IP activity, analyzing user-agent information, and following network indicators, I successfully uncovered the hidden flag. The challenge reinforced practical threat-hunting techniques commonly used by SOC analysts and Blue Team professionals.
