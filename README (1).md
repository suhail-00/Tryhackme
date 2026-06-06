# TryHackMe – Network Traffic Analysis: ICMP Tunneling & DNS Exfiltration

**Category:** Network Traffic Analysis / Blue Team  
**Difficulty:** Intermediate  
**Platform:** TryHackMe  
**Room:** Wireshark Traffic Analysis PROD v0.2  
**Tools Used:** Wireshark  

---

## Overview

This room involved packet-level analysis of two PCAP files to identify covert communication techniques used by attackers to bypass traditional security controls. The investigation uncovered two distinct attack patterns — **ICMP tunneling** for covert C2 communication and **DNS-based data exfiltration** using high-entropy subdomain encoding.

Both techniques abuse protocols that are routinely allowed through firewalls, making them particularly dangerous in environments that rely solely on signature-based detection.

---

## Part 1 – ICMP Tunneling Analysis

**File:** `icmp-tunnel.pcap`  
**Wireshark Filter:** `ip.len > 200 && icmp`

### What is ICMP Tunneling?

ICMP (Internet Control Message Protocol) is primarily used for diagnostic purposes — most commonly the `ping` command. Because ICMP is widely trusted and rarely blocked at the firewall level, attackers abuse it to embed arbitrary data inside Echo Request/Reply packets, creating a covert channel for C2 communication or data exfiltration.

### Investigation

Applying the filter `ip.len > 200 && icmp` immediately surfaced anomalous traffic:

![Wireshark ICMP tunnel filter showing oversized packets and suspicious payload](images/icmp_tunnel.png)

### Indicators of Compromise

**1. Abnormally large packet sizes**

Normal ICMP ping packets are typically 64–84 bytes. The filtered results showed packets ranging from **238 to 1070 bytes** — far exceeding what legitimate ping traffic produces.

| Packet | Length | Direction |
|--------|--------|-----------|
| 46 | 886 | Request (131 → 132) |
| 48 | 878 | Reply (132 → 131) |
| 174 | 1070 | Reply (132 → 131) |
| 175 | 1070 | Request (131 → 132) |
| 176 | 1070 | Reply |
| 177 | 1070 | Request |

Packets of 1070 bytes sustained over multiple exchanges strongly indicate **data being chunked and transmitted** through ICMP payloads.

**2. Suspicious payload content**

Inspecting the Data field of packet 46 revealed 844 bytes of embedded data. The hex dump and ASCII decode showed fragments consistent with **SSH handshake negotiation strings**:

```
c-md5-96, hmac-sha1, hmac-md5, hmac-ripemd160
@openssh.com, zlib, none
```

This is SSH KEX (Key Exchange) data — meaning the attacker was tunneling an **SSH session inside ICMP packets** to establish encrypted C2 communication.

**3. Checksum anomalies**

Packet 46 showed:
```
Checksum: 0x0000 incorrect, should be 0x12ff
[Checksum Status: Bad]
```

Malformed checksums are a common artifact of tunneling tools that craft packets programmatically rather than through the OS network stack.

**4. Sustained bidirectional traffic pattern**

The traffic showed consistent Request/Reply pairs between `192.168.154.131` and `192.168.154.132` over an extended time window (32s to 218s), with no response seen for certain packets — consistent with a tunneling tool managing its own session state.

### Attacker Technique

| Indicator | Significance |
|-----------|-------------|
| Packet size 886–1070 bytes | Data embedded in ICMP payload |
| SSH KEX strings in payload | SSH tunnel over ICMP (e.g. ptunnel, icmptunnel) |
| Bad checksum | Packets crafted by tunneling tool, not OS |
| Sustained bidirectional traffic | Active C2 session in progress |

**MITRE ATT&CK:** T1095 – Non-Application Layer Protocol  
**MITRE ATT&CK:** T1572 – Protocol Tunneling

---

## Part 2 – DNS Exfiltration Analysis

**File:** `dns.pcap`  
**Wireshark Filter:** `dns`

### What is DNS Exfiltration?

DNS is one of the most universally permitted protocols on any network — blocking it would break internet connectivity entirely. Attackers exploit this by encoding stolen data into DNS query subdomains, then sending those queries to an attacker-controlled authoritative DNS server that logs and reassembles the data. The traffic blends in with normal DNS activity.

### Investigation

Filtering for DNS traffic revealed **33,172 total packets** with **30,370 displayed** — an unusually high volume of DNS activity for a standard environment.

![Wireshark DNS filter showing high-entropy MX query responses](images/dns_exfil.png)

### Indicators of Compromise

**1. High-entropy subdomain strings**

The DNS responses contained MX record queries with extremely long, random-looking subdomain strings:

```
8AA600B0DE75522612EFA900002...
8AD001B0DEBFC061FF7A3B088a0...
8AE401B0DE6B288EECD93C06ec9...
8AF901B0DE1CC19E69388E00c52...
8B0001B0DEDB05F18140820b245...
```

These are not legitimate domain names. The length and entropy are consistent with **Base64 or hex-encoded data** being transmitted as subdomain labels — a classic DNS tunneling pattern.

**2. Repetitive MX record type**

All queries used the **MX (Mail Exchange)** record type. Legitimate MX queries happen rarely and only when sending email. Seeing hundreds of MX responses in a short window is a strong anomaly signal — attackers choose MX, TXT, or CNAME record types because they can carry more data than standard A records.

**3. Structured naming pattern**

Examining the decoded answer section:
```
Name: 8AA600B0DE75522612EFA90000...
Type: MX (Mail eXchange)
Class: IN
TTL: 60 (1 minute)
```

The TTL of just 60 seconds prevents DNS caching, ensuring each query hits the attacker's DNS server — and delivers the next chunk of exfiltrated data.

**4. Hex payload in response body**

The raw hex dump showed structured data at offsets `0x00a0–0x00d0`:
```
edea00b0 de187928 7bc99fff ff06a321 72·dataexfil.com
```

The domain `dataexfil.com` visible in the ASCII decode is a clear indicator of a **deliberately named exfiltration domain** used as the attacker's DNS server.

**5. Volume anomaly**

Over 30,000 DNS packets displayed out of ~33,000 total packets in the capture is an extreme ratio. In a healthy network, DNS typically represents a small percentage of total traffic. This volume indicates **automated, high-speed data exfiltration in progress**.

### Attacker Technique

| Indicator | Significance |
|-----------|-------------|
| High-entropy subdomains | Data encoded in DNS labels |
| MX record type abuse | Carries more data per query than A records |
| TTL = 60 seconds | Bypasses DNS cache, ensures delivery to attacker server |
| `dataexfil.com` in payload | Attacker-controlled authoritative DNS server |
| 30,000+ DNS packets | Automated exfiltration tool running |

**MITRE ATT&CK:** T1071.004 – Application Layer Protocol: DNS  
**MITRE ATT&CK:** T1048.003 – Exfiltration Over Unencrypted Protocol

---

## Full MITRE ATT&CK Mapping

| Technique | ID | Part |
|-----------|----|------|
| Non-Application Layer Protocol | T1095 | ICMP Tunneling |
| Protocol Tunneling | T1572 | ICMP/SSH Tunnel |
| Application Layer Protocol: DNS | T1071.004 | DNS Exfiltration |
| Exfiltration Over Unencrypted Protocol | T1048.003 | DNS Exfiltration |
| Exfiltration Over C2 Channel | T1041 | Both |

---

## Detection Recommendations

### For ICMP Tunneling
- Alert on ICMP packets exceeding 128 bytes in payload size
- Flag sustained ICMP bidirectional traffic between the same two hosts
- Inspect ICMP payloads for non-null data (legitimate pings carry minimal payload)
- Block outbound ICMP at the perimeter unless explicitly required

### For DNS Exfiltration
- Alert on DNS query labels exceeding 50 characters
- Baseline normal DNS query volume per host; alert on deviations
- Flag rare DNS record types (MX, TXT, NULL) from non-mail servers
- Implement DNS sinkholes for known exfiltration domains
- Use DNS over HTTPS (DoH) monitoring or split-horizon DNS to inspect queries

---

## Key Takeaways

Modern attackers increasingly abuse **legitimate, trusted protocols** — ICMP, DNS, HTTP — to evade traditional signature-based controls. Effective Blue Team detection requires:

- **Deep packet inspection** to uncover hidden payload activity
- **Behavioral traffic analysis** to identify deviations from normal patterns
- **Protocol-level anomaly detection** — not just port/IP blocking
- **Understanding of covert channel techniques** to recognize what normal traffic shouldn't look like

This lab reinforced that a strong SOC analyst must think beyond firewall rules and understand *how* protocols work at the packet level to detect when they are being abused.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | Packet capture analysis and filtering |
| Display filter: `ip.len > 200 && icmp` | Isolate oversized ICMP packets |
| Display filter: `dns` | Isolate all DNS traffic |
| Hex/ASCII pane | Decode embedded payload data |
| Packet details pane | Inspect protocol fields (checksum, TTL, record type) |

---

## Screenshots

| Screenshot | Section |
|------------|---------|
| `images/icmp_tunnel.png` | Part 1 – ICMP Tunneling Analysis |
| `images/dns_exfil.png` | Part 2 – DNS Exfiltration Analysis |

---

*Write-up by Mohammed Suhail | [GitHub](https://github.com/suhail-00/Tryhackme) | [LinkedIn](https://www.linkedin.com/)*
