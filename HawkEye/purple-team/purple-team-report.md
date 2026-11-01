# HawkEye — Purple Team Handover Report
## Collaborative Attack Emulation, Defensive Gap Analysis & Detection Engineering Handover

**Document Reference:** ELEV-SOC-HAWKEYE-PURPLE-2026-001
**Internship Module:** Task 1 — HawkEye Tri-Team Analysis (Purple Team Perspective)
**Student Intern:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Provider:** ElevanceSkills
**Date of Execution:** 2026-10-02 (Revised & Verified: 2026-10-31)
**Classification:** TLP:CLEAR / Educational Threat Analysis Portfolio
**Status:** **Completed & Verified (Educational Threat Analysis Portfolio — Grounded in Empirical PCAP Telemetry)**

---

> [!IMPORTANT]
> **PURPLE TEAM MANDATE & EVIDENTIARY TRANSPARENCY:**
> This report consolidates empirical findings from both offensive emulation (Red Team) and defensive monitoring (Blue Team) derived from the packet capture `stealer.pcap` (4,003 total packets).
> - **Directly Observed Wire Evidence:** Network-layer transactions (HTTP executable download, DNS resolutions, HTTP external IP queries, authenticated SMTP transmissions, and recurring timers) represent confirmed ground truth from packet analysis.
> - **Base64 Encoding vs. Encryption:** Authentication credentials and message payloads transmitted in SMTP streams utilize Base64 encoding (RFC 4648). Base64 is a reversible encoding scheme, **not cryptographic encryption**; authentication tokens and message bodies are transmitted in cleartext on the wire.
> - **Periodic Traffic vs. Host Scheduling:** While network telemetry reveals 7 periodic exfiltration cycles at ~10-minute intervals, the network data alone cannot establish the underlying host implementation mechanism (such as an application `Sleep()` loop, an event timer, or a Windows Scheduled Task).
> - **Inferred Host Activity (Corroborated by Payload):** Local endpoint execution, keylogging hooks, and browser credential theft are analytical inferences corroborated by the plain-text email payload transmitted across the wire, rather than directly observed through endpoint kernel telemetry.
> - **Proposed Rules Status:** Network detection signatures (Suricata/Snort) represent **proposed detection engineering drafts** modeled from observed indicators; they were not deployed or tested against a live IDS sensor engine.

---

## 1. Executive Summary

The Purple Team exercise for the HawkEye incident establishes a collaborative bridge between adversary tradecraft and defensive detection engineering. By analyzing the complete attack lifecycle observed in `stealer.pcap` (**4,003 packets**, duration: **1:03:41**), the Purple Team correlates offensive Tactics, Techniques, and Procedures (TTPs) with high-fidelity network and host detection opportunities.

The primary compromised workstation identified in the traffic was **`10.4.10.132`** (`Beijing-5cd1-PC`). The threat lifecycle proceeded across four sequential operational phases:
1. **Payload Ingress:** HTTP download of `tkraw_Protected99.exe` (MD5: `71826BA0...`) from `217.182.138.150:80` following DNS resolution of `proforma-invoices.com` (Frames 204–3155).
2. **Reconnaissance & Egress Verification:** DNS resolution of `bot.whatismyipaddress.com` (Frame 3159) returning public server IP `66.171.248.178` (Frame 3160), followed by an HTTP query (Frame 3164) returning the victim's true external public IP: **`173.66.146.112`** in Frame 3166.
3. **Covert Exfiltration Channel:** Submission of carved keylogger payloads over unencrypted SMTP to `23.229.162.69:587` (resolved from domain `macwinlogistics.in`, Exim 4.91 banner `p3plcpnl0413.prod.phx3.secureserver.net`) using cleartext Base64 authentication (Frames 3172–3207). Earlier student notes referenced `mail.winlogistics.in`; packet analysis confirms the queried apex domain is `macwinlogistics.in`.
4. **Recurring ~10-Minute Network Cadence:** Recurring exfiltration cycles observed across 7 iterations at approximately **604–606 second (~10 minute)** intervals on the wire, concluding with Cycle 7 in Frames 3910–3982 (active message transmission in Frames 3923–3958; capture ends at Packet 4,003). While network telemetry confirms regular outbound bursts, the internal host execution state during silent intervals cannot be established from the PCAP alone.

```
+---------------------------------------------------------------------------------------------------+
|                              HAWKEYE PURPLE TEAM LIFECYCLE HANDOVER                               |
+-------------------+--------------------+--------------------+--------------------+----------------+
| RED TEAM TTPs     | MITRE ATT&CK       | DEFENSIVE GAPS     | BLUE TEAM DETECTION| MITRE D3FEND / |
| (Observed Attack) | (Technique ID)     | (Identified Blind) | (Engineered Logic) | REMEDIATION    |
+-------------------+--------------------+--------------------+--------------------+----------------+
| 1. HTTP Exe Down  | T1105 Ingress Tool | Unrestricted HTTP  | Zeek HTTP / Snort  | M1031 Network  |
|    from Staging   | Transfer           | Executable Egress  | PE Carving Rule    | Prevention     |
| 2. WhatIsMyIP     | T1016 System Net   | Unmonitored Public | DNS Threat Intel / | M1037 Traffic  |
|    Lookup         | Config Discovery   | IP Lookup Queries  | Sysmon Event 22    | Filter Egress  |
| 3. SMTP Auth on   | T1041 Exfiltration | Endpoints talking  | Alert Workstation  | M1037 Block    |
|    Port 587       | Over C2 Protocol   | Direct to Ext Mail | to Ext Mail Relays | Direct Egress  |
| 4. 10-Min Periodic| T1029 Scheduled    | No Jitter / Beacon | Statistical Inter- | D3-NBA Network |
|    Beaconing      | Transfer Cadence   | Detection in Place | Arrival Analysis   | Beacon Analys  |
+-------------------+--------------------+--------------------+--------------------+----------------+
```

---

## 2. PCAP Evidence Disambiguation: 66.171.248.178 vs. 173.66.146.112

A primary requirement of forensic integrity is clearly separating third-party cloud lookup infrastructure from the victim system's own external identity. The actual PCAP evidence provides irrefutable proof:

```
+---------------------------------------------------------------------------------------------------+
|                     PCAP PROOF: 66.171.248.178 vs. 173.66.146.112                                 |
+-------------------+-------------------------------------------------------------------------------+
| IP Address        | Role, Network Protocol & Empirical PCAP Evidence                              |
+-------------------+-------------------------------------------------------------------------------+
| 66.171.248.178    | • Identity: External Web Server hosting bot.whatismyipaddress.com.            |
|                   | • DNS Answer (Frame 3160): DNS A-record response for bot.whatismyipaddress.com|
|                   |   resolves to 66.171.248.178.                                                 |
|                   | • HTTP Connection (Frame 3164): 10.4.10.132 connects to 66.171.248.178:80.    |
|                   | • Finding: THIS IS AN EXTERNAL SERVICE. It is NOT the victim IP.             |
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

---

## 3. Directly Observed Network Evidence vs. Forensic Interpretation vs. Unobservable Host State

To maintain analytical rigor, the Purple Team categorizes findings into three clear evidentiary tiers:

| Category | 1. Directly Observed on Wire (PCAP Truth) | 2. Forensic Interpretation (Corroborated) | 3. Unobservable from PCAP Alone |
|---|---|---|---|
| **Payload Ingress** | HTTP GET `/proforma/tkraw_Protected99.exe` transferring 2,025,472 bytes (Frames 207–3155). | Executable delivered to disk on host `10.4.10.132`. | User launch method (manual double-click vs. automated helper script). |
| **System Discovery** | DNS query and HTTP transaction to `bot.whatismyipaddress.com` returning `173.66.146.112`. | External IP lookup performed to tag exfiltrated telemetry with public IP. | Local execution of discovery commands (e.g., `ipconfig` or WinINet APIs). |
| **Data Collection** | Frame 3194 body containing keystrokes, OS info, and bank profile (`oman.mcguire`). | Stolen data harvested from local browser databases and input buffers. | In-memory Win32 API hooking (`SetWindowsHookEx`) or RAM buffer state during inactivity. |
| **Exfiltration** | SMTP session on port 587 to `23.229.162.69` authenticated via `sales.del@macwinlogistics.in` (cleartext Base64). | Cleartext unencrypted C2 data exfiltration channel over standard submission port. | Local process PID or thread owning the outbound network socket. |
| **Periodic Cadence** | 7 repeating cycles at ~604–606s intervals (Frames 3172–3982; all <= Packet 4003). | Automated scheduling logic driving regular egress bursts. | Exact host process state during gaps: sleep loop vs. thread timer vs. scheduled task. |
| **Initial Delivery** | Inbound HTTP staging download (Frame 207). | Staging server (`217.182.138.150:80`) hosted payload for download. | Phishing lure / delivery email (not captured in PCAP; inferred from campaign norms). |

> [!NOTE]
> **Inter-Cycle Gap Network Telemetry Verification:**
> An exhaustive packet filter across all silent intervals between exfiltration cycles (Frames 3255–3289, 3345–3376, 3432–3461, 3517–3576, 3630–3831, 3888–3909) confirms:
> 1. Zero packets to port 587 or C2 IP `23.229.162.69` occurred during the ~10-minute gaps.
> 2. Network activity in these gaps consisted of internal LAN traffic (SMB TCP 445 keepalives, NetBIOS UDP 137, internal DNS UDP 53) and benign workstation traffic (Frames 3268–3289: Google Chrome update check over HTTPS to `update.googleapis.com` / `216.58.193.131:443`).
> 3. The PCAP establishes that network C2 was dormant between bursts, but the internal process state during these gaps cannot be proven from PCAP data alone.

### 3.1 Verified Seven-Cycle Exfiltration Timeline & Transport Security Audit
Every packet frame boundary across all seven exfiltration cycles was extracted directly from `stealer.pcap`:

| Cycle # | DNS Public IP Discovery (`bot.whatismyip`) | HTTP IP Echo (`66.171.248.178:80`) | DNS Mail Host (`macwinlogistics.in`) | SMTP Active Message Range (`23.229.162.69:587`) | SMTP Full Session (incl. Teardown) | Actual Timestamp (UTC) / Elapsed (s) | Measured Delta from Prev. Cycle |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | Frames 3159–3160 | Frames 3161–3169 (Req: 3164, Res: 3166) | Frames 3170–3171 | **Frames 3172–3207** (36 pkts) | Frames 3172–3254 (40 pkts) | `2019-04-10 20:38:15 UTC` (`T + 68.78s`) | Baseline |
| **2** | Frames 3290–3291 | Frames 3292–3300 (Req: 3295, Res: 3297) | Frames 3301–3302 | **Frames 3303–3338** (36 pkts) | Frames 3303–3344 (40 pkts) | `2019-04-10 20:48:20 UTC` (`T + 673.21s`) | **+604.42 s** (10m 04s) |
| **3** | Frames 3377–3378 | Frames 3379–3387 (Req: 3382, Res: 3384) | Frames 3388–3389 | **Frames 3390–3425** (36 pkts) | Frames 3390–3431 (40 pkts) | `2019-04-10 20:58:24 UTC` (`T + 1277.47s`) | **+604.26 s** (10m 04s) |
| **4** | Frames 3462–3463 | Frames 3464–3472 (Req: 3467, Res: 3469) | Frames 3473–3474 | **Frames 3475–3510** (36 pkts) | Frames 3475–3516 (40 pkts) | `2019-04-10 21:08:30 UTC` (`T + 1883.23s`) | **+605.76 s** (10m 05s) |
| **5** | Frames 3577–3578 | Frames 3579–3587 (Req: 3582, Res: 3584) | Frames 3588–3589 | **Frames 3590–3625** (36 pkts) | Frames 3590–3629 (40 pkts) | `2019-04-10 21:18:34 UTC` (`T + 2487.36s`) | **+604.13 s** (10m 04s) |
| **6** | Frames 3832–3833 | Frames 3834–3842 (Req: 3837, Res: 3839) | Frames 3843–3844 | **Frames 3845–3880** (36 pkts) | Frames 3845–3887 (40 pkts) | `2019-04-10 21:28:38 UTC` (`T + 3091.53s`) | **+604.17 s** (10m 04s) |
| **7** | Frames 3910–3911 | Frames 3912–3920 (Req: 3915, Res: 3917) | Frames 3921–3922 | **Frames 3923–3958** (36 pkts) | Frames 3923–3982 (40 pkts) | `2019-04-10 21:38:42 UTC` (`T + 3695.66s`) | **+604.12 s** (10m 04s) |

#### Protocol & Security Dissection:
1. **Server Identity Disambiguation:**
   - Destination host: `23.229.162.69:587`, resolving exclusively from domain `macwinlogistics.in` (banner: `220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91`).
   - Suffix/Subdomain note: Earlier informal writeups used shorthand `mail.winlogistics.in`; packet analysis proves the queried domain is strictly `macwinlogistics.in`.
   - External reference `mail.gulfstreamins.com / 64.233.167.27` does not exist in `stealer.pcap` (0 matching packets across all 4,003 frames); it originated from an unrelated public malware report.
2. **Encryption Status — 100% Cleartext Session:**
   - The mail server advertises `250-STARTTLS` in response to `EHLO` (Frame 3178).
   - The malware client **never sends `STARTTLS`**.
   - Zero TLS records exist on port 587 throughout the entire PCAP.
   - Authentication tokens (`sales.del@macwinlogistics.in` / `Sales@23`) are encoded in RFC 4648 Base64, which is an encoding scheme, not encryption.
   - The entire payload (MIME headers, subject, and captured credential data) is transmitted in cleartext and inspectable by any passive network sniffer or IDS.

---

## 4. Comprehensive MITRE ATT&CK & MITRE D3FEND Handover Matrix

The following matrix maps observed offensive techniques directly to defensive mitigations, detection logic, and verification tests, with explicit classification of evidentiary support:

| Attack Phase | MITRE ATT&CK TTP | Observed Red Team Activity | Identified Blue Team Gap | Recommended Mitigation (MITRE Enterprise) | MITRE D3FEND Countermeasure | Detection Engineering Query / Logic | Evidence Classification |
|:---|:---|:---|:---|:---|:---|:---|:---:|
| **Initial Staging** | **T1105** (Ingress Tool Transfer) | HTTP GET request for `/proforma/tkraw_Protected99.exe` to `217.182.138.150:80` (Frames 207–3155). | Endpoints permitted to download raw PE executables directly over uninspected HTTP. | **M1031** (Network Intrusion Prevention)<br>**M1021** (Restrict Web-Based Content) | **D3-FIP** (File Inspection)<br>**D3-EAP** (Executable Allowlisting) | Proposed Snort / Suricata:<br>`alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"PROPOSED: SUSPICIOUS .exe Download over HTTP"; content:".exe"; nocase; sid:1000001;)` | **Direct Network Evidence** |
| **Reconnaissance** | **T1016** (System Network Configuration Discovery) | DNS query & HTTP lookup to `bot.whatismyipaddress.com` returning public IP `173.66.146.112`. | External IP lookup domains treated as standard web traffic; no alerting on programmatic access. | **M1037** (Filter Network Traffic)<br>**M1030** (Network Segmentation) | **D3-DRA** (DNS Request Analysis) | Sigma / Elastic DSL:<br>`dns.question.name: ("*whatismyip*" OR "*ifconfig.me*" OR "*icanhazip*") AND NOT user.name: "system"` | **Direct Network Evidence** |
| **Data Collection**| **T1056.001** (Keylogging / Input Capture) | HawkEye Keylogger Reborn v9 resident in memory harvesting keystrokes and credentials. | Absence of EDR behavior blocking for untrusted binaries accessing Win32 API hooks (`SetWindowsHookEx`). | **M1040** (Behavior Prevention on Endpoint)<br>**M1049** (Antivirus/Antimalware) | **D3-PSA** (Process Spawn Analysis)<br>**D3-POA** (Process Origin Analysis) | Sysmon Event ID 1 & 11:<br>Detect process creation from user `Temp` or `AppData` spawning network sockets within 60 seconds. | **Inferred (Payload Corroborated)** |
| **Credential Access** | **T1555.003** (Credentials from Web Browsers) | Automated harvesting of browser credentials (`oman.mcguire` Bank of America profile). | Unencrypted credential stores accessible by non-privileged user processes. | **M1027** (Password Policies)<br>**M1043** (Credential Access Protection) | **D3-FAP** (File Access Pattern Analysis) | Sysmon Event ID 11:<br>Monitor non-browser processes accessing `%AppData%\Local\Google\Chrome\User Data\Default\Login Data`. | **Inferred (Payload Corroborated)** |
| **Data Exfiltration** | **T1041** (Exfiltration Over C2 Channel) | Outbound SMTP connection on port 587 with Base64 credentials submitting keylogger archives. | Workstations permitted direct outbound egress to external SMTP servers on port 587. | **M1037** (Filter Network Traffic — Block outbound ports 25, 465, 587 for endpoints) | **D3-OFA** (Outbound Flow Analysis) | Perimeter Firewall Egress Rule:<br>`REJECT tcp from $WORKSTATION_SUBNET to any port [25, 465, 587]` (Permit only designated corporate MTA). | **Direct Network Evidence** |
| **Periodic Cadence** | **T1029** (Scheduled Transfer) | 7 consecutive SMTP cycles repeating at exact 604–606s intervals (Frames 3172–3958). | SIEM lacked sliding-window inter-arrival time calculation for automated beacon detection. | **M1031** (Network Intrusion Prevention) | **D3-NBA** (Network Beaconing Analysis) | Statistical SIEM Aggregation:<br>Flag internal hosts generating $> 5$ connections to same external IP with timestamp delta variance $< 5\%$. | **Direct Network Evidence** |

---

## 5. Detection Engineering Handover Specifications

### 5.1 Proposed Suricata / Snort Signatures
The Blue Team drafted the following proposed network intrusion detection signatures to alert on HawkEye staging and egress:

```snort
# Proposed Rule 1: Detect HawkEye Staging Executable Download
# Status: PROPOSED SPECIFICATION (Untested against live sensor engine)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( \
    msg:"PROPOSED: HawkEye Keylogger Executable Download (.exe)"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    content:".exe"; http_uri; nocase; \
    threshold: type limit, track by_src, count 1, seconds 300; \
    classtype:trojan-activity; sid:2026001; rev:1; \
)

# Proposed Rule 2: Detect Unauthorized Workstation Outbound SMTP Submission
# Status: PROPOSED SPECIFICATION (Untested against live sensor engine)
alert tcp $HOME_NET any -> $EXTERNAL_NET [25, 587] ( \
    msg:"PROPOSED: Unauthorized Egress SMTP Session from End-User Workstation"; \
    flow:to_server,established; \
    content:"AUTH LOGIN"; nocase; \
    threshold: type limit, track by_src, count 1, seconds 60; \
    reference:url,attack.mitre.org/techniques/T1041; \
    classtype:policy-violation; sid:2026002; rev:1; \
)
```

### 5.2 Multi-Event SIEM Correlation Query (Elasticsearch / Lucene)
To identify the complete intrusion sequence as a consolidated incident, the Blue Team specified a stateful SIEM correlation rule matching all three stages within a 15-minute sliding window:

```lucene
# Sequence Correlation Definition (Window: 15 Minutes, Group By: host.name / source.ip)
Stage 1 (Download):
  event.category: "file" AND file.extension: "exe" AND url.path: *tkraw*
      FOLLOWED BY
Stage 2 (Reconnaissance):
  event.category: "dns" AND dns.question.name: "*whatismyipaddress.com"
      FOLLOWED BY
Stage 3 (Exfiltration):
  event.category: "network" AND destination.port: (25 OR 587) AND network.protocol: "smtp"
```

---

## 6. Host & Endpoint Telemetry Improvements (Sysmon & Windows Audit)

While the provided PCAP captures network wire telemetry, closing the visibility gap requires host-level sensor coverage:
1. **Sysmon Event ID 1 (Process Creation):** Ensure command-line logging (`CommandLine`) and parent process fields (`ParentImage`, `ParentCommandLine`) are active to catch process injection and staging execution.
2. **Sysmon Event ID 3 (Network Connection):** Correlate endpoint socket creation with destination port 587 to identify which local PID initiated the mail connection.
3. **Sysmon Event ID 11 (File Create):** Monitor for dropped binaries in user-writable paths:
   - `C:\Users\*\AppData\Local\Temp\`
   - `C:\Users\Public\`
4. **PowerShell Script Block Logging (Event ID 4104):** Enable system-wide transcription to detect Living-off-the-Land helper scripts.

---

## 7. Incident Response & Containment Playbook Handover

If similar TTPs are detected in enterprise telemetry, the SOC Tier 2 incident handling team must execute the following response actions:
1. **Network Containment:** Issue immediate EDR host isolation for `10.4.10.132` to terminate outbound SMTP channels while preserving memory telemetry.
2. **Perimeter Firewall Blocks:** Push permanent IP block rules for `217.182.138.150` (Download server) and `23.229.162.69` (C2 SMTP server).
3. **Domain Sinkholing:** Configure internal DNS sinkholes on `10.4.10.4` for `proforma-invoices.com`, `macwinlogistics.in`, and legacy alias `mail.winlogistics.in`.
4. **Credential Revocation:** Immediately reset passwords for compromised email identity `sales.del@macwinlogistics.in` and impacted bank profiles (`oman.mcguire`).
5. **Memory & Disk Forensics:** Acquire full physical RAM dump and triage image of `Beijing-5cd1-PC` before re-imaging from golden baseline.

---

## 8. Purple Team Collaborative Retrospective & Conclusion

The HawkEye exercise demonstrates the strategic necessity of Purple Teaming. By aligning Red Team offensive execution (`proforma-invoices.com` $\rightarrow$ IP lookup $\rightarrow$ periodic SMTP) with Blue Team sensor capabilities, defensive engineering moves from reactive perimeter alerting to proactive, multi-stage detection.

Implementing the recommended egress firewall rules, proposed network signatures, and Sysmon process correlation significantly reduces defensive visibility gaps and provides practical detection opportunities across network and endpoint boundaries.
