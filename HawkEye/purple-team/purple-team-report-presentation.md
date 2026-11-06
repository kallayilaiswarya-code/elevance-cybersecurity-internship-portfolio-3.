# HawkEye — Purple Team Handover Report

## 1. Executive Summary

This Purple Team report bridges adversary tradecraft emulation and defensive detection engineering through a comprehensive analysis of the CyberDefenders HawkEye intrusion dataset (`stealer.pcap`). The capture contains **4,003 packets** spanning **1 hour, 3 minutes, and 41 seconds** of continuous telemetry.

The primary compromised workstation is **`10.4.10.132`** (`Beijing-5cd1-PC`). The threat lifecycle unfolded across four distinct operational phases:

1. **Payload Ingress (Frames 204–3155):** HTTP download of binary `tkraw_Protected99.exe` (MD5: `71826BA081E303866CE2A2534491A2F7`) from `217.182.138.150:80` following DNS resolution of `proforma-invoices.com`.
2. **Reconnaissance & Egress Verification (Frames 3159–3167):** DNS query to `bot.whatismyipaddress.com` resolving to server IP `66.171.248.178`, followed by an HTTP query returning the victim's true public NAT IP: **`173.66.146.112`**.
3. **Covert Exfiltration Channel (Frames 3172–3207):** Transmission of captured credentials and keylogger data over unencrypted SMTP to `23.229.162.69:587` (`macwinlogistics.in`, Exim 4.91 banner `p3plcpnl0413.prod.phx3.secureserver.net`) using cleartext Base64 authentication.
4. **Recurring ~10-Minute Cadence:** Seven distinct exfiltration cycles recurring at regular intervals of **604–606 seconds (~10 minutes)**, concluding with Cycle 7 in Frames 3910–3982.

### Purple Team Lifecycle Handover Matrix

> [!NOTE]
> **Defensive Engineering Implementation Status:** The MITRE D3FEND countermeasures documented in this section represent **recommended architectural hardening controls** designed for production enterprise SOC environments (e.g. AppLocker allowlisting, firewall egress port filtering). They are proposed specifications and were not deployed or tested in the live challenge network, with the exception of local Snort/Suricata and Sigma detection rule logic evaluated as proposed rule specifications.

| Observed Red Team Activity | MITRE ATT&CK | Identified Blue Team Gap | Engineered Blue Team Detection | Recommended D3FEND Countermeasure (Proposed Hardening) |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP Executable Ingress** | T1105 Ingress Tool Transfer | Unrestricted HTTP executable downloads from untrusted hosts | Suricata/Snort PE file carving rule; Zeek `files.log` alert | **D3-FCOA** File Content Analysis / **D3-EAL** Executable Allowlisting |
| **External IP Discovery** | T1016 System Network Configuration Discovery | Unmonitored programmatic IP discovery queries | DNS threat intelligence filtering; Sysmon Event ID 22 | **D3-DNSTA** DNS Traffic Analysis |
| **SMTP Auth on Port 587** | T1041 Exfiltration Over C2 Channel | Workstations permitted direct outbound SMTP to external relays | Perimeter firewall egress rule alerting on non-mail server SMTP | **D3-NTF** Network Traffic Filtering |
| **10-Min Periodic Beaconing** | T1029 Scheduled Transfer | SIEM lacked sliding-window inter-arrival time calculation | Statistical sliding-window inter-arrival time analysis | **D3-NTA** Network Traffic Analysis |

---

## 2. PCAP Evidence Disambiguation: 66.171.248.178 vs. 173.66.146.112

A primary requirement of forensic integrity is clearly separating third-party cloud lookup services from the victim system's external identity:

| IP Address | Role & Network Context | Empirical PCAP Telemetry | Evidentiary Finding |
| :--- | :--- | :--- | :--- |
| **`66.171.248.178`** | External Web Service (`bot.whatismyipaddress.com`) | • **DNS Answer (Frame 3160):** Resolves `bot.whatismyipaddress.com` to `66.171.248.178`.<br>• **HTTP Connection (Frame 3164):** Victim workstation connects to `66.171.248.178:80`. | **External Service.** This is an external third-party lookup host, NOT the victim workstation. |
| **`173.66.146.112`** | Victim Workstation's Public NAT Address | • **HTTP Payload (Frame 3166):** Service returns 14-byte payload `"173.66.146.112"`.<br>• **SMTP Greeting (Frame 3178):** Remote mail server greets client: `250 Hello Beijing-5cd1-PC [173.66.146.112]`.<br>• **Malware Body (Frame 3194):** HawkEye embeds `"173.66.146.112"` into the stolen system info block. | **Victim Public IP.** This is the victim system's actual external Internet egress address. |

---

## 3. Evidence Classification: Wire Telemetry vs. Inferred Host Behavior

To maintain analytical precision, all forensic conclusions are categorized into three distinct evidentiary tiers:

| Analysis Domain | 1. Directly Observed Wire Evidence (PCAP Ground Truth) | 2. Forensic Interpretation (Corroborated) | 3. Unobservable from PCAP Alone |
| :--- | :--- | :--- | :--- |
| **Payload Ingress** | HTTP GET `/proforma/tkraw_Protected99.exe` in Frame 210 transferring 2,025,472 bytes across reassembled TCP Frames 214–3155. | Executable delivered to disk on host `10.4.10.132`. | Initial user launch mechanism (manual double-click vs. helper script). |
| **System Discovery** | DNS lookup and HTTP transaction to `bot.whatismyipaddress.com` returning `173.66.146.112`. | External IP lookup executed to record victim's public IP address. | Underlying API calls (`ipconfig`, WinINet, or socket libraries). |
| **Data Collection** | Frame 3194 payload containing keystrokes, OS metadata, and bank profile (`oman.mcguire`). | Data harvested locally from browser stores and keyboard hooks. | In-memory hook mechanics (`SetWindowsHookEx`) or RAM buffer states during idle periods. |
| **Data Exfiltration** | SMTP session on port 587 to `23.229.162.69` authenticated via `sales.del@macwinlogistics.in` (cleartext Base64). | Unencrypted C2 channel operating over standard mail submission port. | Local process ID (PID) or thread owning the network socket. |
| **Periodic Cadence** | Seven repeating exfiltration bursts at ~604–606s intervals (Frames 3172–3982; capture ends at Packet 4,003). | Automated timing mechanism driving regular egress bursts. | Exact host process state during silent gaps: `Sleep()` loop vs. thread timer vs. Scheduled Task. |
| **Initial Delivery** | Inbound HTTP staging download from `217.182.138.150:80` in Frame 210 (Handshake: Frames 207–209, Payload: Frames 214–3155). | Staging server hosted malicious executable for download. | Delivery lure or phishing email (not captured in PCAP; inferred from campaign patterns). |

> [!NOTE]
> **Inter-Cycle Gap Network Telemetry Verification:**
> An exhaustive filter across all silent intervals between exfiltration cycles (Frames 3255–3289, 3345–3376, 3432–3461, 3517–3576, 3630–3831, 3888–3909) confirms:
> 1. Zero packets were transmitted to port 587 or C2 IP `23.229.162.69` during the ~10-minute intervals.
> 2. Traffic in these gaps consisted exclusively of internal LAN communications (SMB keepalives on port 445, NetBIOS UDP 137, internal DNS UDP 53) and benign workstation activity (Frames 3268–3289: Google Chrome update check over HTTPS to `update.googleapis.com` / `216.58.193.131:443`).
> 3. The network channel was completely idle between bursts; internal host thread states during these gaps cannot be confirmed from PCAP data alone.

---

## 4. Verified Seven-Cycle Exfiltration Timeline

Every packet frame boundary across all seven exfiltration cycles was extracted directly from `stealer.pcap`:

| Cycle | DNS Public IP Discovery (`bot.whatismyip`) | HTTP IP Echo (`66.171.248.178:80`) | DNS Mail Host (`macwinlogistics.in`) | Active SMTP Transmission (`23.229.162.69:587`) | Full SMTP Session (incl. Teardown) | Timestamp (UTC) / Elapsed (s) | Measured Delta from Previous Cycle |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | Frames 3159–3160 | Frames 3161–3169 (Req: 3164, Res: 3166) | Frames 3170–3171 | **Frames 3172–3207** (36 pkts) | Frames 3172–3254 (40 pkts) | `2019-04-10 20:38:15 UTC` (`T + 68.78s`) | Baseline |
| **2** | Frames 3290–3291 | Frames 3292–3300 (Req: 3295, Res: 3297) | Frames 3301–3302 | **Frames 3303–3338** (36 pkts) | Frames 3303–3344 (40 pkts) | `2019-04-10 20:48:20 UTC` (`T + 673.21s`) | **+604.42 s** (10m 04s) |
| **3** | Frames 3377–3378 | Frames 3379–3387 (Req: 3382, Res: 3384) | Frames 3388–3389 | **Frames 3390–3425** (36 pkts) | Frames 3390–3431 (40 pkts) | `2019-04-10 20:58:24 UTC` (`T + 1277.47s`) | **+604.26 s** (10m 04s) |
| **4** | Frames 3462–3463 | Frames 3464–3472 (Req: 3467, Res: 3469) | Frames 3473–3474 | **Frames 3475–3510** (36 pkts) | Frames 3475–3516 (40 pkts) | `2019-04-10 21:08:30 UTC` (`T + 1883.23s`) | **+605.76 s** (10m 05s) |
| **5** | Frames 3577–3578 | Frames 3579–3587 (Req: 3582, Res: 3584) | Frames 3588–3589 | **Frames 3590–3625** (36 pkts) | Frames 3590–3629 (40 pkts) | `2019-04-10 21:18:34 UTC` (`T + 2487.36s`) | **+604.13 s** (10m 04s) |
| **6** | Frames 3832–3833 | Frames 3834–3842 (Req: 3837, Res: 3839) | Frames 3843–3844 | **Frames 3845–3880** (36 pkts) | Frames 3845–3887 (40 pkts) | `2019-04-10 21:28:38 UTC` (`T + 3091.53s`) | **+604.17 s** (10m 04s) |
| **7** | Frames 3910–3911 | Frames 3912–3920 (Req: 3915, Res: 3917) | Frames 3921–3922 | **Frames 3923–3958** (36 pkts) | Frames 3923–3982 (40 pkts) | `2019-04-10 21:38:42 UTC` (`T + 3695.66s`) | **+604.12 s** (10m 04s) |

### Protocol & Security Findings
* **Mail Server Identity:** Destination `23.229.162.69:587` resolves strictly from domain `macwinlogistics.in` (service banner: `220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91`). Informal writeups previously cited `mail.winlogistics.in`; packet analysis proves the queried apex domain is `macwinlogistics.in`.
* **External Reference Disambiguation:** External reference `mail.gulfstreamins.com` / `64.233.167.27` is not present in `stealer.pcap` (0 matching packets across all 4,003 frames); it originated from an unrelated public malware writeup.
* **Cleartext Session (Zero Encryption):** The server advertises `250-STARTTLS` in Frame 3178, but the malware client **never requests TLS**. Authentication tokens (account: `sales.del@macwinlogistics.in` / password: `[REDACTED_LAB_PASSWORD: Decoded SMTP authentication secret redacted for public portfolio presentation; reversible Base64 token documented in lab evidence]`) are encoded in RFC 4648 Base64, which is a reversible encoding scheme rather than encryption. All message contents and stolen credentials are fully exposed on the wire.

---

## 5. Comprehensive MITRE ATT&CK & D3FEND Mapping

| Attack Phase | MITRE ATT&CK | Observed Red Team Activity | Identified Blue Team Gap | Recommended Mitigation (MITRE Enterprise) | Recommended D3FEND Countermeasure (Proposed Hardening) | Detection Logic / Query | Evidence Tier |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Initial Staging** | **T1105** Ingress Tool Transfer | HTTP GET request for `/proforma/tkraw_Protected99.exe` to `217.182.138.150:80` (Frame 210; Handshake: Frames 207–209; Payload: Frames 214–3155). | Workstations permitted to download executable binaries over uninspected HTTP. | **M1031** Network Intrusion Prevention<br>**M1021** Restrict Web Content | **D3-FCOA** File Content Analysis<br>**D3-EAL** Executable Allowlisting | Proposed Snort/Suricata PE file carving rule | Direct Network Evidence |
| **Reconnaissance** | **T1016** System Network Configuration Discovery | DNS query & HTTP lookup to `bot.whatismyipaddress.com` returning public IP `173.66.146.112`. | External IP lookup domains treated as standard web traffic; no alerting on programmatic access. | **M1037** Filter Network Traffic<br>**M1030** Network Segmentation | **D3-DNSTA** DNS Traffic Analysis | Sigma/Elastic DSL query for programmatic IP services | Direct Network Evidence |
| **Data Collection** | **T1056.001** Keylogging / Input Capture | HawkEye Keylogger Reborn v9 resident in memory harvesting keystrokes and credentials. | Absence of EDR behavior blocking for untrusted binaries accessing Win32 API hooks (`SetWindowsHookEx`). | **M1040** Behavior Prevention on Endpoint<br>**M1049** Antivirus/Antimalware | **D3-PSA** Process Spawn Analysis<br>**D3-PLA** Process Lineage Analysis | Sysmon Event ID 1 & 11 detecting process creation in `Temp` or `AppData` | Inferred (Payload Corroborated) |
| **Credential Access** | **T1555.003** Credentials from Web Browsers | Automated harvesting of browser credentials (`oman.mcguire` Bank of America profile). | Unencrypted credential stores accessible by non-privileged user processes. | **M1027** Password Policies<br>**M1043** Credential Access Protection | **D3-FAPA** File Access Pattern Analysis | Sysmon Event ID 11 monitoring non-browser access to Chrome `Login Data` | Inferred (Payload Corroborated) |
| **Data Exfiltration** | **T1041** Exfiltration Over C2 Channel | Outbound SMTP connection on port 587 with Base64 credentials submitting keylogger archives. | Workstations permitted direct outbound egress to external SMTP servers on port 587. | **M1037** Filter Network Traffic (Block outbound ports 25, 465, 587 for endpoints) | **D3-NTF** Network Traffic Filtering | Perimeter firewall rule rejecting workstation SMTP egress | Direct Network Evidence |
| **Periodic Cadence** | **T1029** Scheduled Transfer | 7 consecutive SMTP cycles repeating at exact 604–606s intervals (Frames 3172–3958). | SIEM lacked sliding-window inter-arrival time calculation for automated beacon detection. | **M1031** Network Intrusion Prevention | **D3-NTA** Network Traffic Analysis | Statistical SIEM query calculating timestamp variance across repeated connections | Direct Network Evidence |

---

## 6. Detection Engineering Handover Specifications

### 6.1 Proposed Suricata / Snort Signatures
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

### 6.2 Multi-Event SIEM Correlation Query (Elasticsearch / Lucene)
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

## 7. Endpoint Telemetry & Incident Response Handover

### 7.1 Sysmon & Audit Logging Configuration
* **Sysmon Event ID 1 (Process Creation):** Ensure command-line logging (`CommandLine`) and parent process fields (`ParentImage`, `ParentCommandLine`) are enabled to capture process injection and staging.
* **Sysmon Event ID 3 (Network Connection):** Correlate endpoint socket creation with destination port 587 to identify the local process ID (PID) initiating mail connections.
* **Sysmon Event ID 11 (File Create):** Monitor for dropped binaries in user-writable paths (`AppData\Local\Temp`, `C:\Users\Public`).

### 7.2 Containment & Eradication Playbook
If similar indicators are observed in enterprise monitoring:
1. **Network Containment:** Isolate host `10.4.10.132` via EDR to sever outbound SMTP sessions while preserving volatile memory.
2. **Perimeter Firewall Blocks:** Push permanent IP block rules for `217.182.138.150` (malware host) and `23.229.162.69` (C2 SMTP server).
3. **Internal DNS Sinkholing:** Configure internal DNS sinkholes on `10.4.10.4` redirecting `proforma-invoices.com`, `macwinlogistics.in`, and legacy alias `mail.winlogistics.in` to loopback (`127.0.0.1`).
4. **Credential Revocation:** Immediately reset passwords for compromised mail account `sales.del@macwinlogistics.in` and impacted bank profile (`oman.mcguire`).
5. **Host Triage:** Capture full RAM image and triage disk artifacts from `Beijing-5cd1-PC` before re-imaging from golden baseline.

---

## 8. Conclusion

The HawkEye Purple Team exercise highlights the value of aligning offensive emulation with defensive engineering. By correlating adversary techniques (`proforma-invoices.com` $\rightarrow$ public IP discovery $\rightarrow$ periodic SMTP transmission) with detection logic, defensive operations move from isolated perimeter alerting to coordinated, multi-stage detection coverage across network and host boundaries.
