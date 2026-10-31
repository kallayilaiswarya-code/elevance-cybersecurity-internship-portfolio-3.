# HawkEye Investigation Notes

## Investigation Objective

The objective was to reconstruct the HawkEye Keylogger data-exfiltration incident by analyzing the supplied network capture and documenting observable indicators, communication patterns, and extracted artifacts.

## Evidence Analyzed

- Network capture: `stealer.pcap` (4,003 packets, 2,454,198 bytes)
- Extracted executable: `tkraw_Protected99.exe` (2,025,472 bytes)
- Network analysis tool: Wireshark
- Lab platform: CyberDefenders HawkEye

## Host Identification

- Most active network-level host: `Beijing-5cd1-PC`
- Victim internal IP: `10.4.10.132`
- Victim MAC Address: `0:08:02:1c:47:ae` (NIC Manufacturer: Hewlett-Packard, HQ: Palo Alto)
- Organization DNS server: `10.4.10.4`
- Victim operating system: Windows NT 6.1 (Windows 7 / Server 2008 R2)
- Internal enterprise computers observed: 3

## Malicious File Analysis

The PCAP contains an HTTP download request from `10.4.10.132` for:

`/proforma/tkraw_Protected99.exe`

The request was addressed to:

`proforma-invoices.com`

The domain resolved to server IP:

`217.182.138.150` (France, OVH SAS)

The HTTP response returned `200 OK` and identified the web server as LiteSpeed.

The executable was extracted from the reassembled TCP stream (Frames 213–3155) for evidentiary preservation.

### File Hashes

- MD5: `71826BA081E303866CE2A2534491A2F7`
- SHA-256: `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11`

The CyberDefenders investigation identifies the malware variant as:

**HawkEye Keylogger - Reborn v9**

## Network and Exfiltration Activity

Following executable download and execution, the host initiated automated external IP reconnaissance by querying:

`bot.whatismyipaddress.com`

- **External Service Resolution:** The domain resolved to DNS A record `66.171.248.178`.
- **Returned Victim Public IP:** The HTTP response body returned the victim workstation's public gateway IP address: **`173.66.146.112`**.

This lookup was immediately followed by outbound SMTP communication to:

`23.229.162.69` (Port 587)

The destination mail server identified itself in the initial 220 banner as:

`Exim 4.91` (`p3plcpnl0413.prod.phx3.secureserver.net`)

Upon client `EHLO Beijing-5cd1-PC`, the mail server explicitly corroborated the victim's public IP:

`250-p3plcpnl0413.prod.phx3.secureserver.net Hello Beijing-5cd1-PC [173.66.146.112]`

SMTP authentication (`AUTH LOGIN`) was observed using credentials:

- Username: `[REDACTED_LAB_USERNAME]` (Base64: `[REDACTED_BASE64_USER]`)
- Password: `[REDACTED_LAB_PASSWORD]` (Base64: `[REDACTED_BASE64_PASSWORD]`)

Following authentication, the malware transmitted stolen system telemetry, keystrokes, and Bank of America credentials via an email message with subject `HawkEye Keylogger - Reborn v9`.

## Repeated Exfiltration Pattern

The packet capture demonstrates a strict, periodic exfiltration routine:
- Seven distinct exfiltration cycles were recorded over the 63-minute capture.
- Activity points: ~68.5 s, ~672.9 s, ~1277.2 s, ~1883.0 s, ~2487.1 s, ~3091.3 s, and ~3695.4 s.
- Interval duration: Approximately **604–606 seconds** (~10 minutes).
- Every cycle strictly performs an external IP lookup via `bot.whatismyipaddress.com` prior to opening the SMTP socket to `23.229.162.69:587`.

## Important Investigation Limitation

The PCAP provides network-level evidence. It captures the network download of the binary and subsequent egress communication, but does not include host-level endpoint telemetry (such as initial phishing email attachments, process command-line arguments, or parent-child process trees).

Sensitive credential values observed during the lab were analyzed solely to answer CyberDefenders challenge requirements.
