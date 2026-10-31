# HawkEye — Red Team Report

## 1. Executive Summary

This report documents the HawkEye incident from a Red Team perspective based on analysis of the provided `stealer.pcap` network capture.

The investigation identified an internal host, `10.4.10.132`, downloading a Windows executable named `tkraw_Protected99.exe` from `217.182.138.150` over HTTP.

Following the download, the host performed an external-IP lookup, contacted the returned external IP address over HTTP, and established SMTP communication with `23.229.162.69` on port `587`.

The SMTP session showed successful authentication and submission of email containing HawkEye keylogger/password-log information. Similar SMTP submission activity repeated throughout the capture.

The observed network sequence demonstrates executable acquisition followed by credential-related data transmission.

> Note: This report documents behavior supported by the network capture. The PCAP does not establish the exact initial compromise method, whether the downloaded executable was executed, or the identity of the attacker.

---

## 2. Lab Environment

| Item | Details |
|---|---|
| Investigation dataset | `stealer.pcap` |
| Primary internal host | `10.4.10.132` |
| Internal DNS server | `10.4.10.4` |
| Network analysis tool | Wireshark |
| Evidence type | Network packet capture (PCAP) |
| Primary focus | Executable download and credential-related data transmission |

---

## 3. Observed Attack Sequence

1. The internal host `10.4.10.132` performed DNS activity associated with `proforma-invoices.com`.
2. The domain resolved to `217.182.138.150`.
3. The host established an HTTP connection to the external server.
4. The HTTP request requested `/proforma/tkraw_Protected99.exe`.
5. The server returned `200 OK`.
6. The downloaded executable was identified as `tkraw_Protected99.exe`.
7. The host subsequently queried `bot.whatismyipaddress.com`.
8. The lookup returned `66.171.248.178`.
9. The host contacted `66.171.248.178` over HTTP.
10. The host resolved `mail.winlogistics.in` to `23.229.162.69`.
11. An SMTP connection was established to port `587`.
12. SMTP authentication succeeded.
13. An email containing HawkEye keylogger/password-log information was submitted.
14. Similar SMTP submission activity repeated approximately every 10 minutes.

---

## 4. Attack Methodology

### 4.1 Executable Acquisition

The observed HTTP connection originated from:

`10.4.10.132`

and connected to:

`217.182.138.150`

The request was associated with:

`proforma-invoices.com`

The requested resource was:

`/proforma/tkraw_Protected99.exe`

The HTTP response returned `200 OK`.

The executable was extracted from the HTTP stream and preserved as evidence.

### 4.2 File Identification

The extracted file was:

`tkraw_Protected99.exe`

File hashes:

| Algorithm | Hash |
|---|---|
| MD5 | `71826BA081E303866CE2A2534491A2F7` |
| SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |

The web server identified in the HTTP response was:

`LiteSpeed`

The CyberDefenders HawkEye investigation identifies the malware variant as:

`HawkEye Keylogger - Reborn v9`

### 4.3 External-IP Discovery

After the executable download, the host queried:

`bot.whatismyipaddress.com`

The lookup returned:

`66.171.248.178`

The host then made an HTTP connection to the returned address.

This activity is relevant from a Red Team perspective because external-IP discovery can provide information about the victim's public network address.

### 4.4 SMTP Data Transmission

The host resolved:

`mail.winlogistics.in`

to:

`23.229.162.69`

It then established SMTP communication over:

`TCP/587`

The SMTP server identified itself as:

`Exim 4.91`

The captured traffic showed successful SMTP authentication followed by submission of collected information.

The observed email account was:

`sales.del@macwinlogistics.in`

Sensitive credential values are intentionally not reproduced in this report.

---

## 5. Repeated Exfiltration Pattern

The capture showed repeated external-IP lookup and SMTP activity at approximately:

- 68.5 seconds
- 672.9 seconds
- 1277.2 seconds
- 1883.0 seconds
- 2487.1 seconds
- 3091.3 seconds
- 3695.4 seconds

The intervals were approximately 604–605 seconds, corresponding to approximately 10 minutes.

The repeated sequence consisted of external-IP lookup followed by SMTP communication and submission activity.

---

## 6. Red Team Perspective

From an adversary-behavior perspective, the observed network sequence contains several distinct stages:

| Stage | Observed Activity |
|---|---|
| Acquisition | HTTP retrieval of `tkraw_Protected99.exe` |
| Network discovery | External public-IP lookup |
| External communication | HTTP connection to `66.171.248.178` |
| Collection/exfiltration channel | SMTP communication |
| Authentication | Successful SMTP authentication |
| Data transfer | Submission of credential-related information |
| Persistence of activity | Repeated approximately 10-minute submissions |

The PCAP demonstrates the network-side behavior of the activity but does not provide enough evidence to establish the complete endpoint execution chain.

---

## 7. Indicators Relevant to Red Team Analysis

| Type | Indicator |
|---|---|
| Internal host | `10.4.10.132` |
| Download domain | `proforma-invoices.com` |
| Download IP | `217.182.138.150` |
| Malicious file | `tkraw_Protected99.exe` |
| External-IP lookup domain | `bot.whatismyipaddress.com` |
| Returned public IP | `66.171.248.178` |
| SMTP server | `23.229.162.69` |
| SMTP domain | `mail.winlogistics.in` |
| SMTP port | `587` |
| File MD5 | `71826BA081E303866CE2A2534491A2F7` |
| File SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |

---

## 8. Red Team Findings

The network evidence demonstrates:

1. Retrieval of a suspicious Windows executable over HTTP.
2. Communication with infrastructure associated with the executable download.
3. External-IP discovery activity.
4. SMTP-based communication to an external server.
5. Successful SMTP authentication.
6. Submission of credential-related information.
7. Repeated data-submission activity at approximately 10-minute intervals.

These observations provide useful indicators for defensive monitoring and Purple Team detection engineering.

---

## 9. Limitations

The analysis is based on network-level evidence contained in the supplied PCAP.

The capture alone does not establish:

- The exact initial-access method.
- Whether the downloaded executable was executed.
- The complete endpoint process chain.
- The identity of the attacker.
- The full contents of the affected endpoint.

Sensitive credentials observed during the lab are intentionally excluded from this report.

---

## 10. Conclusion

The HawkEye PCAP demonstrates a sequence involving executable acquisition, external-IP discovery, SMTP authentication, and repeated credential-related data transmission.

From a Red Team perspective, the most significant observable characteristics are the suspicious executable download, external infrastructure communication, SMTP-based data submission, and recurring approximately 10-minute communication pattern.

These behaviors provide concrete indicators that can be used by Blue Team analysts to develop detection rules and by Purple Team analysts to validate defensive coverage.
