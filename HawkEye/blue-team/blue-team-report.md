# HawkEye — Blue Team Report

## 1. Executive Summary

This report documents the HawkEye incident from a Blue Team / SOC analyst perspective using the supplied `stealer.pcap` network capture.

The investigation focused on identifying suspicious network activity, reconstructing the incident timeline, extracting indicators of compromise, and identifying detection and response opportunities.

The primary internal host was:

`10.4.10.132`

The observed sequence included:

1. DNS resolution of `proforma-invoices.com`
2. HTTP download of `tkraw_Protected99.exe`
3. External-IP lookup through `bot.whatismyipaddress.com`
4. HTTP communication with `66.171.248.178`
5. DNS resolution of `mail.winlogistics.in`
6. SMTP communication with `23.229.162.69:587`
7. Successful SMTP authentication
8. Submission of credential-related information
9. Repeated SMTP activity at approximately 10-minute intervals

These observations provide multiple network-level detection opportunities.

---

## 2. Incident Overview

### 2.1 Primary Host

The main internal system involved in the observed activity was:

`10.4.10.132`

The network-level hostname identified during the investigation was:

`Beijing-5cd1-PC`

The internal DNS server was:

`10.4.10.4`

The operating system identified from the network evidence was:

`Windows NT 6.1`

### 2.2 Capture Details

| Item | Value |
|---|---|
| Capture | `stealer.pcap` |
| Packet count | `4003` |
| Primary analysis tool | Wireshark |
| Evidence type | Network packet capture |
| Capture duration | `01:03:41` |

---

## 3. Detection Timeline

| Approx. Time | Observed Activity |
|---:|---|
| ~47.6 s | HTTP request for `tkraw_Protected99.exe` |
| ~48.9 s | HTTP `200 OK` response containing the executable |
| ~68.5 s | DNS lookup for `bot.whatismyipaddress.com` |
| ~68.6 s | `66.171.248.178` returned by the lookup |
| ~68.8 s | SMTP connection to `23.229.162.69:587` |
| ~68.8 s | SMTP authentication |
| ~69 s | Email/data submission |
| ~672.9 s | Repeated external-IP lookup and SMTP activity |
| ~1277.2 s | Repeated external-IP lookup and SMTP activity |
| ~1883.0 s | Repeated external-IP lookup and SMTP activity |
| ~2487.1 s | Repeated external-IP lookup and SMTP activity |
| ~3091.3 s | Repeated external-IP lookup and SMTP activity |
| ~3695.4 s | Repeated external-IP lookup and SMTP activity |

The repeated activity occurs approximately every 604–605 seconds, corresponding to approximately 10 minutes.

---

## 4. Suspicious Network Activity

### 4.1 Executable Download

The host:

`10.4.10.132`

requested:

`/proforma/tkraw_Protected99.exe`

from:

`proforma-invoices.com`

The domain resolved to:

`217.182.138.150`

The HTTP response returned:

`200 OK`

The web server identified itself as:

`LiteSpeed`

The executable was extracted from the HTTP stream for evidence preservation.

### 4.2 File Indicators

| Indicator | Value |
|---|---|
| Filename | `tkraw_Protected99.exe` |
| MD5 | `71826BA081E303866CE2A2534491A2F7` |
| SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |

The CyberDefenders investigation identifies the malware variant as:

`HawkEye Keylogger - Reborn v9`

### 4.3 External-IP Lookup

The host subsequently queried:

`bot.whatismyipaddress.com`

The response identified the external address:

`66.171.248.178`

The host then made an HTTP connection to that address.

From a SOC perspective, an endpoint unexpectedly querying an external-IP service followed by suspicious external communication is a useful correlation signal.

### 4.4 SMTP Communication

The host resolved:

`mail.winlogistics.in`

to:

`23.229.162.69`

It established SMTP communication over:

`TCP/587`

The SMTP server identified itself as:

`Exim 4.91`

Successful SMTP authentication was observed, followed by submission of collected information.

The observed account was:

`sales.del@macwinlogistics.in`

Sensitive credentials observed in the lab are intentionally excluded from this report.

---

## 5. Indicators of Compromise

| Type | Indicator |
|---|---|
| Internal host | `10.4.10.132` |
| Hostname | `Beijing-5cd1-PC` |
| DNS server | `10.4.10.4` |
| Download domain | `proforma-invoices.com` |
| Download IP | `217.182.138.150` |
| Malicious file | `tkraw_Protected99.exe` |
| File MD5 | `71826BA081E303866CE2A2534491A2F7` |
| File SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |
| IP lookup domain | `bot.whatismyipaddress.com` |
| Returned external IP | `66.171.248.178` |
| SMTP domain | `mail.winlogistics.in` |
| SMTP server | `23.229.162.69` |
| SMTP port | `587` |

---

## 6. Detection Opportunities

### 6.1 Suspicious Executable Downloads

Monitor HTTP traffic for executable downloads, especially:

- `.exe` files
- `application/x-msdownload`
- Unusual executable paths
- Downloads from domains not normally associated with business activity

A request for:

`/proforma/tkraw_Protected99.exe`

would be a high-value investigation event in this case.

### 6.2 External-IP Lookup Correlation

Create a correlation rule for:

1. Internal endpoint queries an external-IP discovery service.
2. The same endpoint communicates with a newly observed external IP.
3. The activity is followed by SMTP communication.

The combination is more useful than any individual event alone.

### 6.3 Suspicious SMTP From Endpoints

Monitor endpoints that initiate outbound SMTP connections, particularly:

- TCP/587
- Successful SMTP authentication
- Repeated message submission
- Unusual external SMTP destinations

An endpoint generating periodic SMTP submissions should be investigated when this behavior is not expected.

### 6.4 Periodic Communication

The repeated approximately 10-minute pattern can be used as a behavioral detection signal.

Repeated sequences of:

`External-IP lookup → SMTP connection → authentication → submission`

should be correlated by source host and time interval.

---

## 7. Recommended SOC Response

If similar activity is detected in a live environment:

1. Identify the affected endpoint.
2. Preserve relevant network and endpoint evidence.
3. Isolate the affected endpoint if appropriate under the organization's incident-response procedure.
4. Block or investigate confirmed malicious infrastructure.
5. Search for the file hashes across available endpoint and network telemetry.
6. Review outbound SMTP activity from the affected host.
7. Investigate authentication activity associated with the observed account.
8. Review other endpoints for the same indicators.
9. Reset affected credentials according to organizational procedures if compromise is confirmed.
10. Document the timeline and preserve evidence for further investigation.

These actions are general defensive recommendations; the supplied PCAP alone does not establish the full endpoint compromise chain.

---

## 8. Detection-to-Response Mapping

| Observed Behavior | Detection Opportunity | Response |
|---|---|---|
| Executable downloaded over HTTP | Monitor executable downloads | Investigate endpoint and preserve evidence |
| Suspicious domain resolution | DNS monitoring | Search related DNS activity |
| External-IP lookup | DNS/service correlation | Correlate with subsequent connections |
| SMTP connection from endpoint | Outbound SMTP monitoring | Investigate source endpoint |
| Successful SMTP authentication | Authentication monitoring | Review account activity |
| Repeated 10-minute submissions | Periodicity/behavioral detection | Investigate automated activity |
| Known file hash | Hash-based detection | Search and contain matching artifacts |

---

## 9. Investigation Limitations

The analysis is based on network-level evidence contained in the supplied PCAP.

The capture alone does not establish:

- The exact initial-access method.
- Whether the downloaded executable was executed.
- The complete local process-execution chain.
- The identity of the attacker.
- The complete endpoint state.

Sensitive credential values from the lab are intentionally excluded from this report.

---

## 10. Conclusion

The HawkEye investigation demonstrates how network telemetry can be used by a SOC analyst to identify a suspicious executable download, trace related network infrastructure, detect SMTP-based data submission, and identify a recurring communication pattern.

The strongest defensive value comes from correlating multiple signals rather than relying on a single indicator.

The identified domains, IP addresses, file hashes, SMTP behavior, and approximately 10-minute periodicity provide concrete starting points for network detection and incident response.

Supporting evidence and detailed investigation material are available in the `cyberdefenders-hawkeye` directory.
