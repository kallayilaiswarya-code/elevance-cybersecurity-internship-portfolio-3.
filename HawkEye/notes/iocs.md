# HawkEye Indicators of Compromise (IOCs)

## 1. Internal Host

| Indicator | Value | Context |
|---|---|---|
| Internal IP | `10.4.10.132` | Host observed downloading the executable and communicating with external services |

---

## 2. Internal DNS Server

| Indicator | Value | Context |
|---|---|---|
| DNS server | `10.4.10.4` | Internal DNS server observed resolving external domains |

---

## 3. Downloaded Executable

| Indicator | Value | Context |
|---|---|---|
| Filename | `tkraw_Protected99.exe` | Executable downloaded over HTTP |
| SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` | Hash of extracted executable |
| HTTP path | `/proforma/tkraw_Protected99.exe` | Observed download path |
| Content-Type | `application/x-msdownload` | HTTP response content type |

---

## 4. Executable Download Infrastructure

| Indicator | Value | Context |
|---|---|---|
| Destination IP | `217.182.138.150` | HTTP server contacted by internal host |
| Domain | `proforma-invoices.com` | HTTP Host header |
| Protocol | HTTP | Executable transfer |

---

## 5. External IP Lookup

| Indicator | Value | Context |
|---|---|---|
| Domain | `bot.whatismyipaddress.com` | Repeated DNS lookup |
| Resolved IP | `66.171.248.178` | IP returned by internal DNS |
| Protocol | DNS | Repeated resolution activity |

---

## 6. External HTTP Connection

| Indicator | Value | Context |
|---|---|---|
| Destination IP | `66.171.248.178` | Host contacted after external-IP lookup |
| Destination port | `80` | HTTP |
| HTTP request | `GET /` | Observed request |
| HTTP response | `200 OK` | Observed response |

---

## 7. SMTP Infrastructure

| Indicator | Value | Context |
|---|---|---|
| SMTP server IP | `23.229.162.69` | SMTP destination |
| SMTP server hostname | `p3plcpnl0413.prod.phx3.secureserver.net` | Server hostname from SMTP greeting |
| Destination port | `587` | SMTP submission |
| Related domain | `macwinlogistics.in` | Queried domain resolved before SMTP connection (earlier notes cited `mail.winlogistics.in`) |
| Protocol | SMTP | Email submission |

---

## 8. SMTP Client Information

| Indicator | Value | Context |
|---|---|---|
| Client hostname | `Beijing-5cd1-PC` | Reported by the SMTP client through EHLO |
| Public IP reported by SMTP server | `173.66.146.112` | Public IP included in SMTP server greeting |

---

## 9. Email Indicators

| Indicator | Value | Context |
|---|---|---|
| Sender | `sales.del@macwinlogistics.in` | Observed SMTP MAIL FROM |
| Recipient | `sales.del@macwinlogistics.in` | Observed SMTP RCPT TO |
| Subject | `HawkEye Keylogger - Reborn v9 - Passwords Logs` | Subject observed in submitted message |
| Authentication | `AUTH LOGIN` | SMTP authentication mechanism |
| Authentication result | `235 Authentication succeeded` | Server response |
| Message acceptance | `250 OK` | SMTP server accepted the submitted message |

Actual authentication credentials and password values observed in the PCAP are intentionally excluded from this IOC list.

---

## 10. Behavioral Indicators

The following behaviors were observed in the PCAP:

1. An internal host downloaded a Windows executable over HTTP.
2. The executable was transferred from an external IP address.
3. The host subsequently performed repeated external-IP lookup queries.
4. The host contacted the resulting external IP over HTTP.
5. The host resolved a mail-related domain.
6. The host established repeated SMTP connections to port 587.
7. SMTP authentication succeeded.
8. Email messages containing HawkEye keylogger/password-log information were submitted.
9. Similar DNS and SMTP activity repeated at approximately regular intervals.

---

## 11. Evidence References

| Evidence | Screenshot |
|---|---|
| HTTP executable download | `screenshots/01_http_executable_download.png` |
| SMTP credential/keylogger exfiltration | `screenshots/02_smtp_exfiltration.png` |
| Repeated SMTP activity | `screenshots/03_repeated_smtp_activity.png` |
| DNS resolution | `screenshots/04_dns_resolution.png` |
| Repeated external-IP lookup | `screenshots/05_post_download_ip_lookup.png` |
| External HTTP connection | `screenshots/06_external_http_connection.png` |
| SMTP server connection | `screenshots/07_smtp_server_connection.png` |
| SMTP authentication | `screenshots/08_smtp_authentication.png` |
| Email submission | `screenshots/09_email_submission.png` |
| SMTP message acceptance | `screenshots/10_smtp_message_accepted.png` |
