# Indicators of Compromise (IOCs)

## Files

| Artifact | Size (Bytes) | MD5 | SHA-256 | Description |
|---|---|---|---|---|
| `stealer.pcap` | 2,454,198 | `6DBD3019A87981CC77DD14C32D7AC3A4` | `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51` | Primary network packet capture |
| `tkraw_Protected99.exe` | 2,025,472 | `71826BA081E303866CE2A2534491A2F7` | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` | Extracted malicious executable |

## Network Indicators

| Type | Indicator | Context |
|---|---|---|
| Internal Host | `10.4.10.132` | Compromised victim workstation (`Beijing-5cd1-PC`) |
| DNS Server | `10.4.10.4` | Internal organization DNS resolver |
| External IP | `217.182.138.150` | Malicious HTTP server hosting executable (France, OVH) |
| External IP | `66.171.248.178` | External IP lookup web server (`bot.whatismyipaddress.com`) |
| Public IP (Victim) | `173.66.146.112` | Public IP of victim system (returned in HTTP response payload and logged in SMTP EHLO banner) |
| SMTP Server IP | `23.229.162.69` | Destination SMTP mail server for exfiltration (United States, GoDaddy) |
| Domain | `proforma-invoices.com` | Staging domain associated with malware download |
| Domain | `bot.whatismyipaddress.com` | External IP lookup service queried before each exfiltration cycle |
| Domain | `mail.winlogistics.in` | SMTP server domain / reverse DNS hostname |

## Malware / Binary Indicators

- **Filename:** `tkraw_Protected99.exe`
- **File Size:** 2,025,472 bytes
- **Web Server Software:** LiteSpeed (hosted at `217.182.138.150:80`)
- **Malware Variant:** HawkEye Keylogger - Reborn v9
- **MD5 Checksum:** `71826BA081E303866CE2A2534491A2F7`
- **SHA-256 Checksum:** `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11`

## Email & Exfiltration Indicators

- **SMTP Destination Port:** 587 (Submission)
- **SMTP Server Software:** Exim 4.91
- **Sender / Recipient Account:** `sales.del@macwinlogistics.in`
- **Authentication Method:** `AUTH LOGIN` (Base64 encoded)
- **Exfiltration Cadence:** Deterministic ~10-minute interval (~604–606 seconds)

> Note: Sensitive credential values observed in lab traffic are intentionally excluded from general IOC tables to maintain security best practices.
