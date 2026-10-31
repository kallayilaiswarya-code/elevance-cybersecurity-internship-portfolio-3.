# Evidence Integrity Verification

## Verification Date
2026-10-30

## Verified Artifacts

### Core Investigation Evidence

| Artifact | Size (Bytes) | Algorithm | Verified Hash | Description |
|:---|:---|:---|:---|:---|
| `stealer.pcap` | 2,454,198 | SHA-256 | `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51` | Primary network packet capture |
| `stealer.pcap` | 2,454,198 | MD5 | `6DBD3019A87981CC77DD14C32D7AC3A4` | Primary network packet capture |
| `tkraw_Protected99.exe` | 2,025,472 | SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` | Extracted HawkEye keylogger executable |
| `tkraw_Protected99.exe` | 2,025,472 | MD5 | `71826BA081E303866CE2A2534491A2F7` | Extracted HawkEye keylogger executable |

### Verified Screenshots (`HawkEye\screenshots\` & `HawkEye\cyberdefenders-hawkeye\screenshots\`)

All 10 screenshot files have been verified as valid 1366×768 PNG images with unique cryptographic hashes, confirmed identical across both repository directories:

| Screenshot File Name | Size (Bytes) | Resolution | SHA-256 Hash |
|:---|:---:|:---:|:---|
| `01_http_executable_download.png` | 143,155 | 1366×768 | `6BC375525EAE4B62D92E4D28D7F4294721453FA9A0003F6718B925832FE7EA60` |
| `02_smtp_exfiltration.png` | 192,472 | 1366×768 | `3A083448126325871B58F2DC42998497AB2E1595764606076F104DBDF042A7F2` |
| `03_repeated_smtp_activity.png` | 206,311 | 1366×768 | `B5380C7BAB04DB97C987AB14A4F3A2AE4DFA4180AE33B0388E44B08F3837460E` |
| `04_dns_resolution.png` | 194,572 | 1366×768 | `3B7852BA59FEFB3F7CF998767B4E96C4D4EBFF34805E2F5556F33F8AC9848034` |
| `05_post_download_ip_lookup.png` | 153,624 | 1366×768 | `EA4E1CEDBCD4C28545FB4D928E5C8AF46A606C99EFD892FF625F4285D83D137A` |
| `06_external_http_connection.png` | 185,596 | 1366×768 | `C21665795EC82C11E72502AE98DF62FB70D8D239B08589FC5C804CE0E6331D80` |
| `07_smtp_server_connection.png` | 186,784 | 1366×768 | `3A40C5C41C19471743CF301ABF695143404C6DA7F1DB0C54E8F5C2F7F92F9738` |
| `08_smtp_authentication.png` | 120,092 | 1366×768 | `53B35AA1D7F18C95D50376E559D59F928B6629FAAE6699E16C3393C8D22B726B` |
| `09_email_submission.png` | 134,853 | 1366×768 | `A0D597FA2AB43249446DBA987A090048B2E3F093337F5AD0F2912ED405CBA397` |
| `10_smtp_message_accepted.png` | 182,718 | 1366×768 | `1511136466309E3FC82CAEAAF3138BCA0C9C0A2913F10F58FA6EF92DAF704A4D` |

## Result
The calculated hashes confirm the integrity of the evidence files and corroborate that the local screenshot artifacts are genuine, high-resolution Wireshark captures matching the documented evidence.

## Verification Method
Hashes were independently calculated using PowerShell `Get-FileHash` and verified via Python `hashlib.sha256()` directly against the files stored in the project directories. PNG headers were validated for 8-byte magic numbers (`\x89PNG\r\n\x1a\n`) and dimension chunks (`IHDR`).
