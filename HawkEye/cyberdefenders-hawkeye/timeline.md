# HawkEye Investigation Timeline

> Timestamps below use capture-relative elapsed time from `stealer.pcap`. The initial packet was captured at approximately **2019-04-10 20:37:07 UTC**.

| Capture-Relative Time | Frame / Packet # | Protocol | Event Description | Evidentiary Basis |
|---:|:---:|:---:|---|---|
| ~0.0 s | Frame 1 | PCAP | Capture commences | `stealer.pcap` initial packet |
| ~47.6 s | Frame 204 | DNS | DNS standard query for `proforma-invoices.com` from `10.4.10.132` to DNS server `10.4.10.4` | DNS query record |
| ~47.6 s | Frame 206 | DNS | DNS response resolving `proforma-invoices.com` to `217.182.138.150` (France) | DNS A record |
| ~47.6 s | Frames 207–209 | TCP | Three-way TCP handshake between `10.4.10.132` and `217.182.138.150:80` | TCP SYN / SYN-ACK / ACK |
| ~47.6 s | Frame 210 | HTTP | Internal host `10.4.10.132` sends HTTP `GET /proforma/tkraw_Protected99.exe` | HTTP request |
| ~48.9 s | Frame 212 | HTTP | Web server returns `HTTP/1.1 200 OK` (Server: LiteSpeed); executable stream begins (Frames 213–3155, 2,025,472 bytes) | HTTP response |
| ~68.5 s | Frame 3159 | DNS | Host `10.4.10.132` performs DNS query for `bot.whatismyipaddress.com` | DNS query |
| ~68.6 s | Frame 3160 | DNS | DNS response resolves `bot.whatismyipaddress.com` to external service IP `66.171.248.178` | DNS A record |
| ~68.6 s | Frame 3164 | HTTP | Host `10.4.10.132` sends HTTP `GET /` to `bot.whatismyipaddress.com` (`66.171.248.178:80`) | HTTP request |
| ~68.7 s | Frame 3167 | HTTP | Service returns `HTTP/1.1 200 OK` containing victim public IP **`173.66.146.112`** in HTTP response body | HTTP payload |
| ~68.8 s | Frames 3168–3170 | TCP | Host `10.4.10.132` initiates TCP three-way handshake to SMTP server `23.229.162.69:587` | TCP handshake |
| ~68.8 s | Frame 3173 | SMTP | SMTP server banner: `220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91` | SMTP 220 banner |
| ~68.8 s | Frame 3174 | SMTP | Client sends `EHLO Beijing-5cd1-PC`; server acknowledges with `Hello Beijing-5cd1-PC [173.66.146.112]` | SMTP EHLO response |
| ~68.9 s | Frame 3180 | SMTP | Client submits base64-encoded username `sales.del@macwinlogistics.in` via `AUTH LOGIN` | SMTP authentication |
| ~69.1 s | Frame 3182 | SMTP | Client submits base64-encoded password `[REDACTED_LAB_PASSWORD]` | SMTP authentication |
| ~69.2 s | Frame 3184 | SMTP | Server responds: `235 Authentication succeeded` | SMTP 235 response |
| ~69.4 s | Frames 3185, 3188 | SMTP | Client issues `MAIL FROM:<sales.del@macwinlogistics.in>` and `RCPT TO:<sales.del@macwinlogistics.in>` | SMTP envelope |
| ~69.5 s | Frame 3191 | SMTP | Client issues `DATA` command to initiate payload transmission | SMTP command |
| ~69.6 s | Frame 3194 | SMTP | Exfiltrated email body transmitted: Subject `HawkEye Keylogger - Reborn v9`, system info, and Bank of America credentials | Keylogger payload |
| ~69.7 s | Frame 3206 | SMTP | Server responds: `250 OK id=... Message accepted for delivery` | Delivery confirmation |
| ~672.9 s | Frames 3290–3339 | DNS/SMTP | **Cycle 2:** External IP lookup and recurring SMTP data submission (~604 s interval) | Recurring exfiltration |
| ~1277.2 s | Frames 3377–3426 | DNS/SMTP | **Cycle 3:** External IP lookup and recurring SMTP data submission (~604 s interval) | Recurring exfiltration |
| ~1883.0 s | Frames 3462–3511 | DNS/SMTP | **Cycle 4:** External IP lookup and recurring SMTP data submission (~606 s interval) | Recurring exfiltration |
| ~2487.1 s | Frames 3577–3626 | DNS/SMTP | **Cycle 5:** External IP lookup and recurring SMTP data submission (~604 s interval) | Recurring exfiltration |
| ~3091.3 s | Frames 3832–3881 | DNS/SMTP | **Cycle 6:** External IP lookup and recurring SMTP data submission (~604 s interval) | Recurring exfiltration |
| ~3695.4 s | Frames 3910–3959 | DNS/SMTP | **Cycle 7:** External IP lookup and recurring SMTP data submission (~604 s interval) | Recurring exfiltration |
| ~3821.5 s | Frame 4003 | PCAP | Capture completes (total duration: 1 hour, 3 minutes, 41 seconds) | `stealer.pcap` end |

## Key Timeline Findings

1. **Deterministic Exfiltration Cadence:** The malware executes recurring exfiltration cycles at approximately **604–606 second intervals** (~10 minutes).
2. **Two-Stage Beacon Sequence:** Each cycle strictly begins with an external IP lookup via `bot.whatismyipaddress.com` (Frames 3159–3167) before establishing the authenticated SMTP transmission on port 587 (Frames 3168–3206).
3. **Public IP Distinction:** DNS resolves `bot.whatismyipaddress.com` to **`66.171.248.178`** (the external lookup server). The HTTP payload returned by this service conveys **`173.66.146.112`**, which is the victim workstation's public gateway IP (corroborated in the SMTP server's EHLO response).

## Investigation Scope
This timeline records observable network events preserved in `stealer.pcap`. Initial-access delivery vectors prior to the HTTP download and local host endpoint telemetry are outside the capture scope.
