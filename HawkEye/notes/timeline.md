# HawkEye Investigation Timeline

## Evidence

**PCAP:** `stealer.pcap`

**Primary internal host:** `10.4.10.132`

**Internal DNS server:** `10.4.10.4`

---

## Timeline

| Time (seconds) | Source | Destination | Protocol | Observed Activity |
|---:|---|---|---|---|
| 47.391827 | 10.4.10.132 | 10.4.10.255 | NBNS | Local name-resolution activity |
| 47.447289 | 10.4.10.132 | 10.4.10.4 | DNS | DNS activity resolving `proforma-invoices.com` |
| 47.459211 | 10.4.10.132 | 217.182.138.150 | TCP/80 | TCP connection initiated |
| 47.597546 | 10.4.10.132 | 217.182.138.150 | HTTP | GET request for `tkraw_Protected99.exe` |
| 47.609069 | 217.182.138.150 | 10.4.10.132 | HTTP | HTTP response begins |
| 47.734506+ | 217.182.138.150 | 10.4.10.132 | TCP | Large HTTP response segments transfer executable |
| 48.947474 | 217.182.138.150 | 10.4.10.132 | HTTP | HTTP 200 OK |
| 49.008850 | 10.4.10.132 | 217.182.138.150 | TCP | TCP RST, ACK |
| 68.542554 | 10.4.10.132 | 10.4.10.4 | DNS | Query for `bot.whatismyipaddress.com` |
| 68.576418 | 10.4.10.4 | 10.4.10.132 | DNS | Response: `66.171.248.178` |
| 68.591965 | 10.4.10.132 | 66.171.248.178 | TCP/80 | HTTP connection |
| 68.640169 | 10.4.10.132 | 66.171.248.178 | HTTP | GET `/` |
| 68.691423 | 66.171.248.178 | 10.4.10.132 | HTTP | HTTP 200 OK |
| 68.702274 | 10.4.10.132 | 10.4.10.4 | DNS | Query for `macwinlogistics.in` (earlier notes cited `mail.winlogistics.in`) |
| 68.783223 | 10.4.10.4 | 10.4.10.132 | DNS | Response: `23.229.162.69` |
| 68.784554 | 10.4.10.132 | 23.229.162.69 | TCP/587 | SMTP connection initiated |
| 69.160215 | 23.229.162.69 | 10.4.10.132 | SMTP | SMTP server greeting |
| 69.160551+ | 10.4.10.132 | 23.229.162.69 | SMTP | SMTP authentication and message submission |
| ~69+ | 23.229.162.69 | 10.4.10.132 | SMTP | `250 OK` message acceptance observed |

---

## Repeated Activity

The following repeated DNS lookups for `bot.whatismyipaddress.com` were observed:

| Approx. Time | Resolved IP |
|---:|---|
| 68.542554 | `66.171.248.178` |
| 672.924931 | `66.171.248.178` |
| 1277.235858 | `66.171.248.178` |
| 1883.011320 | `66.171.248.178` |
| 2487.117820 | `66.171.248.178` |
| 3091.283069 | `66.171.248.178` |
| 3695.428257 | `66.171.248.178` |

Repeated SMTP authentication and email-submission activity was also observed at approximately:

- 69 seconds
- 673 seconds
- 1277 seconds
- 1883 seconds
- 2487 seconds
- 3091 seconds
- 3695 seconds

---

## Timeline Interpretation

The observed sequence begins with DNS activity associated with `proforma-invoices.com`, followed by an HTTP connection and download of `tkraw_Protected99.exe`.

Shortly afterward, the internal host performed an external-IP lookup and contacted the resulting IP address over HTTP.

The host then resolved `macwinlogistics.in` (earlier notes cited `mail.winlogistics.in`), established an SMTP connection to `23.229.162.69` on port 587, authenticated successfully via cleartext Base64, and submitted an email containing HawkEye keylogger/password-log information.

Similar DNS lookup and SMTP submission activity was observed repeatedly throughout the capture.
