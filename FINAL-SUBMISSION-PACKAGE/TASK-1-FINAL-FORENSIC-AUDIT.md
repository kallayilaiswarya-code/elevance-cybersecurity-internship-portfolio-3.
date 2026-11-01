# Task 1 Final Forensic Consistency Audit & Evidence Verification Report

**Document Reference:** ELEV-SOC-TASK1-AUDIT-2026-FINAL
**Workspace:** `Elevance-SOC-Internship-PUBLIC`
**Classification:** TLP:CLEAR / Educational Cybersecurity Portfolio
**Audit Date:** November 1, 2026
**Auditor:** Senior SOC Project Auditor & Cybersecurity Documentation Engineer

---

## Executive Summary

This formal audit report documents the comprehensive forensic verification, hash reconciliation, and timeline validation performed for **Task 1: HawkEye Tri-Team Analysis (Red Team, Blue Team & Purple Team)** within the ElevanceSkills SOC Analyst Internship public repository.

All analyses were executed using offline packet header inspection and byte-level payload dissection directly on the evidentiary packet capture file (`stealer.pcap`) without accessing private folders, modifying git history, or connecting to external systems.

---

## Section A: PCAP Cryptographic Hash Reconciliation

### 1. Hash Calculation & Comparison
The evidentiary packet capture file was hashed directly using Python `hashlib` and PowerShell `Get-FileHash`:

| Metric | Empirical Analysis Result |
|:---|:---|
| **File Name** | `stealer.pcap` |
| **File Size** | `2,454,198` bytes |
| **Total Packet Count** | `4,003` packets |
| **MD5 Checksum** | `6dbd3019a87981cc77dd14c32d7ac3a4` |
| **SHA-256 Checksum** | `22106927c11836d29078dfbec20be9d6b61b1f3f47f95c758acc47a1fb424e51` |

### 2. Discrepancy Resolution
A discrepancy was audited between two candidate SHA-256 hashes previously referenced:
* **Hash A:** `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51`
* **Hash B:** `91547748ca5927515b1ea5c1979b90875bc4da82fb5a38048227b40974b2569f`

**Forensic Finding:**
1. **Hash A (`22106927...`)** is the **true, authentic cryptographic SHA-256 hash** of the 2,454,198-byte `stealer.pcap` file analyzed in this project. It matches the hash recorded across all official repository integrity documents:
   - `HawkEye/cyberdefenders-hawkeye/evidence-integrity.md`
   - `HawkEye/cyberdefenders-hawkeye/hawkeye-lab-report.md`
   - `HawkEye/red-team/red-team-report.md`
2. **Hash B (`91547748...`)** was identified as an **erroneous string hallucinated during assistant conversation output** in an earlier review turn. It does not exist in any file within the public repository, nor does it correspond to any extracted artifact on disk.
3. **Audit Status:** **PASS** (Hash A `22106927...` confirmed as the sole authentic hash).

---

## Section B: Seven-Cycle Timeline & CSV Validation

Every row of the exported dataset [`FINAL-SUBMISSION-PACKAGE/Datasets/hawkeye_verified_seven_cycle_timeline.csv`](file:///C:/Users/aiswarya/Documents/Elevance-SOC-Internship-PUBLIC/FINAL-SUBMISSION-PACKAGE/Datasets/hawkeye_verified_seven_cycle_timeline.csv) was validated packet-by-packet against `stealer.pcap`:

### 1. Verification Matrix Across All 7 Cycles

| Cycle | DNS Query Frame (`bot.whatismyip`) | DNS Response Frame | HTTP Req Frame (`GET /`) | HTTP Resp Frame (`200 OK`) | SMTP First Frame (SYN) | SMTP Last Frame (ACK) | Active SMTP Pkts | Delayed Teardown Frames | Full Session Frame Range | Cycle Timestamp (UTC) | Interval from Prev (s) | Destination Server | Result |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | 3159 | 3160 | 3164 | 3166 | 3172 | 3207 | **36** | 3251–3254 | 3172–3254 | 2019-04-10 20:38:15 | Baseline | `23.229.162.69:587` | **PASS** |
| **2** | 3290 | 3291 | 3295 | 3297 | 3303 | 3338 | **36** | 3341–3344 | 3303–3344 | 2019-04-10 20:48:20 | 604.42 s | `23.229.162.69:587` | **PASS** |
| **3** | 3377 | 3378 | 3382 | 3384 | 3390 | 3425 | **36** | 3428–3431 | 3390–3431 | 2019-04-10 20:58:24 | 604.26 s | `23.229.162.69:587` | **PASS** |
| **4** | 3462 | 3463 | 3467 | 3469 | 3475 | 3510 | **36** | 3513–3516 | 3475–3516 | 2019-04-10 21:08:30 | 605.76 s | `23.229.162.69:587` | **PASS** |
| **5** | 3577 | 3578 | 3582 | 3584 | 3590 | 3625 | **36** | 3626–3629 | 3590–3629 | 2019-04-10 21:18:34 | 604.13 s | `23.229.162.69:587` | **PASS** |
| **6** | 3832 | 3833 | 3837 | 3839 | 3845 | 3880 | **36** | 3884–3887 | 3845–3887 | 2019-04-10 21:28:38 | 604.17 s | `23.229.162.69:587` | **PASS** |
| **7** | 3910 | 3911 | 3915 | 3917 | 3923 | 3958 | **36** | 3979–3982 | 3923–3982 | 2019-04-10 21:38:42 | 604.12 s | `23.229.162.69:587` | **PASS** |

### 2. Validation Findings
* **Active Packet Count:** Exactly **36 packets** per cycle represent the active SMTP dialogue (TCP handshake, EHLO greeting, cleartext Base64 AUTH LOGIN, MAIL FROM, RCPT TO, DATA, and MIME message body transfer).
* **Delayed TCP Teardown:** Exactly **4 packets** per cycle occur ~80–120 seconds after active message completion, performing standard TCP FIN/ACK socket termination. Total packets per connection = 40.
* **Capture Boundary Integrity:** All frame numbers are strictly $\le 4,003$. Cycle 7 active exfiltration completes at **Frame 3958**, and its teardown finishes at **Frame 3982**. The final packet of the capture is **Frame 4003** at elapsed time `3,821.56 s`.

---

## Section C: Evidentiary Taxonomy & Claims Correction

### 1. Corrected Unsupported Claims
Previous drafts contained unverified claims asserting that the PCAP provided definitive proof of:
1. *A deterministic in-memory malware sleep loop.*
2. *Continued active keystroke logging during periods of network inactivity.*
3. *Exact process execution behavior during the ~10-minute silent intervals.*

**Corrective Action Taken:**
All reports were updated with evidence-based, scientifically qualified wording:
* Network telemetry establishes approximately **10-minute intervals (604.12 s to 605.76 s)** between outbound SMTP exfiltration bursts.
* However, a network packet capture records only wire telemetry across network interfaces; **the PCAP alone cannot establish the malware's internal process execution state** (such as a Win32 `Sleep()` API loop, asynchronous timer callback, or Windows Scheduled Task) without host-based memory/event telemetry.
* While the presence of stolen credentials in subsequent email payloads corroborates that data harvesting occurred on the host, the exact hooking mechanism (`SetWindowsHookEx`) during the silent network interval is an inference, not directly observable on the wire.

### 2. Rigorous Tripartite Evidentiary Taxonomy
All technical reports now explicitly bifurcate findings into three tiers:

```
+---------------------------------------------------------------------------------------------------+
|                        TRIPARTITE EVIDENTIARY CLASSIFICATION & INTEGRITY AUDIT                    |
+------------------------------------+--------------------------------+-----------------------------+
| 1. Directly Observed Wire Evidence | 2. Forensic Interpretation     | 3. Unobservable from PCAP   |
|    (Empirical PCAP Ground Truth)   |    (Corroborated by Payload)   |    (Requires Host Telemetry)|
+------------------------------------+--------------------------------+-----------------------------+
| • HTTP GET download of PE binary   | • Malware payload execution    | • Initial phishing email    |
|   tkraw_Protected99.exe (Fr. 207). |   occurred on victim machine   |   delivery lure (capture    |
| • DNS resolution & HTTP IP echo    |   (inferred from subsequent    |   begins at HTTP download). |
|   returning 173.66.146.112.        |   exfiltration telemetry).     | • Process spawn mechanism   |
| • Cleartext Base64 SMTP login to   | • System info & passwords were |   (double-click vs script). |
|   23.229.162.69:587 (Fr. 3172-3207)|   extracted from local browser | • Windows API hook calls    |
| • 7 recurring network cycles at    |   profiles (corroborated by    |   (SetWindowsHookEx) and    |
|   ~604-606s intervals.             |   cleartext Frame 3194 body).  |   RAM keylogger buffer.     |
| • Network traffic during gaps:     | • ~10-minute cadence represents| • Exact internal process    |
|   zero HawkEye C2 (port 587); only |   an automated exfiltration    |   state during gaps:        |
|   internal LAN traffic (SMB/NBNS)  |   schedule rather than human   |   sleep loop vs timer queue |
|   and Google update (Fr. 3268-3289)|   operator activity.           |   vs scheduled task.        |
+------------------------------------+--------------------------------+-----------------------------+
```

### 3. Empirical Inspection of Inter-Cycle Gap Traffic
To verify network activity during the ~600-second intervals between exfiltration cycles, packet filters were executed across all gap intervals:
* **Filter Scope:** Frames 3255–3289 (Gap 1), 3345–3376 (Gap 2), 3432–3461 (Gap 3), 3517–3576 (Gap 4), 3630–3831 (Gap 5), 3888–3909 (Gap 6).
* **C2 Inactivity:** **Zero packets** to port 587, port 25, port 465, or destination IP `23.229.162.69` occurred during any gap interval.
* **Internal LAN Background:** Traffic during gaps consisted of standard Windows LAN operations: SMB keepalives on TCP port 445 between `10.4.10.132` and `10.4.10.4`, NetBIOS Name Service broadcasts (UDP 137), and internal DNS lookups (UDP 53).
* **Workstation Internet Activity:** In Gap 1 (Frames 3268–3289), the workstation conducted a legitimate Google Chrome update check over HTTPS to `update.googleapis.com` (`216.58.193.131:443`). No unauthorized C2 communication took place.

---

## Section D: Cross-Report Consistency & Deliverables

### 1. Parameter Agreement Across All Reports
The following parameters were audited across all Task 1 documents and confirmed 100% consistent:
* **Destination Domain:** `macwinlogistics.in` (Apex domain queried via DNS; earlier notes citing `mail.winlogistics.in` noted as informal shorthand; `mail.gulfstreamins.com` debunked as non-existent in this PCAP).
* **Destination IP & Port:** `23.229.162.69:587`.
* **Transport Security:** 100% unencrypted cleartext SMTP transport (server advertised `250-STARTTLS`, client never negotiated TLS; authentication tokens encoded in RFC 4648 Base64; zero TLS records in capture).
* **Total Capture Volume:** Exactly 4,003 packets.
* **Capture Duration:** 3,821.56 seconds (`01:03:41.56`).
* **Start / End Timestamps:** `2019-04-10 20:37:07 UTC` to `2019-04-10 21:40:48 UTC`.
* **PCAP SHA-256:** `22106927C11836D29078DFBEC20BE9D6B61B1F3F47F95C758ACC47A1FB424E51`.

### 2. Exact Files Modified in this Audit
1. `HawkEye/red-team/red-team-report.md`
2. `HawkEye/blue-team/blue-team-report.md`
3. `HawkEye/purple-team/purple-team-report.md`
4. `Internship-Report.md` (Consolidated Internship Report)
5. `PDF-Reports/Task-1-HawkEye-TriTeam-Report.pdf` (Recompiled & validated)
6. `FINAL-SUBMISSION-PACKAGE/PDF-Reports/Task-1-HawkEye-TriTeam-Report.pdf` (Synchronized deliverable)
7. `FINAL-SUBMISSION-PACKAGE/Datasets/hawkeye_verified_seven_cycle_timeline.csv` (Exported dataset)
8. `HawkEye/notes/hawkeye_verified_seven_cycle_timeline.csv` (Local reference)
9. `FINAL-SUBMISSION-PACKAGE/TASK-1-FINAL-FORENSIC-AUDIT.md` (This official audit record)

---

## Section E: Audit Scorecard & Final Status

| Audit Check Item | Evaluated Metric | Verification Result | Status |
|:---|:---|:---|:---:|
| **Check 1** | PCAP Hash Discrepancy Resolution | Authentic hash verified as `22106927...`; hallucinated `91547748...` purged | **PASS** |
| **Check 2** | Seven-Cycle Frame Verification | All DNS, HTTP, and SMTP frames verified $\le 4,003$ | **PASS** |
| **Check 3** | Active Packet Count per Cycle | Verified exactly 36 active SMTP packets per cycle across all 7 cycles | **PASS** |
| **Check 4** | Delayed Teardown Disambiguation | Separated 4 teardown packets (40 total) from 36 active message packets | **PASS** |
| **Check 5** | Destination Server & Port | Verified strictly `23.229.162.69:587` (`macwinlogistics.in`) | **PASS** |
| **Check 6** | Encryption Status Dissection | Verified unencrypted cleartext transport; Base64 encoding; 0 TLS records | **PASS** |
| **Check 7** | Inter-Cycle Gap Telemetry Audit | Verified 0 C2 packets during gaps; documented LAN & Google update frames | **PASS** |
| **Check 8** | Evidentiary Qualification | Replaced unsupported sleep loop claims with tripartite evidentiary tiers | **PASS** |
| **Check 9** | Cross-Report Parameter Agreement | Red, Blue, Purple, and Consolidated Reports in 100% alignment | **PASS** |
| **Check 10**| PDF Deliverable Integrity | Regenerated `Task-1-HawkEye-TriTeam-Report.pdf` (860,920 bytes) valid & synchronized | **PASS** |

**OVERALL AUDIT OUTCOME:** **PASS** (Zero unresolved discrepancies; 100% compliant with empirical evidence).
