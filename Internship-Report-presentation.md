# ElevanceSkills Cybersecurity Internship — Consolidated Final Report
## Security Operations Center (SOC) Engineering, Threat Analysis & Incident Response

**Student Name:** Aiswarya  
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science  
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala  
**Affiliated University:** APJ Abdul Kalam Technological University  
**Internship Organization:** ElevanceSkills  
**Project Repository:** `local internship project folder\`  
**Date of Submission:** 2026-10-30  
**Classification:** TLP:CLEAR / Academic Cybersecurity Internship Report  

---

> [!IMPORTANT]
> **ACADEMIC INTERNSHIP & EVIDENTIARY TRANSPARENCY NOTICE:**
> This consolidated report documents the technical activities, methodologies, and engineering deliverables developed during the ElevanceSkills SOC Internship.
> - All analytical tasks were performed on a resource-constrained host (Windows 11, 7.67 GB RAM). In accordance with strict SOC integrity standards, heavy enterprise clusters (live multi-node ELK, Security Onion, live TheHive daemons) were **not** run as resident production services.
> - High-fidelity enterprise compatibility was engineered through standardized offline specifications (Kibana 8.x NDJSON, MISP RFC JSON, Sigma rules, ElastAlert 2, TheHive templates) verified via lightweight Python evaluation harnesses (`< 30 MB RAM`).
> - Synthetic training datasets (Tasks 2, 3, and parts of 6) are strictly distinguished from genuine lab challenge forensics (Tasks 1, 4, 5, and HawkEye/Brutus subsets of Task 6).

---

## 1. Introduction

The modern enterprise threat landscape is defined by increasingly sophisticated adversary tradecraft. Threat actors execute stealthy, multi-stage attacks that span initial credential brute-forcing, living-off-the-land (LotL) execution, local account persistence, and covert application-layer data exfiltration. To effectively defend against such intrusions, modern Security Operations Centers (SOCs) require cross-disciplinary analysts capable of bridging offensive threat emulation, automated log correlation, deep network packet inspection, host-level kernel forensics, and interactive telemetry visualization.

This consolidated report documents the technical activities, methodologies, competencies, and engineering outcomes developed during the **ElevanceSkills Cybersecurity SOC Internship**. The program focused on six comprehensive, hands-on tasks simulating enterprise SOC environments and real-world intrusion investigations:

1. **Adversary Emulation & Tri-Team Operations:** HawkEye Red, Blue, and Purple Team Analysis.
2. **Detection Engineering:** Custom SIEM Correlation Rules for Credential Stuffing, DNS Tunneling, and PowerShell Exploitation.
3. **Advanced Threat Response:** Multi-Stage APT Simulation, Forensic Investigation, TheHive 5 Case Management, and MISP Threat Sharing.
4. **Network Forensics:** Deep Packet Inspection of the CyberDefenders HawkEye Keylogger Intrusion (24/24 questions solved).
5. **Host-Level Linux Forensics:** Hack The Box Sherlock "Brutus" SSH Brute-Force & Persistence Investigation (8/8 questions solved).
6. **SOC Engineering & Telemetry Visualization:** Custom 3-Pillar SIEM Dashboard, Elastic Common Schema (ECS) Data Normalization, and Kibana NDJSON Specification.

Through these rigorous investigations, theoretical knowledge from computer science and cybersecurity coursework was directly applied to resolve complex defensive challenges.

---

## 2. Background

### 2.1 The Defensive Mandate of the Modern SOC

A modern Security Operations Center operates on the principle of continuous visibility and assumed breach. Attackers rarely execute single-stage exploits; instead, they navigate the Cyber Kill Chain and MITRE ATT&CK lifecycles. Effective detection requires telemetry ingestion across disparate enterprise data sources—including network taps, endpoint audit daemons, web proxies, and authentication servers.

### 2.2 Academic Coursework Integration

The technical tasks undertaken during this internship directly operationalized foundational computer science disciplines:

| Course Discipline | Applied SOC & Engineering Concepts in Internship |
|:---|:---|
| **Computer Networks** | • TCP three-way handshakes, sequence numbers, and packet reassembly.<br>• DNS request/response architectures and covert tunneling via TXT/A queries.<br>• SMTP client-server state machines (`EHLO`, `AUTH`, `MAIL`, `RCPT`, `DATA`) on port 587. |
| **Operating Systems** | • Linux PAM (Pluggable Authentication Modules) logging in `/var/log/auth.log`.<br>• Low-level C binary `struct utmp` unpacking from `/var/log/wtmp`.<br>• Windows PE binary structures, process tokens (`SeDebugPrivilege`), and systemd session scopes. |
| **Data Science & AI** | • Shannon entropy calculation for algorithmic detection of encoded payloads.<br>• Statistical threshold aggregation for distributed credential stuffing.<br>• Data normalization to Elastic Common Schema (ECS) across 79 security events. |
| **Cybersecurity & IR** | • NIST SP 800-61 incident response lifecycle (Containment, Eradication, Recovery).<br>• MITRE ATT&CK Enterprise Matrix mapping across all adversary TTPs.<br>• Sigma rule engineering, Lucene query optimization, and threat intelligence sharing. |

---

## 3. Learning Objectives

The internship was structured around five core educational and technical objectives:

1. **Master Tri-Team Collaboration:** Understand how offensive tactics (Red Team) inform detection rules (Blue Team) and how joint exercises (Purple Team) identify and remediate enterprise visibility blind spots.
2. **Develop Enterprise Detection Engineering Skills:** Author high-fidelity SIEM correlation rules using Sigma and Elastic DSL, minimizing false positives while detecting stealthy anomalous behaviors.
3. **Execute Structured Incident Response:** Follow formal incident handling frameworks (NIST SP 800-61) to document timelines, calculate evidence hashes, isolate threats, and generate MISP/TheHive artifacts.
4. **Acquire Low-Level Forensic Proficiency:** Perform root-cause forensic investigations on raw network packet captures (PCAP) and host binary databases (wtmp), correctly handling UTC timestamp normalization and session tracking.
5. **Architect Resource-Efficient SOC Telemetry Systems:** Design and verify an interactive SIEM dashboard capable of visualizing high-priority threat categories under strict hardware constraints without relying on resource-intensive enterprise infrastructure.

---

## 4. Activities and Tasks

| Task Identifier | Technical Focus Area | Core Methods & Telemetry Sources | Interactive Viewer Link |
|:---|:---|:---|:---:|
| **Task 1** | Tri-Team Operations & Keylogger Analysis | Attack simulation, Blue Team detection mapping, Purple Team remediation | [View Task 1 Report](report.html?report=task-1) |
| **Task 2** | Custom SIEM Correlation Rules | Credential Stuffing, DNS Tunneling, PowerShell abuse (Sigma / Elastic DSL) | [View Task 2 Report](report.html?report=task-2) |
| **Task 3** | Multi-Stage APT Incident Response | NIST SP 800-61 lifecycle, TheHive 5 case templates, MISP candidate JSON | [View Task 3 Report](report.html?report=task-3) |
| **Task 4** | CyberDefenders HawkEye Network Forensics | Deep packet inspection (4,003 pkts), PE carving, 7-cycle SMTP beaconing (24/24) | [View Task 4 Report](report.html?report=task-4) |
| **Task 5** | HTB Sherlock "Brutus" Host Forensics | Linux `auth.log` and binary `wtmp` analysis, root compromise, backdoor user (8/8) | [View Task 5 Report](report.html?report=task-5) |
| **Task 6** | Custom 3-Pillar SIEM Dashboard | Multi-pillar threat visualization, 79 ECS events, Kibana NDJSON, Python engine | [View Task 6 Report](report.html?report=task-6) |

### 4.1 Task 1: HawkEye Red Team, Blue Team, and Purple Team Analysis
- **Objective:** Evaluate the complete intrusion lifecycle of the HawkEye keylogger through offensive, defensive, and collaborative perspectives.
- **Red Team Analysis:** Deconstructed the attack chain: phishing delivery $\rightarrow$ HTTP payload staging (`/proforma/tkraw_Protected99.exe`) $\rightarrow$ public IP discovery $\rightarrow$ local keystroke logging $\rightarrow$ automated cleartext Base64 SMTP data exfiltration to external mail infrastructure `23.229.162.69:587` (`macwinlogistics.in`).
- **Blue Team Analysis:** Mapped defensive detection controls across network, host, and email boundaries. Identified detection gaps in legacy anti-malware and uninspected egress traffic.
- **Purple Team Handover:** Formulated an integrated detection improvement plan, recommending Snort/Suricata network signatures, Sysmon host auditing (`Event ID 1`, `3`), and host firewall rules.
- **Detailed Documentation:** [HawkEye Purple Team Presentation Report](report.html?report=task-1)

### 4.2 Task 2: Custom SIEM Correlation Rules
- **Objective:** Design, implement, and validate production-ready SIEM correlation rules detecting three widespread cyberattack techniques.
- **Attack 1 (Credential Stuffing - T1110.004):** Implemented an aggregation rule triggering an alert when an external source IP generates $\ge 10$ failed authentication events (`event.outcome: failure`) followed by a successful login within a 5-minute sliding window.
- **Attack 2 (DNS Tunneling - T1071.004):** Developed statistical anomaly detection targeting unusually high query frequency, excessive subdomain length ($> 30$ characters), and elevated Shannon entropy indicative of base32/base64 encoded exfiltration payloads.
- **Attack 3 (PowerShell Exploitation - T1059.001):** Engineered a regex-based pattern matching rule detecting suspicious CLI execution flags (`-EncodedCommand`, `-W Hidden`, `-NoP`, `DownloadString`, `IEX`) in Windows Event ID 4688 and PowerShell script block logging (Event ID 4104).
- **Deliverables:** Production rule definitions formatted in official Sigma, Elastic Lucene queries, and ElastAlert configurations.
- **Detailed Documentation:** [SIEM Correlation Rules Presentation Report](report.html?report=task-2)

### 4.3 Task 3: Multi-Stage APT Attack Simulation & Incident Response
- **Objective:** Conduct a complete incident response lifecycle following NIST SP 800-61 guidelines against an advanced persistent threat (APT) campaign.
- **Incident Investigation:** Traced adversary activity across initial spear-phishing, credential dumping, lateral movement, persistence, and automated exfiltration.
- **Evidence Management & Indexing:** Compiled a cryptographic evidence index securing raw hashes and chain-of-custody records.
- **SIEM Demonstrator & Test Harness:** Engineered an offline Python SIEM detection script (`siem/siem_detector.py`) executing correlation logic that triggered seven high-fidelity alerts against normalized simulated APT telemetry.
- **TheHive & MISP Integration:** Authored production-standard candidate objects: an official TheHive 5 case template (`thehive/thehive_case_template.json`) containing task-based response workflows, and an RFC-compliant MISP threat sharing candidate event (`misp/misp_event_candidate.json`) with populated IOC attributes.
- **Detailed Documentation:** [APT Incident Response Presentation Report](report.html?report=task-3)

### 4.4 Task 4: CyberDefenders HawkEye Network Forensics
- **Objective:** Solve all 24 questions of the CyberDefenders HawkEye challenge by performing forensic packet analysis on `stealer.pcap`.
- **Packet Analysis & Evidence Extraction:** Inspected 4,003 packets in Wireshark. Carved the malicious executable `tkraw_Protected99.exe` (2,025,472 bytes) from HTTP TCP stream reassembly and validated its MD5 (`71826BA0...`) and SHA-256 (`62099532...`) hashes.
- **Reconnaissance & Egress Disambiguation:** Dissected the automated reconnaissance routine: resolved DNS query for `bot.whatismyipaddress.com` to `66.171.248.178`, which returned the victim's external public IP **`173.66.146.112`** in the HTTP response payload. Corroborated this IP in the subsequent SMTP server EHLO response.
- **Exfiltration Cadence:** Mapped all 7 recurring exfiltration cycles on the network, documenting recurring ~10-minute intervals (604–606 seconds) between outbound bursts, while distinguishing wire observations from unobservable internal host process states.
- **Screenshot Verification:** Captured and cryptographically verified 10 genuine Wireshark screenshots (1366×768 resolution), embedding them directly into the report narrative with specific frame numbers.
- **Detailed Documentation:** [CyberDefenders HawkEye Presentation Report](report.html?report=task-4)

### 4.5 Task 5: Hack The Box Sherlock "Brutus" Linux Host Forensics
- **Objective:** Perform forensic log analysis on a compromised Linux server to investigate an SSH brute-force attack and solve all 8 HTB Sherlock questions.
- **Brute-Force Dissection:** Analyzed `auth.log` (385 lines) to identify threat actor IP `65.2.161.68` executing 48 rapid failed authentication attempts across 5 user accounts (`server_adm`, `svc_account`, `admin`, `backup`, `root`), distinguishing it from legitimate administrator IP `203.101.190.9`.
- **Root Compromise & Session Lifecycle:** Located the successful authentication event for user `root` at `06:32:44 UTC`, triggering `systemd-logind` interactive Session `37`.
- **Binary `wtmp` Analysis & Timezone Resolution:** Resolved a 5.5-hour divergence caused by local workstation time (IST) in `utmp.py` by converting raw UNIX epoch seconds (`1709706765`) to UTC via `gmtime()`, confirming the exact wtmp login timestamp of `2024-03-06 06:32:45 UTC`.
- **Persistence & Privilege Escalation:** Traced the creation of backdoor user `cyberjunkie` (T1136.001), password assignment, and addition to group `sudo` (T1548.003). Documented Session 37 termination at `06:37:24 UTC` and subsequent login as `cyberjunkie` to execute `sudo /usr/bin/curl ... linper.sh` (T1059.004).
- **Detailed Documentation:** [HTB Brutus Lab Presentation Report](report.html?report=task-5)

### 4.6 Task 6: Custom SIEM Dashboard
- **Objective:** Design, build, and verify a custom SIEM dashboard visualizing three core attack vectors under strict physical workstation memory constraints.
- **Three Visualization Pillars:**
  1. *Brute-Force Attacks:* Visualizing failed vs. successful logins, attacker IPs (`65.2.161.68`), and targeted accounts.
  2. *Privilege Escalation:* Tracking unauthorized account creations (`cyberjunkie`), sudo group additions, and admin token grants.
  3. *Data Exfiltration Attempts:* Monitoring DNS tunneling byte anomalies and recurring SMTP exfiltration traffic.
- **Dataset Engineering:** Normalized **79 security events** into standard Elastic Common Schema (ECS) format (`data/siem_dashboard_events.jsonl`), combining synthetic training events from Tasks 2/3 with real lab forensic data from Tasks 4/5.
- **Dual-Mode Architecture:**
  - *Enterprise Mode:* Exported standard Kibana 8.x NDJSON (`kibana/kibana_dashboard.ndjson`) containing Lens visualizations, Data Views, and dashboard containers.
  - *Local Mode:* Engineered a zero-dependency Python backend (`backend/dashboard_server.py`) serving an interactive dark-mode SOC dashboard (`frontend/index.html`) using dynamic Chart.js graphing and live KPI metrics computed from raw event objects.
- **Verification:** Automated test suite `verify_dashboard.py` passed 5/5 checks; 5 automated headless browser screenshots were captured and archived.
- **Detailed Documentation:** [Custom SIEM Dashboard Presentation Report](report.html?report=task-6)

---

## 5. Skills and Competencies Developed

| Competency Domain | Specific Skills Demonstrated in Program |
|:---|:---|
| **Threat Hunting & SIEM** | • Sigma rule drafting and Elastic Query DSL optimization.<br>• Threshold, sequence, and statistical aggregation detection logic.<br>• Elastic Common Schema (ECS) normalization across multi-source logs. |
| **Network Security** | • Packet slicing, TCP stream reassembly, and payload carving.<br>• Network protocol analysis across DNS, HTTP, SMTP, and SSH.<br>• Automated beaconing detection and inter-arrival time calculation. |
| **Host & System Forensics** | • Linux PAM syslog parsing and systemd-logind session tracking.<br>• Low-level C `struct utmp` binary parsing from `/var/log/wtmp`.<br>• Multi-jurisdictional timestamp normalization to UTC. |
| **Incident Response & SOAR** | • NIST SP 800-61 playbook creation and evidence chain-of-custody.<br>• Threat intelligence formatting using MISP candidate event schemas.<br>• Case template engineering for TheHive 5 SOAR automation. |
| **Software & Systems Eng.** | • Lightweight Python web servers (`http.server`, `urllib`, `json`).<br>• Modern frontend engineering (HTML5, responsive CSS dark mode, CDN).<br>• PowerShell automation for cryptographic hashing and evidence audits. |

---

## 6. Feedback and Evidence

### 6.1 Mentor Guidance & Academic Review

Throughout the internship, investigative approaches and technical deliverables were systematically reviewed and validated:
- **Evidentiary Rigor:** Mentorship emphasized that all forensic claims must be anchored in empirical evidence (exact packet frame numbers, byte offsets, and syslog line numbers) rather than high-level assumptions.
- **Honest Architectural Disclosure:** Guidance reinforced the requirement to clearly disclose local hardware boundaries and avoid asserting that live enterprise clusters (e.g., live ELK or Security Onion) were deployed when offline verification harnesses were used.
- **Data Provenance:** Guidance mandated explicit labeling of synthetic training datasets versus genuine captured artifacts.

### 6.2 Evidentiary Artifacts Summary

| Category | Primary Artifact Path | Verification Method | Status |
|:---|:---|:---|:---:|
| **Network Evidence** | `HawkEye\evidence\stealer.pcap` | SHA-256 Hash Recalculation | **VERIFIED** |
| **Malicious Binary** | `HawkEye\evidence\tkraw_Protected99.exe` | MD5 & SHA-256 Hash Corroboration | **VERIFIED** |
| **Linux Auth Log** | `Brutus\auth.log` | Line-by-line Syslog Analysis | **VERIFIED** |
| **Linux Login DB** | `Brutus\wtmp` | Binary `struct utmp` C Unpacking | **VERIFIED** |
| **HTB Sherlock Proof**| `Brutus\Evidence\HTB-Brutus-All-8-Tasks-Completed.png.png` | Screenshot & Hash Verification | **VERIFIED** |
| **Network Screenshots**| `HawkEye\screenshots\` (01 to 10) | Unique SHA-256 & 1366×768 PNG Header Check | **VERIFIED** |
| **SIEM Telemetry** | `SIEM-Dashboard\data\siem_dashboard_events.jsonl` | 79 ECS Records JSONL Validation | **VERIFIED** |
| **Kibana Export** | `SIEM-Dashboard\kibana\kibana_dashboard.ndjson` | Official NDJSON Schema Syntax Check | **VERIFIED** |
| **Dashboard Proof** | `SIEM-Dashboard\evidence\` (5 Screenshots) | Headless Browser Automation Capture | **VERIFIED** |

---

## 7. Challenges and Solutions

### 7.1 Challenge: Hardware Resource Constraints vs. Enterprise SIEM Requirements
- **Problem:** Enterprise SIEM suites (Elasticsearch, Logstash, Kibana, Security Onion) require 16–32 GB of physical RAM. The host system possessed 7.67 GB total RAM with ~2.5 GB available, making live VM or container deployment prone to OS instability and out-of-memory (OOM) crashes.
- **Solution:** Engineered a **Dual-Mode Zero-Overhead SOC Architecture**. For enterprise compatibility, an official Kibana 8.x NDJSON export was authored. For local verification and interactive review, a lightweight (`< 30 MB RAM`), zero-dependency Python backend was built to serve a dark-mode web console with Chart.js visualization.

### 7.2 Challenge: Workstation Timezone Offset in Binary Forensic Parsing
- **Problem:** When parsing Linux `/var/log/wtmp` using `utmp.py`, Python's `time.localtime()` converted raw epoch seconds to Indian Standard Time (IST, UTC+5:30), displaying `12:02:45` instead of the true event time, causing an apparent discrepancy with syslog timestamps.
- **Solution:** Re-engineered the timestamp extraction logic to use `time.gmtime()`, calculating the direct Coordinated Universal Time (UTC) equivalent (`2024-03-06 06:32:45 UTC`). This synchronized the binary database perfectly with `auth.log` line 322.

### 7.3 Challenge: Public IP Conflation During Reconnaissance Analysis
- **Problem:** Initial log inspection conflated the IP address of the external web lookup service (`66.171.248.178`, the DNS A record of `bot.whatismyipaddress.com`) with the victim host's actual public IP address.
- **Solution:** Performed deep packet inspection of the HTTP 200 OK response payload (Frame 3167), revealing the 14-byte response body containing `173.66.146.112`. Corroborated this public IP in Frame 3174 where the remote SMTP server greeted the host with `Hello Beijing-5cd1-PC [173.66.146.112]`. Updated all documentation to clearly distinguish service infrastructure from victim identity.

### 7.4 Challenge: Placeholder Image Duplication in Lab Screenshots
- **Problem:** An evidentiary audit revealed that four screenshot files in `HawkEye\screenshots\` (`02`, `08`, `09`, `10`) were 3,304-byte identical non-image text placeholders.
- **Solution:** Re-captured genuine high-resolution (1366×768) Wireshark screenshots for all four events directly from `stealer.pcap`. Replaced the placeholders, validated PNG headers, verified unique cryptographic hashes, synchronized both screenshot directories, and embedded the images into the narrative report with figure numbers and frame numbers.

---

## 8. Outcomes and Impact

1. **Production-Ready Defensive Repository:** Produced an organized, fully reproducible cybersecurity portfolio encompassing detection rules, incident response plans, and forensic reports across six major enterprise scenarios.
2. **Standardized Telemetry Normalization:** Mastered and applied the Elastic Common Schema (ECS), converting multi-source log formats into unified fields (`@timestamp`, `event.category`, `source.ip`, `user.name`).
3. **Verified Forensic Excellence:** Solved 100% of forensic challenge questions across CyberDefenders HawkEye (24/24) and Hack The Box Brutus (8/8) with complete evidentiary backing.
4. **Professional SOC Documentation Standard:** Demonstrated adherence to industry reporting standards, ensuring that all findings distinguish observed evidence from analytical inference, include cryptographic checksums, and respect data sensitivity.
5. **Practical Resource Optimization:** Demonstrated that high-fidelity security operations, detection testing, and data visualization can be engineered effectively even under constrained hardware environments without compromising analytical rigor.

---

## 9. Conclusion

The ElevanceSkills SOC Internship provided comprehensive, practical experience across the primary domains of modern defensive cybersecurity. By systematically progressing through adversary emulation, detection engineering, incident response, network packet analysis, Linux host forensics, and telemetry dashboard development, this internship bridged academic computer science theory with enterprise security operations.

The resulting portfolio demonstrates technical proficiency in analyzing advanced cyber intrusions, designing resilient detection rules, and presenting complex forensic telemetry clearly and honestly. The skills and methodologies developed during this program establish a robust foundation for future professional roles as a SOC Analyst, Incident Responder, or Security Engineer.
