# ElevanceSkills SOC Internship — Master Project Portfolio
## Security Operations Center (SOC) Engineering & Cyber Threat Analysis Portfolio

**Student Intern:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Provider:** ElevanceSkills
**Internship Role:** SOC Analyst & Cybersecurity Intern
**Repository Type:** Public Portfolio & Submission Staging (`Elevance-SOC-Internship-PUBLIC`)
**Submission Classification:** TLP:CLEAR / Educational Cybersecurity Portfolio
**Portfolio Status:** **All 6 Tasks Completed, Verified, and Documented**

---

> [!IMPORTANT]
> **TRANSPARENCY & EVIDENTIARY INTEGRITY DISCLOSURE:**
> This repository represents an undergraduate cybersecurity engineering portfolio developed during the ElevanceSkills SOC Internship.
> - **Hardware Constraints & Architecture:** All analytical tasks were executed on a resource-constrained workstation (Windows 11, 7.67 GB RAM). In accordance with strict SOC integrity standards, **enterprise heavyweights (live ELK clusters, Security Onion, live TheHive instances, or live MISP servers) were NOT deployed as running services on this host**.
> - **Dual-Mode Engineering:** Production compatibility was achieved through official offline specifications (e.g., standard Kibana 8.x NDJSON exports, MISP RFC-compliant JSON objects, ElastAlert 2 configurations, and TheHive 5 case templates) coupled with lightweight, zero-dependency Python verification harnesses (`< 30 MB RAM`).
> - **Simulated vs. Genuine Forensics:** The portfolio cleanly bifurcates synthetic training telemetry (Tasks 2, 3, and parts of 6) from genuine incident response evidence (Tasks 1, 4, 5, and HawkEye/Brutus subsets of Task 6). Synthetic events are never presented as real attacks.
> - **Sanitization & Exclusion Notice:** In compliance with public cybersecurity repository safety standards, raw malware binaries (`tkraw_Protected99.exe`), raw packet captures containing unredacted credentials (`stealer.pcap`), and raw Linux authentication databases (`wtmp`, `auth.log`) have been excluded from this public repository and preserved securely in offline private storage. Full cryptographic hashes and detailed forensic analysis are provided in respective reports.

---

## 1. Portfolio Overview

This repository consolidates the six core technical deliverables completed during the ElevanceSkills SOC Internship. The curriculum encompasses the entire modern SOC defense lifecycle: adversary emulation, network protocol dissection, detection engineering (SIEM correlation rules), threat intelligence sharing (MISP), case management automation (TheHive), Linux authentication and host intrusion forensics, and multi-pillar SIEM telemetry dashboarding.

```
+---------------------------------------------------------------------------------------------------+
|                           ELEVANCESKILLS SOC INTERNSHIP CURRICULUM ARCHITECTURE                   |
+-------------------+--------------------+--------------------+--------------------+----------------+
| OFFENSIVE TTPs    | DETECTION RULES    | INCIDENT RESPONSE  | NETWORK FORENSICS  | HOST FORENSICS |
| Task 1: HawkEye   | Task 2: Elastic /  | Task 3: Multi-     | Task 4: Cyber-     | Task 5: HTB    |
| Red/Blue/Purple   | Sigma / ElastAlert | Stage APT Response | Defenders HawkEye  | Brutus Sherlock|
| Attack Emulation  | Rules (3 Attacks)  | TheHive 5 & MISP   | Wireshark PCAP     | auth.log & wtmp|
+-------------------+--------------------+--------------------+--------------------+----------------+
                                              |
                                              v
                              +-------------------------------+
                              |     VISUALIZATION & SOC UI    |
                              | Task 6: Custom SIEM Dashboard |
                              | 3 Pillars, Kibana NDJSON, UI  |
                              +-------------------------------+
```

---

## 2. Six Completed Internship Tasks & Report Navigation

| Task # | Task Title | Core Technical Focus | Primary Deliverables & Reports | Status |
|:---:|:---|:---|:---|:---:|
| **1** | **HawkEye Tri-Team Analysis** | Red Team attack simulation, Blue Team detection mapping, and Purple Team collaborative defense handover. | • [Red Team Report](HawkEye/red-team/red-team-report.md)<br>• [Blue Team Report](HawkEye/blue-team/blue-team-report.md)<br>• [Purple Team Report](HawkEye/purple-team/purple-team-report.md) | **COMPLETE** |
| **2** | **SIEM Correlation Rules** | Production-grade correlation rules detecting Credential Stuffing, DNS Tunneling, and PowerShell Exploitation across Sigma, Elastic Query DSL, and ElastAlert 2. | • [Task 2 Correlation Report](SIEM-Correlation-Rules/reports/Task-2-SIEM-Correlation-Rules-Report.md)<br>• [Sigma Rules](SIEM-Correlation-Rules/sigma-rules/)<br>• [Elastic Query DSL](SIEM-Correlation-Rules/rules/elastic-dsl/)<br>• [ElastAlert Rules](SIEM-Correlation-Rules/rules/elastalert/) | **COMPLETE** |
| **3** | **Multi-Stage APT Incident Response** | End-to-end APT investigation, TheHive 5 case templates, MISP candidate JSON, and Python SIEM demonstrator. | • [Task 3 Final IR Report](APT-Simulation/reports/Task3-Final-Incident-Response-Report.md)<br>• [Evidence Index](APT-Simulation/reports/Task3-Evidence-Index.md)<br>• [Implementation Log](APT-Simulation/reports/Task3-Implementation-Log.md) | **COMPLETE** |
| **4** | **CyberDefenders HawkEye Investigation** | Network forensics on 4,003-packet PCAP, carving executable, analyzing 7 SMTP cycles, and solving all 24 questions. | • [HawkEye Lab Report](HawkEye/cyberdefenders-hawkeye/hawkeye-lab-report.md)<br>• [Questions & Answers (24/24)](HawkEye/cyberdefenders-hawkeye/questions-and-answers.md)<br>• [Evidence Integrity](HawkEye/cyberdefenders-hawkeye/evidence-integrity.md) | **COMPLETE** |
| **5** | **HTB Brutus SSH Forensics** | Linux host forensics on `auth.log` and binary `wtmp`, identifying 48 failed attempts, root compromise, backdoor user, and sudo abuse. | • [Task 5 HTB Brutus Report](Brutus/reports/Task-5-HTB-Brutus-Lab-Report.md)<br>• [100% Completion Proof](Brutus/Evidence/HTB-Brutus-All-8-Tasks-Completed.png.png) | **COMPLETE** |
| **6** | **Custom SIEM Dashboard** | 3-pillar attack visualization (Brute-Force, Priv-Esc, Exfiltration), 79 normalized events, Kibana NDJSON, and lightweight Python SOC UI. | • [Task 6 Dashboard Report](SIEM-Dashboard/reports/Task-6-Custom-SIEM-Dashboard-Report.md)<br>• [Kibana NDJSON Export](SIEM-Dashboard/kibana/kibana_dashboard.ndjson)<br>• [Dashboard Code](SIEM-Dashboard/backend/dashboard_server.py) | **COMPLETE** |

---

## 3. Tools & Technologies Actually Used

### 3.1 Primary Analytical Tools (Used Locally)
- **Network Protocol Analysis:** Wireshark 4.x (TCP stream reassembly, protocol dissection, payload carving, frame timing).
- **Host & Log Telemetry:** Python 3.12 (`struct`, `json`, `http.server`, `hashlib`), PowerShell 5.1 / 7 (`Get-FileHash`, `Select-String`, object pipelines).
- **Data Normalization:** Elastic Common Schema (ECS), JSON Lines (`.jsonl`), Sigma Rule Specification, Elastic Query DSL, ElastAlert 2 YAML, Lucene.
- **Frontend & Visualization:** HTML5, CSS3 Modern Dark Mode, Chart.js (CDN-delivered responsive telemetry graphing).
- **Validation Harnesses:** Automated unit tests (`verify_dashboard.py`, `siem_engine.py`, `validate_sigma.py`, `validate_elastalert.py`, `validate_elastic_dsl.py`, `validate_templates.py`).

### 3.2 Recommended Enterprise Tooling (Documented for Production)
Where physical hardware precluded heavy enterprise server deployments, production configurations were formally drafted and documented:
- **SIEM & NSM Platforms:** Elasticsearch 8.x, Kibana 8.x, Security Onion 2.x, Zeek NSM.
- **IDS & EDR Agents:** Suricata 6.x, Snort 3.x, Microsoft Sysmon (Event IDs 1, 3, 11), CrowdStrike Falcon.
- **Threat Intelligence & SOAR:** TheHive 5 Case Management, MISP (Malware Information Sharing Platform), Cortex Analyzers.

---

## 4. Summary of Key Learning Outcomes

1. **Adversary Emulation & Tri-Team Operations:** Learned how offensive reconnaissance transitions through initial access, privilege escalation, and exfiltration, and how Red, Blue, and Purple teams collaborate to close defensive visibility gaps.
2. **SIEM Detection Engineering:** Developed precision correlation logic across threshold-based attacks (credential stuffing), statistical anomalies (DNS tunneling sub-label entropy), and script-block telemetry (obfuscated PowerShell) across Sigma, Elastic Query DSL, and ElastAlert 2.
3. **Structured Incident Response:** Mastered standard NIST SP 800-61 incident response phases, implementing containment playbooks, forensic evidence indexes, and structured gap analysis.
4. **Network & Binary Packet Forensics:** Decoded complex multi-stage network attacks from raw PCAP captures, identifying staging web servers, carved PE executables, and recurring SMTP data exfiltration intervals.
5. **Linux Host Forensics:** Dissected low-level Linux authentication telemetry, reconciling human-readable `auth.log` syslogs with binary C `struct utmp` records in `wtmp` and resolving local timezone discrepancies to UTC.
6. **SOC Dashboard Engineering:** Implemented centralized telemetry visualization adhering to Elastic Common Schema standards, ensuring high-fidelity threat monitoring without system resource exhaustion.

---

## 5. Repository Directory Structure (Public Sanitized Layout)

```
Elevance-SOC-Internship-PUBLIC/
├── README.md                                    # Master project index and portfolio guide (This File)
├── Internship-Report.md                         # Consolidated academic internship report (9 Sections)
├── FINAL-SUBMISSION-CHECKLIST.md                # Submission verification and evidentiary checklist
├── FINAL_SUBMISSION_AUDIT.md                    # Formal Phase 1 pre-submission technical audit report
├── PUBLIC-RELEASE-AUDIT.md                      # Sanitization and sensitive file exclusion audit
├── PRE-PUSH-VERIFICATION.md                     # Pre-push validation records
├── index.html                                   # Interactive GitHub Pages portfolio showcase
│
├── APT-Simulation/                              # Task 3: Multi-Stage APT Attack Simulation & Response
│   ├── evidence/                                # Preserved synthetic evidence markers (yara-training-marker.txt)
│   ├── logs/                                    # Raw simulated APT event logs (apt-events.jsonl)
│   ├── reports/                                 # Final incident response report, evidence index, timeline, gap analysis
│   ├── rules/                                   # Detection rules (7 Sigma rules, 1 YARA marker rule)
│   ├── simulation/                              # SIEM correlation engine, APT detector, and synthetic ECS events
│   └── threat-intelligence/                     # MISP training event JSON, TheHive 5 case template, training IOCs CSV
│
├── Brutus/                                      # Task 5: HTB Sherlock "Brutus" Linux Host Forensics
│   ├── Evidence/                                # HTB completion screenshot (8/8 tasks solved proof)
│   ├── reports/                                 # Comprehensive forensic investigation report (496 lines)
│   └── utmp.py                                  # Binary C struct utmp parser utility
│   *(Note: auth.log and binary wtmp excluded from public repo; hashes documented in report)*
│
├── HawkEye/                                     # Tasks 1 & 4: HawkEye Tri-Team & CyberDefenders Investigation
│   ├── blue-team/                               # Task 1 Blue Team defensive analysis report
│   ├── cyberdefenders-hawkeye/                  # Task 4 CyberDefenders lab report, Q&A (24/24), notes, IOCs
│   ├── notes/                                   # Investigation scratch notes and timelines
│   ├── purple-team/                             # Task 1 Purple Team defense handover report
│   ├── red-team/                                # Task 1 Red Team attack simulation report
│   ├── screenshots/                             # 10 verified Wireshark evidence screenshots (1366x768 PNG)
│   └── README.md                                # HawkEye module overview and navigation
│   *(Note: stealer.pcap and tkraw_Protected99.exe excluded from public repo; hashes documented in report)*
│
├── SIEM-Correlation-Rules/                      # Task 2: Custom SIEM Correlation Rules
│   ├── credential_stuffing_correlation.py       # Sliding-window multi-account correlation engine
│   ├── detect.py                                 # Primary Python detection evaluation engine
│   ├── validate_sigma.py                         # Zero-dependency Sigma rule validator
│   ├── validate_elastalert.py                    # Zero-dependency ElastAlert 2 configuration validator
│   ├── validate_elastic_dsl.py                   # Zero-dependency Elastic Query DSL validator
│   ├── logs/                                    # 10 calibrated synthetic ECS security events (sample-events.jsonl)
│   ├── reports/                                 # Technical report, alerts JSON, credential stuffing JSON, Lucene text
│   ├── rules/                                   # Custom detector definitions, ElastAlert YAML, Elastic DSL JSON
│   └── sigma-rules/                             # Official Sigma community rule definitions
│
└── SIEM-Dashboard/                              # Task 6: Custom SIEM Dashboard (3 Attack Pillars)
    ├── backend/                                 # Zero-dependency Python HTTP server (dashboard_server.py)
    ├── data/                                    # 79 normalized ECS security events & dataset builder
    ├── evidence/                                # 5 automated headless browser screenshots
    ├── frontend/                                # Dark-mode SOC console with dynamic Chart.js visualizations
    ├── kibana/                                  # Enterprise Kibana 8.x NDJSON export (7 saved objects)
    ├── reports/                                 # Custom SIEM Dashboard engineering report
    └── verify_dashboard.py                      # Automated test suite (5/5 checks passed)
```

---

## 6. Evidentiary Integrity & Security Policy

- **No Public Credential Reuse:** Sensitive lab credentials identified during challenge investigations (e.g., CyberDefenders HawkEye or HTB Brutus) are strictly documented for academic evaluation and must **never** be exposed in public production systems.
- **Preservation of Raw Evidence:** Cryptographic hashes for all evidentiary binaries (`stealer.pcap`, `tkraw_Protected99.exe`, `wtmp`, `auth.log`) have been preserved in dedicated evidence integrity catalogs.
