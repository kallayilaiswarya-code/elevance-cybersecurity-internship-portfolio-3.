# ElevanceSkills SOC Internship — Master Project Portfolio
## Security Operations Center (SOC) Engineering & Cyber Threat Analysis Portfolio

**Student Intern:** Aiswarya (Department of Cyber Security)
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Provider:** ElevanceSkills
**Internship Role:** SOC Analyst & Cybersecurity Intern
**Project Path:** `local internship project folder\`
**Submission Classification:** TLP:CLEAR / Educational Cybersecurity Portfolio
**Portfolio Status:** **All 6 Tasks Completed, Verified, and Documented**

---

> [!IMPORTANT]
> **TRANSPARENCY & EVIDENTIARY INTEGRITY DISCLOSURE:**
> This repository represents an undergraduate cybersecurity engineering portfolio developed during the ElevanceSkills SOC Internship.
> - **Hardware Constraints & Architecture:** All analytical tasks were executed on a resource-constrained workstation (Windows 11, 7.67 GB RAM). In accordance with strict SOC integrity standards, **enterprise heavyweights (live ELK clusters, Security Onion, live TheHive instances, or live MISP servers) were NOT deployed as running services on this host**.
> - **Dual-Mode Engineering:** Production compatibility was achieved through official offline specifications (e.g., standard Kibana 8.x NDJSON exports, MISP RFC-compliant JSON objects, and TheHive 5 case templates) coupled with lightweight, zero-dependency Python verification harnesses (`< 30 MB RAM`).
> - **Simulated vs. Genuine Forensics:** The portfolio cleanly bifurcates synthetic training telemetry (Tasks 2, 3, and parts of 6) from genuine incident response evidence (Tasks 1, 4, 5, and HawkEye/Brutus subsets of Task 6). Synthetic events are never presented as real attacks.

---

## 1. Portfolio Overview

This repository consolidates the six core technical deliverables completed during the ElevanceSkills SOC Internship. The curriculum encompasses the entire modern SOC defense lifecycle: adversary emulation, network protocol dissection, detection engineering (SIEM correlation rules), threat intelligence sharing (MISP), case management automation (TheHive), Linux authentication and host intrusion forensics, and multi-pillar SIEM telemetry dashboarding.

```
+---------------------------------------------------------------------------------------------------+
|                           ELEVANCESKILLS SOC INTERNSHIP CURRICULUM ARCHITECTURE                   |
+-------------------+--------------------+--------------------+--------------------+----------------+
| OFFENSIVE TTPs    | DETECTION RULES    | INCIDENT RESPONSE  | NETWORK FORENSICS  | HOST FORENSICS |
| Task 1: HawkEye   | Task 2: Elastic /  | Task 3: Multi-     | Task 4: Cyber-     | Task 5: HTB    |
| Red/Blue/Purple   | Sigma Correlation  | Stage APT Response | Defenders HawkEye  | Brutus Sherlock|
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
| **2** | **SIEM Correlation Rules** | Production-grade correlation rules detecting Credential Stuffing, DNS Tunneling, and PowerShell Exploitation. | • [Task 2 Correlation Report](SIEM-Correlation-Rules/reports/Task-2-SIEM-Correlation-Rules-Report.md)<br>• [Elastic / Sigma Rules](SIEM-Correlation-Rules/rules/) | **COMPLETE** |
| **3** | **Multi-Stage APT Incident Response** | End-to-end APT investigation, TheHive 5 case templates, MISP candidate JSON, and Python SIEM demonstrator. | • [Task 3 Final IR Report](APT-Simulation/reports/Task3-Final-Incident-Response-Report.md)<br>• [Evidence Index](APT-Simulation/reports/Task3-Evidence-Index.md)<br>• [Implementation Log](APT-Simulation/reports/Task3-Implementation-Log.md) | **COMPLETE** |
| **4** | **CyberDefenders HawkEye Investigation** | Network forensics on 4,003-packet PCAP, carving executable, analyzing 7 SMTP cycles, and solving all 24 questions. | • [HawkEye Lab Report](HawkEye/cyberdefenders-hawkeye/hawkeye-lab-report.md)<br>• [Questions & Answers (24/24)](HawkEye/cyberdefenders-hawkeye/questions-and-answers.md)<br>• [Evidence Integrity](HawkEye/cyberdefenders-hawkeye/evidence-integrity.md) | **COMPLETE** |
| **5** | **HTB Brutus SSH Forensics** | Linux host forensics on `auth.log` and binary `wtmp`, identifying 48 failed attempts, root compromise, backdoor user, and sudo abuse. | • [Task 5 HTB Brutus Report](Brutus/reports/Task-5-HTB-Brutus-Lab-Report.md)<br>• [100% Completion Proof](Brutus/Evidence/HTB-Brutus-All-8-Tasks-Completed.png.png) | **COMPLETE** |
| **6** | **Custom SIEM Dashboard** | 3-pillar attack visualization (Brute-Force, Priv-Esc, Exfiltration), 79 normalized events, Kibana NDJSON, and lightweight Python SOC UI. | • [Task 6 Dashboard Report](SIEM-Dashboard/reports/Task-6-Custom-SIEM-Dashboard-Report.md)<br>• [Kibana NDJSON Export](SIEM-Dashboard/kibana/kibana_dashboard.ndjson)<br>• [Dashboard Code](SIEM-Dashboard/backend/dashboard_server.py) | **COMPLETE** |

---

## 3. Tools & Technologies Actually Used

### 3.1 Primary Analytical Tools (Used Locally)
- **Network Protocol Analysis:** Wireshark 4.x (TCP stream reassembly, protocol dissection, payload carving, frame timing).
- **Host & Log Telemetry:** Python 3.12 (`struct`, `json`, `http.server`, `hashlib`), PowerShell 5.1 / 7 (`Get-FileHash`, `Select-String`, object pipelines).
- **Data Normalization:** Elastic Common Schema (ECS), JSON Lines (`.jsonl`), Sigma Rule Specification, Elastic Query DSL / Lucene.
- **Frontend & Visualization:** HTML5, CSS3 Modern Dark Mode, Chart.js (CDN-delivered responsive telemetry graphing).
- **Validation Harnesses:** Automated unit tests (`verify_dashboard.py`, `siem_detector.py`, `validate_templates.py`).

### 3.2 Recommended Enterprise Tooling (Documented for Production)
Where physical hardware precluded heavy enterprise server deployments, production configurations were formally drafted and documented:
- **SIEM & NSM Platforms:** Elasticsearch 8.x, Kibana 8.x, Security Onion 2.x, Zeek NSM.
- **IDS & EDR Agents:** Suricata 6.x, Snort 3.x, Microsoft Sysmon (Event IDs 1, 3, 11), CrowdStrike Falcon.
- **Threat Intelligence & SOAR:** TheHive 5 Case Management, MISP (Malware Information Sharing Platform), Cortex Analyzers.

---

## 4. Summary of Key Learning Outcomes

1. **Adversary Emulation & Tri-Team Operations:** Learned how offensive reconnaissance transitions through initial access, privilege escalation, and exfiltration, and how Red, Blue, and Purple teams collaborate to close defensive visibility gaps.
2. **SIEM Detection Engineering:** Developed precision correlation logic across threshold-based attacks (credential stuffing), statistical anomalies (DNS tunneling sub-label entropy), and script-block telemetry (obfuscated PowerShell).
3. **Structured Incident Response:** Mastered standard NIST SP 800-61 incident response phases, implementing containment playbooks, forensic evidence indexes, and structured gap analysis.
4. **Network & Binary Packet Forensics:** Decoded complex multi-stage network attacks from raw PCAP captures, identifying staging web servers, carved PE executables, and recurring SMTP data exfiltration intervals.
5. **Linux Host Forensics:** Dissected low-level Linux authentication telemetry, reconciling human-readable `auth.log` syslogs with binary C `struct utmp` records in `wtmp` and resolving local timezone discrepancies to UTC.
6. **SOC Dashboard Engineering:** Implemented centralized telemetry visualization adhering to Elastic Common Schema standards, ensuring high-fidelity threat monitoring without system resource exhaustion.

---

## 5. Repository Directory Structure

```
Elevance-SOC-Internship/
├── README.md                                    # Master project index and portfolio guide (This File)
├── Internship-Report.md                         # Consolidated academic internship report (9 Sections)
├── FINAL-SUBMISSION-CHECKLIST.md                # Submission verification and evidentiary checklist
│
├── APT-Simulation/                              # Task 3: Multi-Stage APT Attack Simulation & Response
│   ├── data/                                    # Simulated attack telemetry logs
│   ├── evidence/                                # Preserved evidence markers
│   ├── misp/                                    # MISP candidate threat event JSON
│   ├── thehive/                                 # TheHive 5 case template JSON
│   ├── siem/                                    # Python SIEM demonstration & verification test suite
│   └── reports/                                 # Final incident response report, evidence index, gap analysis
│
├── Brutus/                                      # Task 5: HTB Sherlock "Brutus" Linux Host Forensics
│   ├── auth.log                                 # Original Linux authentication log (385 lines)
│   ├── wtmp                                     # Binary Linux user login database (15,360 bytes)
│   ├── wtmp.tsv                                 # Tab-separated forensic export
│   ├── utmp.py                                  # Binary C struct utmp parser
│   ├── Evidence/                                # HTB completion screenshot (8/8 tasks solved)
│   └── reports/                                 # Comprehensive forensic investigation report
│
├── HawkEye/                                     # Tasks 1 & 4: HawkEye Tri-Team & CyberDefenders Investigation
│   ├── evidence/                                # stealer.pcap (2.45 MB) & extracted tkraw_Protected99.exe
│   ├── red-team/                                # Task 1 Red Team attack simulation report
│   ├── blue-team/                               # Task 1 Blue Team detection analysis report
│   ├── purple-team/                             # Task 1 Purple Team defense handover report
│   ├── cyberdefenders-hawkeye/                  # Task 4 CyberDefenders lab report, Q&A (24/24), notes, IOCs
│   ├── screenshots/                             # 10 verified Wireshark evidence screenshots (1366x768 PNG)
│   └── Reports/                                 # Consolidated investigation text notes
│
├── SIEM-Correlation-Rules/                      # Task 2: Custom SIEM Correlation Rules
│   ├── data/                                    # Credential stuffing, DNS tunneling, PowerShell datasets
│   ├── rules/                                   # Elastic, Sigma, and ElastAlert rule definitions
│   └── reports/                                 # Task 2 correlation engineering report & Lucene queries
│
└── SIEM-Dashboard/                              # Task 6: Custom SIEM Dashboard (3 Attack Pillars)
    ├── backend/                                 # Zero-dependency Python HTTP server (dashboard_server.py)
    ├── frontend/                                # Dark-mode SOC console with dynamic Chart.js visualizations
    ├── data/                                    # 79 normalized ECS security events (siem_dashboard_events.jsonl)
    ├── kibana/                                  # Enterprise Kibana 8.x NDJSON export
    ├── evidence/                                # 5 automated headless browser screenshots
    ├── verify_dashboard.py                      # Automated test suite (5/5 checks passed)
    └── reports/                                 # Custom SIEM Dashboard engineering report
```

---

## 6. Evidentiary Integrity & Security Policy

- **No Public Credential Reuse:** Sensitive lab credentials identified during challenge investigations (e.g., CyberDefenders HawkEye or HTB Brutus) are strictly documented for academic evaluation and must **never** be exposed in public production systems.
- **Preservation of Raw Evidence:** Cryptographic hashes for all evidentiary binaries (`stealer.pcap`, `tkraw_Protected99.exe`, `wtmp`, `auth.log`) have been preserved in dedicated evidence integrity catalogs.
