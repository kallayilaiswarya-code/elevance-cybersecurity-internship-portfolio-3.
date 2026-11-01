# ElevanceSkills SOC Internship — Final Submission Package
## Security Operations Center (SOC) Engineering, Threat Analysis & Telemetry Correlation

**Student Intern:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Provider:** ElevanceSkills
**Internship Role:** SOC Analyst & Cybersecurity Intern
**Project Classification:** TLP:CLEAR / Educational Cybersecurity Portfolio
**Submission Package Date:** 2026-10-31
**GitHub Repository:** `https://github.com/kallayilaiswarya-code/elevance-cybersecurity-internship-portfolio-3..git`
**Live Portfolio Showcase:** `https://kallayilaiswarya-code.github.io/elevance-cybersecurity-internship-portfolio-3../`

---

> [!IMPORTANT]
> **TRANSPARENCY & EVIDENTIARY INTEGRITY DISCLOSURE:**
> This submission package represents a comprehensive cybersecurity engineering portfolio completed during the ElevanceSkills SOC Internship.
> - **Hardware Boundary:** All tasks were executed on a resource-constrained host (Windows 11, 7.67 GB RAM). In accordance with strict SOC integrity standards, **enterprise heavyweights (live ELK clusters, Security Onion, live TheHive instances, or live MISP servers) were NOT deployed as running services on this host**.
> - **Dual-Mode Zero-Overhead Engineering:** Production capability was achieved through official offline specifications (Kibana 8.x NDJSON exports, MISP RFC JSON, TheHive 5 case templates, ElastAlert 2 configurations) coupled with lightweight, zero-dependency Python verification harnesses (`< 30 MB RAM`).
> - **Data Provenance:** Synthetic training telemetry (Tasks 2, 3, and parts of 6) is cleanly distinguished from genuine forensic challenge evidence (Tasks 1, 4, 5, and HawkEye/Brutus subsets of Task 6).
> - **Sanitization & Safety Policy:** In accordance with responsible public cybersecurity practices, raw malware binaries (`tkraw_Protected99.exe`), raw packet captures containing unredacted network passwords (`stealer.pcap`), and internal Linux user databases (`auth.log`, `wtmp`) are excluded from this distribution. Full cryptographic hashes and granular packet/syslog line references are preserved in the technical reports.

---

## 1. Package Directory Structure

```text
FINAL-SUBMISSION-PACKAGE/
├── README.md                                    # Master submission guide & execution instructions (This File)
├── DEMO_VIDEO_SCRIPT.md                         # Complete 2-5 minute demonstration video script
│
├── PDF-Reports/                                 # 7 Publication-Ready Academic PDF Reports
│   ├── Consolidated-Internship-Report.pdf       # Master 9-section academic internship report
│   ├── Task-1-HawkEye-TriTeam-Report.pdf        # Red, Blue, and Purple Team consolidated report
│   ├── Task-2-SIEM-Correlation-Rules-Report.pdf # Custom SIEM correlation rules report (345 lines)
│   ├── Task-3-APT-Incident-Response-Report.pdf  # Multi-stage APT IR report (NIST SP 800-61r2)
│   ├── Task-4-HawkEye-Network-Forensics-Report.pdf # CyberDefenders HawkEye report (24/24 solved)
│   ├── Task-5-HTB-Brutus-Linux-Forensics-Report.pdf # HTB Brutus Sherlock report (8/8 solved)
│   └── Task-6-Custom-SIEM-Dashboard-Report.pdf  # Custom SIEM Dashboard engineering report
│
├── Datasets/                                    # Calibrated CSV & JSONL Telemetry
│   ├── training-iocs.csv                        # Task 3 Threat intelligence indicators (9 items)
│   ├── siem_dashboard_events.jsonl              # Task 6 79 normalized ECS security events
│   ├── sample-events.jsonl                      # Task 2 10 synthetic test events
│   └── synthetic_ecs_events.jsonl               # Task 3 12 synthetic APT attack events
│
├── Detection-Rules-and-Configs/                 # Production Multi-Platform Rule Configurations
│   ├── sigma/                                   # 10 Sigma Community YAML Detection Rules
│   │   ├── credential_stuffing.yml              # Windows 4625 failed authentication rule
│   │   ├── powershell_encoded_command.yml       # Obfuscated PowerShell CLI rule
│   │   ├── suspicious_long_dns_query.yml        # Long DNS query regex rule
│   │   ├── stage1-initial-access-office-spawn.yml # Macro spawning hidden PowerShell
│   │   ├── stage2-execution-encoded-powershell.yml # Encoded download cradle rule
│   │   ├── stage3-persistence-scheduled-task.yml # Logon trigger task rule
│   │   ├── stage4-privilege-escalation-sensitive-privilege.yml # SeDebugPrivilege rule
│   │   ├── stage5-lateral-movement-remote-wmi.yml # Remote WMI execution rule
│   │   ├── stage6-exfiltration-dns-tunneling.yml # DNS TXT tunneling rule
│   │   └── apt-suspicious-powershell.yml        # APT training PowerShell rule
│   ├── elastalert/                              # 3 ElastAlert 2 Production YAML Configurations
│   │   ├── credential_stuffing.yaml             # Multi-account sliding window cardinality rule
│   │   ├── dns_tunneling.yaml                   # High-entropy long DNS query rule
│   │   └── powershell_encoded.yaml              # Obfuscated process execution rule
│   ├── elastic-dsl/                             # 3 Native Elasticsearch 8.x Query DSL JSON Definitions
│   │   ├── credential_stuffing_dsl.json         # Terms + Cardinality bucket selector aggregation
│   │   ├── dns_tunneling_dsl.json               # Range + regex subdomain filter query
│   │   └── powershell_encoded_dsl.json          # Wildcard CLI execution query
│   ├── misp/                                    # Threat Intelligence Candidate Event
│   │   └── misp-training-event.json             # RFC-compliant MISP core JSON (9 attributes, 8 tags)
│   ├── thehive/                                 # Case Management Automation
│   │   └── thehive-case-template.json           # TheHive 5 case template (7 tasks, 6 observables)
│   ├── yara/                                    # Static Binary Signature
│   │   └── apt_training_marker.yar              # Verified against training marker with YARA 4.5.5
│   └── kibana/                                  # Enterprise SIEM Dashboard Export
│       └── kibana_dashboard.ndjson              # Kibana 8.x Saved Objects (1 Data View, 5 Lens, 1 Dashboard)
│
├── Source-Code/                                 # Lightweight, Zero-Dependency Verification Tooling
│   ├── SIEM-Dashboard/                          # Custom SIEM Web Console
│   │   ├── backend/dashboard_server.py          # Python standard library HTTP/REST server (< 30 MB RAM)
│   │   ├── frontend/index.html                  # Dark-mode responsive SOC UI with dynamic Chart.js
│   │   ├── data/build_dashboard_dataset.py      # Telemetry aggregation & ECS normalizer
│   │   ├── kibana/generate_kibana_ndjson.py     # Kibana Saved Objects builder
│   │   └── verify_dashboard.py                  # Automated 5-stage test suite
│   ├── SIEM-Correlation-Rules/                  # Detection Engines & Zero-Dependency Validators
│   │   ├── detect.py                            # Primary Python detection evaluation engine
│   │   ├── credential_stuffing_correlation.py   # Multi-account sliding window aggregator
│   │   ├── validate_sigma.py                    # Zero-dependency Sigma rule validator
│   │   ├── validate_elastalert.py               # Zero-dependency ElastAlert 2 validator
│   │   └── validate_elastic_dsl.py              # Zero-dependency Elastic DSL validator
│   ├── APT-Simulation/                          # APT Pipeline & Threat Intel Tools
│   │   ├── siem_engine.py                       # Ingestion, Sigma evaluator & Lucene search engine
│   │   ├── detect_apt.py                        # Lightweight APT incident alert generator
│   │   └── validate_templates.py                # MISP & TheHive offline template validator
│   └── Brutus/                                  # Low-Level Binary Forensic Tools
│       └── utmp.py                              # Binary C struct utmp parser (UTC normalized)
│
├── Evidence/                                    # Verified Forensic Screenshots (PNG)
│   ├── Brutus/
│   │   └── HTB-Brutus-All-8-Tasks-Completed.png.png # 100% HTB Sherlock solved proof badge
│   ├── HawkEye/                                 # 10 Verified 1366x768 Wireshark Investigation Screenshots
│   │   ├── 01_http_executable_download.png
│   │   ├── 02_smtp_exfiltration.png
│   │   ├── 03_repeated_smtp_activity.png
│   │   ├── 04_dns_resolution.png
│   │   ├── 05_post_download_ip_lookup.png
│   │   ├── 06_external_http_connection.png
│   │   ├── 07_smtp_server_connection.png
│   │   ├── 08_smtp_authentication.png
│   │   ├── 09_email_submission.png
│   │   └── 10_smtp_message_accepted.png
│   └── SIEM-Dashboard/                          # 5 Headless Browser Verification Screenshots
│       ├── 01_dashboard_overview.png
│       ├── 02_brute_force_view.png
│       ├── 03_privilege_escalation_view.png
│       ├── 04_data_exfiltration_view.png
│       └── 05_telemetry_table_view.png
│
└── Checklists/                                  # Submission Verification & Delivery Guides
    ├── GOOGLE_DRIVE_SHARING_CHECKLIST.md        # Drive upload & public permission steps
    ├── DEMO_VIDEO_RECORDING_CHECKLIST.md        # Video recording parameters & upload steps
    └── FINAL_SUBMISSION_CHECKLIST.md            # Comprehensive pre-submission audit checklist
```

---

## 2. Local Execution & Verification Instructions

All components run locally on standard Python 3.10+ without installing heavy software or enterprise server clusters:

### 2.1 Launching the Custom SIEM Dashboard (Task 6)
```powershell
# Navigate to the dashboard directory
cd Source-Code\SIEM-Dashboard

# Execute automated 5-stage verification test
python verify_dashboard.py

# Launch the local zero-dependency SOC dashboard server (< 30 MB RAM)
python backend\dashboard_server.py
```
Open a browser and navigate to:
**`http://127.0.0.1:8080/`**
The interactive dark-mode SOC console will render dynamic Chart.js visualizations for all 3 attack pillars (Brute Force, Privilege Escalation, Data Exfiltration), live computed KPI metrics, category filtering, and raw JSON modal inspection.

### 2.2 Running SIEM Correlation Rules & Validators (Task 2)
```powershell
# Navigate to SIEM Correlation Rules directory
cd Source-Code\SIEM-Correlation-Rules

# Run zero-dependency Sigma rule validator (3 rules)
python validate_sigma.py

# Run zero-dependency ElastAlert 2 validator (3 rules)
python validate_elastalert.py

# Run zero-dependency Elastic Query DSL validator (3 configurations)
python validate_elastic_dsl.py

# Run primary detection engine against 10 synthetic events (generates 4 alerts)
python detect.py

# Run sliding-window credential stuffing correlation engine
python credential_stuffing_correlation.py
```

### 2.3 Running Multi-Stage APT Simulation & SOAR Validators (Task 3)
```powershell
# Navigate to APT Simulation directory
cd Source-Code\APT-Simulation

# Validate offline MISP and TheHive 5 candidate templates
python validate_templates.py

# Execute Route D SIEM Ingestion, Sigma evaluation & Lucene search engine
python siem_engine.py

# Generate APT incident alerts
python detect_apt.py
```

---

## 3. Summary of Six Completed Tasks

| Task # | Task Title | Primary Findings & Key Achievements |
|:---:|:---|:---|
| **1** | **HawkEye Tri-Team Analysis** | Deconstructed the intrusion chain across Red, Blue, and Purple teams; mapped T1105 staging download, T1016 IP discovery, T1041 SMTP egress on port 587, and 10-minute exfiltration beaconing. |
| **2** | **SIEM Correlation Rules** | Designed and validated production rules for Credential Stuffing (T1110.004), DNS Tunneling (T1071.004), and PowerShell Obfuscation (T1059.001) across Sigma, Elastic Query DSL, and ElastAlert 2. |
| **3** | **Multi-Stage APT Incident Response** | Investigated a 6-stage APT intrusion modeled on NIST SP 800-61r2; engineered Python SIEM correlation engine achieving 100% TPR / 0% FPR; validated MISP and TheHive 5 templates. |
| **4** | **CyberDefenders HawkEye Lab** | Solved 100% (24/24) questions analyzing 4,003 packets in Wireshark; carved `tkraw_Protected99.exe`; verified 10 genuine screenshots with exact frame numbers (Frames 204–3206). |
| **5** | **HTB Brutus SSH Forensics** | Solved 100% (8/8) questions analyzing Linux `auth.log` and binary `wtmp`; identified 48 failed logins from `65.2.161.68`, root compromise, Session 37, backdoor `cyberjunkie`, and `curl linper.sh`. |
| **6** | **Custom SIEM Dashboard** | Engineered dual-mode SOC dashboard; 79 ECS-normalized events; dynamic Chart.js graphing for 3 attack pillars; verified Kibana 8.x NDJSON export; passed 5/5 automated tests. |
