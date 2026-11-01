# ElevanceSkills SOC Internship — Final Submission & Quality Validation Checklist

**Document Reference:** ELEV-SUBMISSION-CHECKLIST-2026-FINAL
**Student Intern:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Internship Role:** SOC Analyst & Cybersecurity Intern (ElevanceSkills)
**Submission Classification:** TLP:CLEAR / Educational Cybersecurity Portfolio
**Audit & Assembly Timestamp:** 2026-10-31
**Verification Status:** **100% COMPLETE — FULLY AUDITED, PACKAGED & READY FOR MANUAL STUDENT SUBMISSION**

---

## 1. Official Six Internship Tasks Deliverables Audit

| Task # | Task Description | Primary Technical Deliverables | Verification Status | Evidentiary Backing & Notes |
|:---:|:---|:---|:---:|:---|
| **1** | **HawkEye Tri-Team Analysis** | • [`HawkEye/red-team/red-team-report.md`](HawkEye/red-team/red-team-report.md)<br>• [`HawkEye/blue-team/blue-team-report.md`](HawkEye/blue-team/blue-team-report.md)<br>• [`HawkEye/purple-team/purple-team-report.md`](HawkEye/purple-team/purple-team-report.md)<br>• `Task-1-HawkEye-TriTeam-Report.pdf` | **COMPLETE (100%)** | All 3 perspective reports exist, complete with MITRE ATT&CK/D3FEND matrix, Suricata signatures, Lucene sequence query, and SOC containment playbook. |
| **2** | **Custom SIEM Correlation Rules** | • [`Task-2-SIEM-Correlation-Rules-Report.md`](SIEM-Correlation-Rules/reports/Task-2-SIEM-Correlation-Rules-Report.md)<br>• Sigma YAML Rules (3 rules)<br>• ElastAlert 2 YAML Rules (3 rules)<br>• Elastic Query DSL JSON (3 queries)<br>• `Task-2-SIEM-Correlation-Rules-Report.pdf` | **COMPLETE (100%)** | Multi-tier detection for Credential Stuffing (T1110.004), DNS Tunneling (T1071.004), and PowerShell (T1059.001); all 3 zero-dependency validators PASS. |
| **3** | **Multi-Stage APT Incident Response** | • [`Task3-Final-Incident-Response-Report.md`](APT-Simulation/reports/Task3-Final-Incident-Response-Report.md)<br>• 7 Sigma Rules & 1 YARA Marker Rule<br>• `misp-training-event.json` & `thehive-case-template.json`<br>• `Task-3-APT-Incident-Response-Report.pdf` | **COMPLETE (100%)** | 6-stage APT lifecycle investigated under NIST SP 800-61r2; `siem_engine.py` generated 7 alerts (100% TPR / 0% FPR); MISP/TheHive templates validated. |
| **4** | **CyberDefenders HawkEye Lab** | • [`hawkeye-lab-report.md`](HawkEye/cyberdefenders-hawkeye/hawkeye-lab-report.md)<br>• [`questions-and-answers.md`](HawkEye/cyberdefenders-hawkeye/questions-and-answers.md)<br>• 10 Wireshark Evidence Screenshots<br>• `Task-4-HawkEye-Network-Forensics-Report.pdf` | **COMPLETE (100%)** | 100% solved (24/24 questions); carved `tkraw_Protected99.exe`; victim public IP `173.66.146.112` disambiguated; 10-minute SMTP cadence proved across 7 cycles. |
| **5** | **HTB Brutus Linux Host Forensics** | • [`Task-5-HTB-Brutus-Lab-Report.md`](Brutus/reports/Task-5-HTB-Brutus-Lab-Report.md)<br>• `utmp.py` Binary C Parser<br>• HTB 8/8 Solved Proof Screenshot<br>• `Task-5-HTB-Brutus-Linux-Forensics-Report.pdf` | **COMPLETE (100%)** | 100% solved (8/8 questions); 48 failed logins from `65.2.161.68` across 5 accounts; Session 37 root login; `utmp.py` UTC resolution (`06:32:45 UTC`); backdoor `cyberjunkie`. |
| **6** | **Custom SIEM Dashboard** | • [`Task-6-Custom-SIEM-Dashboard-Report.md`](SIEM-Dashboard/reports/Task-6-Custom-SIEM-Dashboard-Report.md)<br>• `dashboard_server.py` & `index.html`<br>• 79 ECS Normalized Events (`.jsonl`)<br>• `kibana_dashboard.ndjson` (7 objects)<br>• `Task-6-Custom-SIEM-Dashboard-Report.pdf` | **COMPLETE (100%)** | Dual-mode SOC console (< 30 MB RAM); dynamic Chart.js visualizations for all 3 pillars; 5/5 automated test suite passed; verified Kibana 8.x NDJSON export. |

---

## 2. Publication-Ready PDF Reports Audit

All 7 required PDF reports have been generated using the local headless browser rendering engine, verified for complete content, valid `%PDF-` file headers, and substantial page counts:

| # | PDF Report Filename | Source Markdown File | File Size | Header Check | Status |
|:---:|:---|:---|---:|:---:|:---:|
| **1** | `Consolidated-Internship-Report.pdf` | `Internship-Report.md` (9 Sections) | 317,578 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **2** | `Task-1-HawkEye-TriTeam-Report.pdf` | Red, Blue & Purple Reports Consolidated | 497,056 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **3** | `Task-2-SIEM-Correlation-Rules-Report.pdf` | `Task-2-SIEM-Correlation-Rules-Report.md` | 354,993 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **4** | `Task-3-APT-Incident-Response-Report.pdf` | `Task3-Final-Incident-Response-Report.md` | 313,728 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **5** | `Task-4-HawkEye-Network-Forensics-Report.pdf` | `hawkeye-lab-report.md` (with 10 figures) | 1,869,246 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **6** | `Task-5-HTB-Brutus-Linux-Forensics-Report.pdf` | `Task-5-HTB-Brutus-Lab-Report.md` | 576,905 bytes | Valid (`%PDF-`) | **VERIFIED** |
| **7** | `Task-6-Custom-SIEM-Dashboard-Report.pdf` | `Task-6-Custom-SIEM-Dashboard-Report.md` | 388,005 bytes | Valid (`%PDF-`) | **VERIFIED** |

---

## 3. Telemetry Datasets & Normalized Artifacts

| Dataset Filename | Format | Event Count / Scope | Purpose & Provenance | Verification Status |
|:---|:---:|:---:|:---|:---:|
| `training-iocs.csv` | CSV | 9 Structured Indicators | Hashes, staging IPs, domains, and task markers from Task 3 APT investigation. | **VERIFIED** |
| `siem_dashboard_events.jsonl` | JSONL | 79 ECS Normalized Events | Consolidates synthetic simulation (21) and real lab forensics (58) across 3 pillars. | **VERIFIED** |
| `sample-events.jsonl` | JSONL | 10 Calibrated ECS Events | Synthetic test cases evaluating Credential Stuffing, DNS, and PowerShell detection. | **VERIFIED** |
| `synthetic_ecs_events.jsonl` | JSONL | 12 Calibrated ECS Events | 6 positive APT attack stages and 6 negative benign baselines for Task 3. | **VERIFIED** |

---

## 4. Detection Engineering Rules & Configuration Files

| Framework / Engine | Directory Location | Files Included | Specification Standard | Status |
|:---|:---|:---|:---|:---:|
| **Sigma Community** | `Detection-Rules-and-Configs/sigma/` | 10 YAML Rules | Official Sigma Rule Specification v1.0 | **VERIFIED (3/3 & 7/7)** |
| **ElastAlert 2** | `Detection-Rules-and-Configs/elastalert/` | 3 YAML Rules | ElastAlert 2 Cardinality & Any Filter Specification | **VERIFIED (3/3)** |
| **Elastic Query DSL** | `Detection-Rules-and-Configs/elastic-dsl/` | 3 JSON Queries | Elasticsearch 8.x Search API & Aggregations | **VERIFIED (3/3)** |
| **MISP Threat Intel** | `Detection-Rules-and-Configs/misp/` | `misp-training-event.json` | MISP RFC Core Event Specification | **VERIFIED** |
| **TheHive 5 SOAR** | `Detection-Rules-and-Configs/thehive/` | `thehive-case-template.json` | TheHive 5 Case & Observable API Specification | **VERIFIED** |
| **YARA Signature** | `Detection-Rules-and-Configs/yara/` | `apt_training_marker.yar` | YARA 4.5.5 Static String Signature | **VERIFIED** |
| **Kibana Saved Objects** | `Detection-Rules-and-Configs/kibana/` | `kibana_dashboard.ndjson` | Official Kibana 8.x Saved Objects NDJSON | **VERIFIED** |

---

## 5. Software Source Code & Automated Test Suites

| Component | Primary Script | Verification Command | Benchmark Result | Status |
|:---|:---|:---|:---|:---:|
| **SIEM Dashboard** | `backend/dashboard_server.py`<br>`frontend/index.html` | `python verify_dashboard.py` | 5/5 Tests Passed (Files, Ingestion, Metrics, NDJSON, REST API) | **OPERATIONAL** |
| **SIEM Rules Validator** | `validate_sigma.py` | `python validate_sigma.py` | 3/3 Sigma rules validated with zero external dependencies | **PASS** |
| **ElastAlert Validator** | `validate_elastalert.py` | `python validate_elastalert.py` | 3/3 ElastAlert configurations validated | **PASS** |
| **Elastic DSL Validator**| `validate_elastic_dsl.py` | `python validate_elastic_dsl.py` | 3/3 Elastic Query DSL queries validated | **PASS** |
| **Primary SIEM Engine** | `detect.py` | `python detect.py` | 10 events processed $\rightarrow$ 4 alerts generated (0 FPR) | **PASS** |
| **Sliding Window Engine**| `credential_stuffing_correlation.py`| `python credential_stuffing_correlation.py` | 5 failures across 5 users $\rightarrow$ 1 High alert generated | **PASS** |
| **APT Ingestion Engine** | `siem_engine.py` | `python siem_engine.py` | 12 events $\rightarrow$ 7 alerts (100% TPR / 0% FPR) | **PASS** |
| **Template Validator** | `validate_templates.py` | `python validate_templates.py` | MISP and TheHive candidate templates parsed cleanly | **PASS** |
| **Binary utmp Parser** | `utmp.py` | `python utmp.py -h` | Decodes C struct utmp records with UTC normalization | **PASS** |

---

## 6. Evidentiary Screenshots & Forensic Proofs

| Category | File Path | Resolution / Size | Content & Verification Notes | Status |
|:---|:---|:---:|:---|:---:|
| **HTB Brutus Proof** | `Evidence/Brutus/HTB-Brutus-All-8-Tasks-Completed.png.png` | 125,891 bytes | Genuine Hack The Box Sherlock dashboard showing 8/8 tasks solved (100% completion). | **VERIFIED** |
| **HawkEye Wireshark** | `Evidence/HawkEye/` (01 to 10 PNGs) | 1366×768 PNGs | 10 unique, high-resolution screenshots verifying DNS queries, executable carving, and SMTP exfiltration. | **VERIFIED** |
| **SIEM Dashboard** | `Evidence/SIEM-Dashboard/` (01 to 05 PNGs) | ~72,000 bytes each | 5 automated headless browser captures showing overview, 3 pillars, and live telemetry explorer. | **VERIFIED** |

---

## 7. Security, Sanitization & Ethical Boundary Policy

- [x] **No Executable Malware in Distribution:** `tkraw_Protected99.exe` excluded from the public package and preserved offline.
- [x] **No Unredacted Raw Packet Captures:** `stealer.pcap` excluded to protect plaintext challenge passwords from public scraping.
- [x] **No Internal System Databases:** Raw Linux `auth.log` and binary `wtmp` excluded from public staging.
- [x] **No Live Server Exploits:** All offensive testing was executed in isolated offline simulation environments.
- [x] **No Sensitive Credentials Exposed:** Educational credentials documented with descriptive redaction placeholders.
- [x] **Zero Leaked Secrets / Keys:** Checked for `.env`, private SSH keys, and cloud API tokens (none present).

---

## 8. Honest Architectural & Hardware Disclosures

- [x] **Workstation Memory Disclosure:** Windows 11 host with 7.67 GB RAM properly disclosed in all reports.
- [x] **No False Cluster Deployment:** Clear disclosure that live Elasticsearch clusters, Security Onion, live TheHive, or live MISP servers were not hosted locally due to physical RAM limitations.
- [x] **Dual-Mode Zero-Overhead Architecture:** Compliance achieved via official offline specifications (NDJSON, JSON, YAML) coupled with standard-library Python engines (`< 30 MB RAM`).
- [x] **Data Provenance:** Synthetic simulation telemetry is explicitly distinguished from real lab forensic captures.

---

## 9. Final Submission Package Structure Verification

The standalone submission package is staged and ready inside the public repository:
`C:\Users\aiswarya\Documents\Elevance-SOC-Internship-PUBLIC\FINAL-SUBMISSION-PACKAGE\`

```text
FINAL-SUBMISSION-PACKAGE/
├── README.md                                    # Master submission overview & execution guide
├── DEMO_VIDEO_SCRIPT.md                         # Complete 2-5 minute demonstration script
├── PDF-Reports/                                 # All 7 verified PDF reports
├── Datasets/                                    # All 4 CSV & JSONL datasets
├── Detection-Rules-and-Configs/                 # Sigma, ElastAlert, Elastic DSL, MISP, TheHive, YARA, Kibana
├── Source-Code/                                 # Dashboard, correlation rules, APT engine, utmp parser
├── Evidence/                                    # Brutus, HawkEye, and Dashboard verified screenshots
└── Checklists/                                  # Drive checklist, video checklist, submission checklist
```

---

## 10. Student Final Action Guide Before Portal Submission

As required by the critical stop conditions, automated publishing, pushing, and form submission are disabled. Please complete the final steps manually:

1. **Review Local Package:**
   - Browse [`FINAL-SUBMISSION-PACKAGE/`](FINAL-SUBMISSION-PACKAGE/) and verify all files open cleanly on your workstation.
2. **Record Demo Video (2–5 Minutes):**
   - Follow the timing and talking points in [`DEMO_VIDEO_SCRIPT.md`](DEMO_VIDEO_SCRIPT.md).
   - Start the dashboard locally (`python Source-Code\SIEM-Dashboard\backend\dashboard_server.py`) and show the running interface at `http://127.0.0.1:8080/`.
   - Upload the recording to YouTube as **Unlisted** (or Google Drive as **Anyone with the link can view**).
3. **Upload to Google Drive:**
   - Follow [`GOOGLE_DRIVE_SHARING_CHECKLIST.md`](FINAL-SUBMISSION-PACKAGE/Checklists/GOOGLE_DRIVE_SHARING_CHECKLIST.md).
   - Upload `FINAL-SUBMISSION-PACKAGE/` to Google Drive and ensure permission is set to **"Anyone with the link can view"**.
   - Test the link in an **Incognito Window**.
4. **Submit Internship Portal Form:**
   - Paste the Google Drive folder link.
   - Paste the GitHub repository link: `https://github.com/kallayilaiswarya-code/elevance-cybersecurity-internship-portfolio-3..git`
   - Paste the live portfolio link: `https://kallayilaiswarya-code.github.io/elevance-cybersecurity-internship-portfolio-3../`
   - Paste the demo video link.
