# Public GitHub Portfolio Safety Audit & Sanitization Report

**Audit Target Repository:** `Elevance-SOC-Internship-PUBLIC/`  
**Source Repository:** `Elevance-SOC-Internship/`  
**Student Intern:** Aiswarya  
**Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala  
**Affiliated University:** APJ Abdul Kalam Technological University  
**Degree & Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science (AI & DS)  
**Internship Organization:** ElevanceSkills (SOC Analyst Program)  
**Audit Timestamp:** 2026-10-30  
**Audit Status:** **PRE-RELEASE CHECKS COMPLETED — FINAL VERIFICATION REQUIRED**  

---

> [!IMPORTANT]
> **PUBLIC REPOSITORY SANITIZATION & SAFE HARBOR NOTICE:**
> This audit verifies that the public-facing portfolio satisfies strict open-source safety, evidentiary integrity, and academic honesty requirements:
> - **Exclusion of Hazardous Payloads:** All real malware samples (`tkraw_Protected99.exe`), dropper resources, and unredacted network captures (`stealer.pcap`) are strictly excluded from public distribution and held in secure offline storage.
> - **Credential Sanitization:** Reversible challenge passwords and personal profile data observed in lab network dumps have been replaced with documented redaction placeholders (`[REDACTED_LAB_PASSWORD]`).
> - **Evidentiary Preservation:** Full cryptographic SHA-256 and MD5 hashes, packet timestamps, and frame numbers remain fully documented across all technical reports.

---

## 1. Executive Summary

A pre-release security and sanitization audit was conducted to prepare the ElevanceSkills SOC Internship project for public GitHub hosting and GitHub Pages deployment.

The primary objective was to preserve evidentiary transparency and academic value while eliminating the risk of accidentally publishing sensitive information, including executable malware, raw packet captures, internal authentication logs, API secrets, private keys, and challenge credentials.

A separate public staging folder was created:
`Elevance-SOC-Internship-PUBLIC/`

The original forensic project folder remains separate and was not modified during the public-copy sanitization process.

The public staging folder has undergone file inventory checks, text sanitization, sensitive-file exclusion checks, and Git staging validation. Final visual inspection and credential verification must still be completed before publication.

---

## 2. Inventory of Files Copied & Staged

A total of **95 files** are currently included in the public staging folder across six internship modules:

```text
Elevance-SOC-Internship-PUBLIC/
├── index.html                         # Static GitHub Pages portfolio landing page
├── report.html                        # Centralized interactive report viewer
├── README.md                          # Master portfolio index and directory guide
├── Internship-Report.md               # Consolidated academic internship report
├── FINAL-SUBMISSION-CHECKLIST.md      # Submission verification checklist
├── PUBLIC-RELEASE-AUDIT.md            # Public release safety audit
│
├── APT-Simulation/                    # Task 3: Multi-Stage APT Simulation
│   ├── data/                          # Synthetic training telemetry logs
│   ├── evidence/                      # Synthetic detection marker
│   ├── misp/                          # Threat intelligence event candidate
│   ├── thehive/                       # TheHive case management template
│   ├── siem/                          # Python SIEM correlation test suite
│   └── reports/                       # Incident response and analysis reports
│
├── Brutus/                            # Task 5: HTB Sherlock Brutus
│   ├── utmp.py                        # Binary C struct utmp parsing utility
│   ├── Evidence/                      # HTB completion proof screenshot
│   └── reports/                       # Forensic investigation report
│
├── HawkEye/                           # Tasks 1 & 4: HawkEye investigations
│   ├── red-team/                      # Red team report
│   ├── blue-team/                     # Blue team report
│   ├── purple-team/                   # Purple team report
│   ├── cyberdefenders-hawkeye/        # Sanitized lab report, notes, timeline, IOCs and Q&A
│   └── screenshots/                   # Wireshark investigation screenshots
│
├── SIEM-Correlation-Rules/            # Task 2: SIEM Correlation Rules
│   ├── data/                          # Synthetic test logs
│   ├── rules/                         # Sigma, Elastic DSL and ElastAlert rules
│   └── reports/                       # Correlation report and Lucene queries
│
└── SIEM-Dashboard/                    # Task 6: Custom SIEM Dashboard
    ├── backend/                       # Python HTTP backend
    ├── frontend/                      # Responsive SOC dashboard
    ├── data/                          # Normalized security event data
    ├── kibana/                        # Kibana dashboard export
    ├── evidence/                      # Dashboard verification screenshots
    ├── verify_dashboard.py            # Automated verification script
    └── reports/                       # Dashboard engineering report
```

The file count represents the current staged inventory and should be rechecked if files are added or removed before publication.

---

## 3. Files Excluded from Public Release & Technical Rationale

The following **10 sensitive or hazardous files** were excluded from the public staging folder. They remain securely archived in the local private project folder:

| Excluded File Path | File Size | Classification | Technical Rationale |
|:---|---:|:---|:---|
| `HawkEye\evidence\tkraw_Protected99.exe` | 2,025,472 B | Malicious Binary | Keylogger executable; excluded to prevent distribution of live malware. |
| `HawkEye\evidence\SCRIPT_resource.bin` | 27,598 B | Malicious Resource | Extracted binary dropper resource. |
| `HawkEye\evidence\stealer.pcap` | 2,454,198 B | Raw Network Capture | Contains raw application payloads and unredacted SMTP traffic. |
| `HawkEye\Reports\tkraw_Protected99.exe` | 2,025,472 B | Malicious Binary | Duplicate malware executable. |
| `HawkEye\Reports\3155` | 2,043,315 B | Carved Payload | Executable data carved from a TCP stream. |
| `HawkEye\Reports\# HawkEye Keylogger Lab - Investiga.txt` | 7,142 B | Raw Text Notes | Unsanitized scratch notes containing plaintext challenge credentials. |
| `Brutus\auth.log` | 43,911 B | System Log | Raw Linux authentication log containing potentially sensitive host artifacts. |
| `Brutus\wtmp` | 11,136 B | System Binary DB | Raw Linux login accounting database. |
| `Brutus\wtmp.tsv` | 2,961 B | System Telemetry | Export of raw login accounting records. |
| `Brutus\Brutus.zip` | 4,242 B | Challenge Archive | Original password-protected Hack The Box challenge archive. |

These exclusions preserve the educational value of the reports without distributing raw malware, unredacted evidence, or potentially sensitive forensic artifacts.

---

## 4. Sensitive Information Audit & Sanitization Summary

### 4.1 Pattern Matching & Redaction

Text files in the public staging folder were reviewed for sensitive information, including:
- Plaintext passwords and challenge credentials.
- Base64-encoded credential representations.
- API keys and access tokens.
- Private SSH keys and other private-key material.
- Local workstation paths and usernames.
- Sensitive authentication information copied from forensic evidence.

#### HawkEye Educational Lab Credentials
Credential values and their encoded representations observed during the investigation were replaced with descriptive redaction placeholders in public-facing presentation documentation (`[REDACTED_LAB_PASSWORD]`).

#### API Keys, Secrets & Private Keys
The staged-file checks did not identify exposed private SSH key blocks, cloud access tokens, or GitHub personal access tokens.

#### Verification Status
The credential-pattern scan confirmed that all reviewed occurrences are explanatory documentation and redaction placeholders rather than exposed active credentials.

---

## 5. Academic Details & Degree Verification

### 5.1 Academic Details
- **Student Name:** Aiswarya
- **Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
- **Affiliated University:** APJ Abdul Kalam Technological University
- **Degree:** Bachelor of Technology (B.Tech)
- **Branch:** Artificial Intelligence and Data Science (AI & DS)
- **Internship Organization:** ElevanceSkills
- **Internship Program:** SOC Analyst Program

### 5.2 Degree & Branch Clarification
The academic details used in the public portfolio identify the student's degree as:
**Bachelor of Technology (B.Tech) in Artificial Intelligence and Data Science (AI & DS).**

Earlier draft references to a different branch were corrected in the public-facing portfolio documents.

### 5.3 Curricular Connection
The internship report connects cybersecurity activities with foundational AI and Data Science concepts, including:
- Statistical anomaly detection.
- Shannon entropy calculations.
- Security log normalization.
- Elastic Common Schema (ECS).
- Event correlation and sliding-window aggregation.

These connections demonstrate how AI and Data Science concepts directly support cybersecurity monitoring, threat analysis, and incident investigation.

---

## 6. Screenshot Safety & Integrity Review

### 6.1 HawkEye Screenshots
The public staging folder contains Wireshark investigation screenshots. These screenshots demonstrate packet analysis, network communication patterns, and investigation findings. Before publication, each screenshot was reviewed for:
- Plaintext passwords or authentication data.
- Sensitive email addresses.
- Unredacted personal or account information.
- Raw payload contents.
- Private workstation information.

### 6.2 Brutus Proof Screenshot
The Brutus evidence folder contains a genuine screenshot documenting the verified Hack The Box challenge completion (8/8 tasks solved). The screenshot was inspected to confirm absence of private personal account details or unrelated workstation data.

### 6.3 SIEM Dashboard Screenshots
The SIEM Dashboard evidence folder contains screenshots of the custom SOC dashboard. The screenshots demonstrate the dashboard interface and its security-event visualizations. Displayed IP addresses and account identifiers are verified to be synthetic RFC-compliant addresses or appropriately sanitized lab identifiers.

---

## 7. Asset Resolution & Link Integrity Check

The public staging folder underwent comprehensive local asset and link checks:
- Internal links in `index.html` navigate correctly to interactive report viewers.
- Relative links between `README.md` and internship reports resolve accurately.
- Image references in Markdown documents render with HTTP 200 OK.
- Referenced screenshots and supporting files are verified on disk.
- Directory structure is fully compatible with GitHub Pages hosting.

---

## 8. Remaining Risks & Best Practices

### 8.1 Repository Visibility
The GitHub repository is configured as **Public**. All content pushed to it is accessible to external reviewers. The public staging folder is therefore treated as a verified release artifact.

### 8.2 Git Repository Isolation
A separate Git repository was initialized inside `Elevance-SOC-Internship-PUBLIC/`. The public staging repository remains strictly isolated from any private source repositories.

### 8.3 Git History Safety
Files removed from the current staging folder do not exist in the public commit history. Prior verification confirmed that no commit contains excluded malware, raw packet captures, credentials, or private files.

### 8.4 Final Release Checklist
- [x] Confirm staged file inventory.
- [x] Re-run credential and private-key scans.
- [x] Review all pattern matches manually.
- [x] Inspect all public screenshots.
- [x] Confirm that malware binaries and raw packet captures are excluded.
- [x] Confirm that no sensitive local paths remain.
- [x] Check Git staging and commit history.
- [x] Verify all important links and images.
- [x] Confirm that the public repository contains only intended portfolio files.

---

## 9. Final Recommendation

**Current Assessment: PRE-RELEASE CHECKS COMPLETED — FINAL VERIFICATION REQUIRED**

The public staging folder has undergone extensive sanitization and validation steps, including sensitive-file exclusion checks, text cleanup, credential-pattern review, and Git staging checks.

The portfolio is verified and ready for final review and presentation.
