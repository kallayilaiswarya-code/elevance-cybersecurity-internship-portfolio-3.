# Public GitHub Portfolio Safety Audit & Sanitization Report

**Audit Target Repository:** `Elevance-SOC-Internship-PUBLIC/`
**Source Repository:** `Elevance-SOC-Internship/`
**Student Intern:** Aiswarya
**Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Affiliated University:** APJ Abdul Kalam Technological University
**Degree & Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science (AI & DS)
**Internship Organization:** ElevanceSkills (SOC Analyst Program)
**Audit Timestamp:** 2026-10-30
**Audit Status:** PRE-RELEASE CHECKS COMPLETED — FINAL VERIFICATION REQUIRED

---

## 1. Executive Summary

A pre-release security and sanitization audit was conducted to prepare the ElevanceSkills SOC Internship project for public GitHub hosting and GitHub Pages deployment.

The primary objective was to preserve evidentiary transparency and academic value while reducing the risk of accidentally publishing sensitive information, including executable malware, raw packet captures, internal authentication logs, API secrets, private keys, and challenge credentials.

A separate public staging folder was created:

`Elevance-SOC-Internship-PUBLIC/`

The original forensic project folder remains separate and was not intentionally modified during the public-copy sanitization process.

The public staging folder has undergone file inventory checks, text sanitization, sensitive-file exclusion checks, and Git staging validation. Final visual inspection and credential verification must still be completed before publication.

---

## 2. Inventory of Files Copied & Staged

A total of **95 files** are currently included in the public staging folder across six internship modules.

```text
Elevance-SOC-Internship-PUBLIC/
├── index.html                         # Static GitHub Pages portfolio landing page
├── README.md                          # Master portfolio index and directory guide
├── Internship-Report.md               # Consolidated academic internship report
├── FINAL-SUBMISSION-CHECKLIST.md      # Submission verification checklist
├── PUBLIC-RELEASE-AUDIT.md            # Public release safety audit
│
├── APT-Simulation/                    # Task 3: Multi-Stage APT Simulation
│   ├── data/                          # Synthetic training telemetry logs
│   ├── evidence/                      # Synthetic detection marker
│   ├── misp/                           # Threat intelligence event candidate
│   ├── thehive/                        # TheHive case management template
│   ├── siem/                           # Python SIEM correlation test suite
│   └── reports/                        # Incident response and analysis reports
│
├── Brutus/                            # Task 5: HTB Sherlock Brutus
│   ├── utmp.py                         # Binary C struct utmp parsing utility
│   ├── Evidence/                       # HTB completion proof screenshot
│   └── reports/                        # Forensic investigation report
│
├── HawkEye/                           # Tasks 1 & 4: HawkEye investigations
│   ├── red-team/                       # Red team report
│   ├── blue-team/                      # Blue team report
│   ├── purple-team/                    # Purple team report
│   ├── cyberdefenders-hawkeye/         # Sanitized lab report, notes, timeline, IOCs and Q&A
│   └── screenshots/                   # Wireshark investigation screenshots
│
├── SIEM-Correlation-Rules/            # Task 2: SIEM Correlation Rules
│   ├── data/                           # Synthetic test logs
│   ├── rules/                          # Sigma, Elastic DSL and ElastAlert rules
│   └── reports/                        # Correlation report and Lucene queries
│
└── SIEM-Dashboard/                    # Task 6: Custom SIEM Dashboard
    ├── backend/                        # Python HTTP backend
    ├── frontend/                       # Responsive SOC dashboard
    ├── data/                           # Normalized security event data
    ├── kibana/                         # Kibana dashboard export
    ├── evidence/                       # Dashboard verification screenshots
    ├── verify_dashboard.py             # Automated verification script
    └── reports/                        # Dashboard engineering report
```

The file count represents the current staged inventory and should be rechecked if files are added or removed before publication.

---

## 3. Files Excluded from Public Release & Technical Rationale

The following **10 sensitive or hazardous files** were excluded from the public staging folder. They remain in the local private project folder.

| Excluded File Path | File Size | Classification | Technical Rationale |
|---|---:|---|---|
| `HawkEye\evidence\tkraw_Protected99.exe` | 2,025,472 B | Malicious Binary | Keylogger executable; excluded to prevent distribution of malware. |
| `HawkEye\evidence\SCRIPT_resource.bin` | 27,598 B | Malicious Resource | Extracted binary dropper resource. |
| `HawkEye\evidence\stealer.pcap` | 2,454,198 B | Raw Network Capture | Contains raw application payloads and unredacted SMTP traffic. |
| `HawkEye\Reports\tkraw_Protected99.exe` | 2,025,472 B | Malicious Binary | Duplicate malware executable. |
| `HawkEye\Reports\3155` | 2,043,315 B | Carved Payload | Executable data carved from a TCP stream. |
| `HawkEye\Reports\# HawkEye Keylogger Lab - Investiga.txt` | 7,142 B | Raw Text Notes | Unsanitized scratch notes containing plaintext challenge credentials. |
| `Brutus\auth.log` | 43,911 B | System Log | Raw Linux authentication log containing potentially sensitive host artifacts. |
| `Brutus\wtmp` | 11,136 B | System Binary DB | Raw Linux login accounting database. |
| `Brutus\wtmp.tsv` | 2,961 B | System Telemetry | Export of raw login accounting records. |
| `Brutus\Brutus.zip` | 4,242 B | Challenge Archive | Original password-protected Hack The Box challenge archive. |

These exclusions help preserve the educational value of the reports without distributing raw malware, unredacted evidence, or potentially sensitive forensic artifacts.

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

**HawkEye Educational Lab Credentials:**

Credential values and their encoded representations observed during the investigation were replaced with descriptive redaction placeholders in public-facing documentation.

**API Keys, Secrets & Private Keys:**

The staged-file checks did not identify exposed private SSH key blocks, cloud access tokens, or GitHub personal access tokens.

**Verification Status:**

The credential-pattern scan identified matches that required manual review. The reviewed matches included explanatory documentation and redaction placeholders rather than confirmed exposed passwords.

A final credential scan and manual review must be performed again immediately before the first public commit.

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
- Event correlation and aggregation.

These connections demonstrate how AI and Data Science concepts can support cybersecurity monitoring, threat analysis, and incident investigation.

---

## 6. Screenshot Safety & Integrity Review

### 6.1 HawkEye Screenshots

The public staging folder contains Wireshark investigation screenshots.

These screenshots are intended to demonstrate packet analysis, network communication patterns, and investigation findings.

Before publication, each screenshot must be visually reviewed for:

- Plaintext passwords or authentication data.
- Sensitive email addresses.
- Unredacted personal or account information.
- Raw payload contents.
- Private workstation information.

### 6.2 Brutus Proof Screenshot

The Brutus evidence folder contains a screenshot documenting the reported Hack The Box challenge completion.

The screenshot should be checked for private account details, browser profile information, and unrelated workstation data before publication.

### 6.3 SIEM Dashboard Screenshots

The SIEM Dashboard evidence folder contains screenshots of the custom SOC dashboard.

The screenshots are intended to demonstrate the dashboard interface and its security-event visualizations. Displayed IP addresses and account identifiers should be checked to ensure they are synthetic or appropriately sanitized.

**Important:** Screenshot safety must be established through direct visual inspection. Text-file scanning alone cannot verify the contents of images.

---

## 7. Asset Resolution & Link Integrity Check

The public staging folder underwent local asset and link checks.

The intended checks include:

- Internal links in `index.html`.
- Relative links between `README.md` and internship reports.
- Image references in Markdown documents.
- Availability of referenced screenshots and supporting files.
- Correct directory structure for GitHub Pages hosting.

Before publication, the following should be verified again:

1. Open `index.html` locally in a browser.
2. Navigate through each internship module.
3. Open all major reports.
4. Confirm that images load correctly.
5. Check that no link points to the private source folder or a local workstation path.

A successful local link check does not guarantee that every link will work after GitHub Pages deployment.

---

## 8. Remaining Risks & Best Practices

### 8.1 Repository Visibility

The GitHub repository is currently configured as **Public**.

Because the repository is already public, all content pushed to it may become accessible to other users. The public staging folder must therefore be treated as a release artifact and checked carefully before committing or pushing.

### 8.2 Git Repository Isolation

A separate Git repository was initialized inside:

`Elevance-SOC-Internship-PUBLIC/`

The public staging repository should remain isolated from the private source repository.

The private source repository's `.git` history must not be copied into the public staging folder.

### 8.3 Git History Safety

Files removed from the current staging folder may still exist in Git history if they were committed previously.

Before publication, verify that no earlier commit contains excluded malware, raw packet captures, credentials, or private files.

### 8.4 Open-Source License

An appropriate license, such as MIT for reusable code or a suitable Creative Commons license for documentation, may be considered.

The license should be selected only after checking ownership and usage rights for third-party materials, challenge evidence, screenshots, and external tools.

### 8.5 Final Release Checklist

Before pushing the portfolio:

- [ ] Confirm the staged file count.
- [ ] Re-run credential and private-key scans.
- [ ] Review all remaining pattern matches manually.
- [ ] Inspect all public screenshots.
- [ ] Confirm that malware binaries and raw packet captures are excluded.
- [ ] Confirm that no local workstation paths remain.
- [ ] Check Git staging and commit history.
- [ ] Verify all important links and images.
- [ ] Confirm that the public repository contains only intended portfolio files.

---

## 9. Final Recommendation

**Current Assessment: PRE-RELEASE CHECKS COMPLETED — FINAL VERIFICATION REQUIRED**

The separate public staging folder has undergone several sanitization and validation steps, including sensitive-file exclusion checks, text cleanup, credential-pattern review, and Git staging checks.

The checks performed so far support proceeding to a final release review. They do not, by themselves, establish that every file, screenshot, link, or historical Git object is safe for public distribution.

The portfolio should be committed and published only after the remaining credential checks, screenshot inspection, Git history review, and final staging verification have been completed.

**Release decision:** Pending final verification and student confirmation.