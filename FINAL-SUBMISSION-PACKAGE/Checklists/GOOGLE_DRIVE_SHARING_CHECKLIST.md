# Google Drive Public Sharing & Submission Checklist

**Document Reference:** ELEV-CHECKLIST-DRIVE-2026-FINAL
**Student Intern:** Aiswarya
**Degree / Branch:** B.Tech in Artificial Intelligence & Data Science
**Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Internship Role:** SOC Analyst & Cybersecurity Intern (ElevanceSkills)

---

> [!IMPORTANT]
> **SAFETY & PERMISSION DISCLOSURE:**
> Never upload executable malware (`.exe`), live attack scripts, or unredacted raw password dumps to Google Drive, as automated scanning daemons may flag the account. The `FINAL-SUBMISSION-PACKAGE` directory has been fully sanitized and is safe for academic upload.

---

## 1. Pre-Upload Safety & File Verification

Before uploading to Google Drive, verify that the submission package contains only sanctioned files:
- [x] **No Executable Malware:** `tkraw_Protected99.exe` is excluded.
- [x] **No Large PCAPs:** `stealer.pcap` is excluded (hashes preserved in PDF report).
- [x] **No Raw System DBs:** `wtmp` and `auth.log` are excluded (line citations preserved in PDF report).
- [x] **No Plaintext Passwords:** Lab challenge credentials are sanitized with descriptive redaction placeholders.
- [x] **Valid PDF Reports:** All 7 PDFs open cleanly and have verified file sizes.
- [x] **Clean Datasets:** CSV and JSONL files contain only sanitized synthetic or aggregated telemetry.

---

## 2. Recommended Google Drive Folder Organization

Create a dedicated parent folder on Google Drive named:
`Aiswarya_ElevanceSkills_SOC_Internship_Submission/`

Upload the contents of `FINAL-SUBMISSION-PACKAGE/` with the following structure:
```text
Aiswarya_ElevanceSkills_SOC_Internship_Submission/
├── README.md
├── DEMO_VIDEO_SCRIPT.md
├── PDF-Reports/
│   ├── Consolidated-Internship-Report.pdf
│   ├── Task-1-HawkEye-TriTeam-Report.pdf
│   ├── Task-2-SIEM-Correlation-Rules-Report.pdf
│   ├── Task-3-APT-Incident-Response-Report.pdf
│   ├── Task-4-HawkEye-Network-Forensics-Report.pdf
│   ├── Task-5-HTB-Brutus-Linux-Forensics-Report.pdf
│   └── Task-6-Custom-SIEM-Dashboard-Report.pdf
├── Datasets/
│   ├── training-iocs.csv
│   ├── siem_dashboard_events.jsonl
│   ├── sample-events.jsonl
│   └── synthetic_ecs_events.jsonl
├── Detection-Rules-and-Configs/
├── Source-Code/
├── Evidence/
└── Checklists/
```

---

## 3. Link Sharing Permission Configuration (Step-by-Step)

Follow these steps to ensure mentors and academic evaluators can access the submission without access request friction:

1. **Right-Click the Parent Folder:**
   - In Google Drive, locate `Aiswarya_ElevanceSkills_SOC_Internship_Submission/`.
   - Right-click the folder and select **Share** $\rightarrow$ **Share**.
2. **Modify General Access Settings:**
   - Under the **"General access"** section, click the dropdown menu (which defaults to *"Restricted"*).
   - Change the setting to **"Anyone with the link"**.
   - Ensure the role dropdown on the right is set to **"Viewer"** (do NOT set to Editor).
3. **Copy Shareable Link:**
   - Click the **"Copy link"** button.
   - The generated link will look like:
     `https://drive.google.com/drive/folders/XXXXXXXXXXXXXXXXXXXX?usp=sharing`
4. **Incognito / Private Window Verification:**
   - Open a new **Incognito / Private Browsing window** where you are not logged into your Google account.
   - Paste the copied Google Drive link into the address bar and press Enter.
   - **Verification Checks:**
     - Does the folder open immediately without prompting for Google account login?
     - Are all subfolders (`PDF-Reports`, `Datasets`, `Source-Code`) visible?
     - Can you click and preview `Consolidated-Internship-Report.pdf` directly in Google Drive viewer?
     - Can you download a sample file without permission errors?

---

## 4. Final Submission Form Checklist

When pasting the Google Drive link into the internship submission portal:
- [ ] Link copied from parent folder with **"Anyone with the link can view"** enabled.
- [ ] Verified in Incognito mode.
- [ ] GitHub repository URL verified: `https://github.com/kallayilaiswarya-code/elevance-cybersecurity-internship-portfolio-3..git`
- [ ] Live GitHub Pages portfolio URL verified: `https://kallayilaiswarya-code.github.io/elevance-cybersecurity-internship-portfolio-3../`
- [ ] Demo video link attached (YouTube Unlisted or Google Drive public link).
