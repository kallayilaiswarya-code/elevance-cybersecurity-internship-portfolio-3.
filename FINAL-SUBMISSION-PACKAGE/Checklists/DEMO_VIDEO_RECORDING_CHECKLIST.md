# Demo Video Recording, Production & Submission Checklist

**Document Reference:** ELEV-CHECKLIST-VIDEO-2026-FINAL
**Student Intern:** Aiswarya
**Degree / Branch:** B.Tech in Artificial Intelligence & Data Science
**Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Internship Role:** SOC Analyst & Cybersecurity Intern (ElevanceSkills)

---

## 1. Technical Recording Specifications

| Parameter | Required Standard | Recommended Tool / Setting |
|:---|:---|:---|
| **Duration** | **2:00 to 5:00 minutes** (Target: 3:30 to 4:00) | Use a stopwatch or OBS timer overlay. |
| **Video Resolution** | **1080p Full HD (1920×1080)** | OBS Studio / Windows Game Bar (`Win + Alt + R`). |
| **Frame Rate** | **30 FPS or 60 FPS** | Constant frame rate, progressive scan. |
| **Audio Quality** | Clear vocal narration | Headset mic or external USB mic; eliminate background hum. |
| **Screen Layout** | Side-by-side or clean window transitions | Left: Terminal / VS Code; Right: Web browser console. |
| **Browser Zoom** | 100% or 110% | Ensures charts, KPIs, and table columns are easily readable. |

---

## 2. Pre-Recording System Setup Checklist

Before hitting the record button, ensure the local environment is staged:
- [ ] **Start Local SIEM Dashboard:**
  ```powershell
  cd Source-Code\SIEM-Dashboard
  python backend\dashboard_server.py
  ```
- [ ] **Open Browser to `http://127.0.0.1:8080/`:**
  - Verify that the 3 charts load smoothly.
  - Verify that the 4 category buttons work.
  - Test searching `root` or `192.0.2.25` in the search box.
  - Test opening the "View JSON" modal.
- [ ] **Prepare Terminal Window for Task 2 & Task 3 Demonstrations:**
  - Clear terminal screen (`cls`).
  - Pre-test commands:
    ```powershell
    python Source-Code\SIEM-Correlation-Rules\detect.py
    python Source-Code\SIEM-Correlation-Rules\validate_sigma.py
    python Source-Code\APT-Simulation\siem_engine.py
    ```
- [ ] **Open Key Evidence / Report Tabs:**
  - Tab 1: Live GitHub Pages portfolio (`index.html`).
  - Tab 2: `Task-4-HawkEye-Network-Forensics-Report.pdf` (scrolled to Wireshark screenshots).
  - Tab 3: `Task-5-HTB-Brutus-Linux-Forensics-Report.pdf` (showing HTB completion screenshot).
  - Tab 4: `http://127.0.0.1:8080/` (live running dashboard).

---

## 3. During-Recording Action Flow Checklist

Follow the step-by-step guidance in [`DEMO_VIDEO_SCRIPT.md`](../DEMO_VIDEO_SCRIPT.md):
- [ ] **[0:00 - 0:30] Introduction:** Clearly state name, academic institution, B.Tech AI & DS branch, and project title.
- [ ] **[0:30 - 1:15] HawkEye Forensics:** Highlight PCAP packet count (4,003), carved executable `tkraw_Protected99.exe`, victim IP `173.66.146.112`, and 10-minute recurring SMTP exfiltration.
- [ ] **[1:15 - 1:55] Brutus Linux Forensics:** Show HTB 8/8 solved proof badge, explain 48 failed logins, session 37 root login, `utmp.py` UTC resolution, and backdoor user `cyberjunkie`.
- [ ] **[1:55 - 2:35] SIEM Rules & Detection Engine:** Run `validate_sigma.py` and `detect.py` live in terminal, explain 3 rule standards (Sigma, ElastAlert, Elastic DSL).
- [ ] **[2:35 - 3:05] APT Simulation & Threat Intel:** Run `siem_engine.py` showing 7 alerts across the 6 attack stages; reference MISP and TheHive candidate templates.
- [ ] **[3:05 - 4:05] Live SIEM Dashboard Walkthrough (CRITICAL):**
  - Show live KPIs (79 total events, 69 active incidents).
  - Walk through Pillar 1 (Brute-Force), Pillar 2 (Privilege Escalation), and Pillar 3 (Data Exfiltration).
  - Click filter buttons ("Brute Force", "Data Exfiltration") to prove live interactivity.
  - Type in search bar to show real-time table filtering.
  - Click "View JSON" to inspect a raw ECS event modal.
- [ ] **[4:05 - 4:35] Architecture & Conclusion:** Explain zero-overhead dual-mode engineering under 7.67 GB RAM constraints; thank the evaluators.

---

## 4. Post-Recording Review & Hosting Checklist

- [ ] **Playback Quality Check:**
  - Is the audio clear and synchronized with video?
  - Are all terminal commands and text legible on a standard monitor?
  - Is the duration strictly between 2:00 and 5:00 minutes?
- [ ] **Hosting Options:**
  - **Option A (YouTube - Recommended):** Upload to YouTube with visibility set to **"Unlisted"** (evaluators with the link can view; not public in search).
  - **Option B (Google Drive):** Upload MP4 to Google Drive folder, right-click $\rightarrow$ Share $\rightarrow$ Set to **"Anyone with the link can view"**.
- [ ] **Verify Link in Incognito Window:**
  - Open an Incognito window and paste the video link to ensure it plays without requiring permissions or sign-in.
