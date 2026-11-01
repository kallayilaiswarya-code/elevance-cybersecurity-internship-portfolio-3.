# ElevanceSkills SOC Analyst Internship — Video Production Notes

**Document Reference:** ELEV-SOC-DEMO-PROD-2026-FINAL
**Target Video Duration:** 3 minutes 45 seconds (225 seconds)
**Resolution:** 1920×1080 Full HD (16:9 widescreen)
**File Format:** MP4 (H.264 / AAC, target size < 100 MB for portal compliance)
**Auditor / Presenter:** Aiswarya

---

## 1. Source Evidence Mapping by Scene

| Scene | Duration | Authentic Project Source Files | Verified Evidence Type |
|:---|:---:|:---|:---|
| **Scene 1: Introduction** | 0:00–0:30 | • `README.md`<br>• `Internship-Report.md` | Academic metadata, internship scope, Tri-Team architecture diagram. |
| **Scene 2: SIEM Dashboard** | 0:30–1:10 | • `SIEM-Dashboard/evidence/*.png` (5 high-res captures)<br>• `SIEM-Dashboard/backend/dashboard_server.py`<br>• `SIEM-Dashboard/frontend/index.html`<br>• `SIEM-Dashboard/data/siem_dashboard_events.jsonl` | **Locally running application** on `http://127.0.0.1:8080` ingesting 79 normalized ECS events from the project dataset across 3 pillars. |
| **Scene 3: Detection Engineering & Rule Validation** | 1:10–1:50 | • `SIEM-Correlation-Rules/sigma-rules/*.yml`<br>• `SIEM-Correlation-Rules/rules/elastalert/*.yaml`<br>• `SIEM-Correlation-Rules/rules/elastic-dsl/*.json`<br>• `SIEM-Correlation-Rules/reports/alerts.json` | Custom detection rules and offline configurations; tested on 10 sample log events, generating 4 alerts and 0 false positives. |
| **Scene 4: HawkEye & Brutus** | 1:50–2:30 | • `HawkEye/screenshots/*.png` (10 Wireshark captures)<br>• `FINAL-SUBMISSION-PACKAGE/Datasets/hawkeye_verified_seven_cycle_timeline.csv`<br>• `Brutus/Evidence/HTB-Brutus-All-8-Tasks-Completed.png.png`<br>• `Brutus/utmp.py` | Genuine Wireshark packet analysis (4,003 packets, 7 cycles to `macwinlogistics.in:587`), and HackTheBox SSH brute-force analysis (48 attempts, root Session 37). |
| **Scene 5: Multi-Stage APT** | 2:30–3:15 | • `APT-Simulation/threat-intelligence/thehive-case-template.json`<br>• `APT-Simulation/threat-intelligence/misp-training-event.json`<br>• `APT-Simulation/rules/sigma/*.yml`<br>• `APT-Simulation/rules/yara/apt_training_marker.yar`<br>• `APT-Simulation/reports/siem-alerts-synthetic.json` | 5-stage APT attack chain, Python detection engine output (7 alerts), and offline candidate objects for TheHive 5 and MISP. |
| **Scene 6: Conclusion** | 3:15–3:45 | • `Consolidated-Internship-Report.pdf`<br>• `FINAL_SUBMISSION_CHECKLIST.md` | Technical competencies summary, AI/cybersecurity synergy, and professional outro. |

---

## 2. Evidentiary Transparency & Disclosure Standards

To ensure complete adherence to professional SOC audit standards:
1. **Locally Running Dashboard (Task 6):**
   * The custom SIEM dashboard is demonstrated as a locally running application using the lightweight Python HTTP server (`dashboard_server.py`) and HTML5/JS frontend (`index.html`).
   * It ingests the project's offline event dataset (`siem_dashboard_events.jsonl`) containing 79 ECS-normalized events. It is explicitly noted that these are project dataset events rather than live network traffic.
2. **Custom Detection Rules & Offline Configurations (Tasks 2 & 3):**
   * Sigma, ElastAlert, and Elastic Query DSL files are described as **custom detection rules and offline configurations**, avoiding any implication of a deployed production enterprise cluster.
   * The validation suite evaluated 10 test log events in `sample-events.jsonl`, generating 4 alerts for malicious sequences and 0 false positives on benign baseline events.
   * TheHive 5 case templates (`thehive-case-template.json`) and MISP threat sharing events (`misp-training-event.json`) are accurately labeled as **offline candidate configurations**, demonstrating zero false claim of running live multi-node enterprise clusters on a 7.67 GB RAM workstation.
3. **Genuine Challenge Forensics (Tasks 4 & 5):**
   * HawkEye findings strictly reference empirical packet evidence from `stealer.pcap` (4,003 packets, destination `23.229.162.69:587` resolving from `macwinlogistics.in`, cleartext Base64 authentication).
   * Brutus findings strictly reflect the HackTheBox Sherlock `auth.log` and binary `wtmp` artifact analysis with UTC normalization.

---

## 3. Production Methodology & Technical Options

### Option A: Interactive Automated HTML5 Presentation (Recommended)
An automated, high-resolution (1920×1080) presentation player (`presentation_player.html`) is authored with:
* Real-time canvas particle network animation in dark navy/cyan.
* Automated 225-second (3:45) transition timeline with synchronized subtitles matching the narration script.
* Embeds of all authentic screenshots, animated attack diagrams, and live dashboard views.
* Runs in Microsoft Edge in full-screen (`F11`) with zero external software required.

### Option B: Screen Recording Capture (For Generating MP4)
Since Windows 11 does not ship with a command-line `ffmpeg.exe` encoder by default:
1. **Windows Built-in Screen Recorder (Windows Game Bar):**
   * Launch `presentation_player.html` in Microsoft Edge and press `F11` (Full Screen 1920×1080).
   * Press `Win + Alt + R` to record the screen with audio narration.
   * The resulting video is saved directly to `C:\Users\aiswarya\Videos\Captures\` as an optimized 1080p MP4 file.
2. **Microsoft Clipchamp (Pre-installed Windows 11 App):**
   * Open Clipchamp, import the recorded video and voiceover, and export as 1080p MP4 directly into `FINAL-SUBMISSION-PACKAGE/DEMO-VIDEO/SOC_Internship_Demo.mp4`.
3. **Portable FFmpeg (If approved):**
   * If a portable `ffmpeg.exe` binary is provided, an automated script can stitch individual 1080p slide renders into `SOC_Internship_Demo.mp4` programmatically.

---

## 4. Pre-Production Quality Checklist

- [x] Target duration verified at 3 minutes 45 seconds (225 seconds).
- [x] Aspect ratio strictly 16:9 (1920×1080 Full HD).
- [x] Palette compliant with SOC dark mode (Navy `#070b14`, Cyan `#00f2fe`, Blue `#2563eb`).
- [x] Script word count calibrated to ~520 words (~138 WPM) for natural, unhurried delivery.
- [x] All 6 internship tasks represented in chronological sequence.
- [x] Zero fabricated data, unverified packet numbers, or false infrastructure claims.
- [x] All authentic evidence screenshots and datasets mapped directly from repository directories.
