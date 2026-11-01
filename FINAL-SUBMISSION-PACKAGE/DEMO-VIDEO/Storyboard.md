# ElevanceSkills SOC Analyst Internship — Master Video Storyboard

**Project:** ElevanceSkills Cybersecurity SOC Analyst Internship
**Presenter:** Aiswarya
**Target Duration:** 3 minutes 45 seconds (225 seconds)
**Resolution:** 1920×1080 Full HD (16:9 Aspect Ratio)
**Visual Aesthetic:** Dark SOC Command Center (Dark Navy `#070b14`, Jet Black `#0a0f1d`, Electric Blue `#2563eb`, Cyan Accent `#00f2fe`, Neon Green Success `#10b981`, Amber Warning `#f59e0b`, Crimson Critical `#ef4444`)
**Typography:** Header: Inter / Segoe UI Semibold (Clean, modern); Monospace: JetBrains Mono / Consolas

---

## Visual & Motion Design System

```
+---------------------------------------------------------------------------------------------------+
|                                  SOC VIDEO DESIGN SPECIFICATION                                   |
+-------------------+-------------------------------------------------------------------------------+
| Background        | Deep navy/black radial gradient (#070b14 -> #0f172a) with subtle animated     |
|                   | digital network nodes, connection lines, and glowing cyber grid.             |
+-------------------+-------------------------------------------------------------------------------+
| Typography        | Clean sans-serif hierarchy; electric cyan titles (#00f2fe), crisp white text  |
|                   | (#f8fafc), and subdued slate gray metadata (#94a3b8).                         |
+-------------------+-------------------------------------------------------------------------------+
| Transitions       | 0.5s smooth cross-fades, sliding timeline reveals, glowing metric pulses,     |
|                   | and animated directional SVG packet flows.                                    |
+-------------------+-------------------------------------------------------------------------------+
| Layout Frame      | Standard 16:9 letterbox safe area (1920x1080), high-contrast data cards,      |
|                   | synchronized subtitle bar along the bottom third.                             |
+-------------------+-------------------------------------------------------------------------------+
```

---

## Detailed Scene-by-Scene Storyboard

### Scene 1: Introduction & Tri-Team Architecture (0:00 – 0:30 | 30 Seconds)
* **Visual Composition (1920×1080):**
  * **0:00–0:10:** High-tech title card with animated cybersecurity emblem, subtle glowing particle net.
    * Text: *"ElevanceSkills Cybersecurity SOC Analyst Internship Capstone"*
    * Subtext: *"Aiswarya — B.Tech Artificial Intelligence & Data Science | Jyothi Engineering College"*
  * **0:10–0:20:** Animated Tri-Team Architecture diagram:
    * Red Team icon (Offensive Emulation & Attack Chains) in crimson.
    * Blue Team icon (Defensive Monitoring & Rule Engineering) in electric blue.
    * Purple Team bridge (Collaborative Gap Closure & MITRE D3FEND) in neon purple/cyan.
  * **0:20–0:30:** Six Internship Tasks Grid appearing in a smooth cascade:
    1. HawkEye Tri-Team Handover
    2. SIEM Correlation Rules
    3. Multi-Stage APT Simulation
    4. HawkEye Network Forensics
    5. HTB Brutus Linux Forensics
    6. Custom SIEM Dashboard
* **Source Assets & Evidence:**
  * `README.md`, `Internship-Report.md` (Architecture overview).
* **On-Screen Badges:** `TLP:CLEAR` | `Academic Portfolio` | `SOC Engineering`.

---

### Scene 2: Custom SIEM Dashboard (0:30 – 1:10 | 40 Seconds)
* **Visual Composition (1920×1080):**
  * **0:30–0:45:** High-resolution capture of the locally running Custom SIEM Dashboard application (`http://127.0.0.1:8080`).
    * Dataset metric cards: `Dataset Events: 79`, `Threat Records: 69`, `Unique Targeted Hosts: 3`, `Attacker Sources: 6`.
  * **0:45–0:55:** Three-Pillar Architecture breakdown (Project Event Dataset):
    * *Pillar 1:* Brute-Force Attacks (57 records — correlated HTB Brutus SSH attempts & synthetic credential stuffing).
    * *Pillar 2:* Privilege Escalation (4 records — backdoor user creation, sudo group modification).
    * *Pillar 3:* Data Exfiltration (7 records — periodic HawkEye SMTP exfiltration bursts & DNS tunneling).
  * **0:55–1:10:** Interactive UI filtering demonstration:
    * Category filter switching between pillars.
    * Instant search for attacker IP `65.2.161.68` and `192.0.2.25`.
    * Telemetry table highlighting normalized Elastic Common Schema (ECS) event fields (`@timestamp`, `event.category`, `source.ip`, `user.name`).
* **Source Assets & Evidence:**
  * `SIEM-Dashboard/evidence/01_dashboard_overview.png`
  * `SIEM-Dashboard/evidence/02_brute_force_view.png`
  * `SIEM-Dashboard/evidence/03_privilege_escalation_view.png`
  * `SIEM-Dashboard/evidence/04_data_exfiltration_view.png`
  * `SIEM-Dashboard/evidence/05_telemetry_table_view.png`
  * `SIEM-Dashboard/data/siem_dashboard_events.jsonl` (79 normalized ECS events in project dataset).
* **On-Screen Badges:** `Locally Running Python Application (< 30 MB RAM)` | `ECS Normalized Dataset` | `Zero Multi-Node Overhead`.

---

### Scene 3: Detection Engineering & Rule Validation (1:10 – 1:50 | 40 Seconds)
* **Visual Composition (1920×1080):**
  * **1:10–1:20:** Split-screen display of the three threat detection vectors:
    1. *Credential Stuffing:* Cardinality threshold on distinct user targets from single source IP within 300s window (MITRE T1110.004).
    2. *DNS Tunneling:* High-length outbound query anomaly filter (> 50 characters, base64 payload) on port 53 (MITRE T1071.004).
    3. *PowerShell Abuse:* Suspicious command-line flag regex (`-[eE][nN]?[cC]?`) for obfuscated base64 execution (MITRE T1059.001).
  * **1:20–1:35:** Custom Detection Rules & Offline Configuration Showcase:
    * Sigma YAML rule (`SIEM-Correlation-Rules/sigma-rules/credential_stuffing.yml`).
    * ElastAlert 2 YAML rule (`rules/elastalert/credential_stuffing.yaml`).
    * Elasticsearch 8.x Query DSL JSON with nested aggregation (`rules/elastic-dsl/credential_stuffing_dsl.json`).
  * **1:35–1:50:** Automated test suite execution graphic:
    * Terminal output showing zero-dependency verification:
      `[PASS] credential_stuffing.yml`, `[PASS] powershell_encoded_command.yml`, `[PASS] suspicious_long_dns_query.yml`.
    * Test result on 10 sample log events (`sample-events.jsonl`): 4 alerts triggered for malicious sequences, 0 false positives on benign baseline queries.
* **Source Assets & Evidence:**
  * `SIEM-Correlation-Rules/sigma-rules/*.yml`
  * `SIEM-Correlation-Rules/rules/elastalert/*.yaml`
  * `SIEM-Correlation-Rules/rules/elastic-dsl/*.json`
  * `SIEM-Correlation-Rules/reports/alerts.json`
* **On-Screen Badges:** `Custom Detection Rules` | `Offline Configurations` | `Validated on 10 Test Events (4 Alerts, 0 FP)`.

---

### Scene 4: HawkEye & Brutus Investigations (1:50 – 2:30 | 40 Seconds)
* **Visual Composition (1920×1080):**
  * **1:50–2:10:** HawkEye Network Forensics (Tasks 1 & 4):
    * Genuine Wireshark packet capture screenshot: Figure 1 & 2 (`01_http_executable_download.png`, Frame 207 HTTP GET for `tkraw_Protected99.exe`).
    * Public IP echo disambiguation graphic: `bot.whatismyipaddress.com` (`66.171.248.178`) returning victim NAT IP `173.66.146.112`.
    * Seven-cycle exfiltration table showing verified ~10-minute cadence (`604.12s–605.76s`) to destination mail server `macwinlogistics.in` (`23.229.162.69:587`).
    * Wireshark screenshot Figure 8 & 9 (`08_smtp_authentication.png`, `09_email_submission.png`) showing cleartext Base64 AUTH and email payload.
  * **2:10–2:30:** HackTheBox Sherlock "Brutus" Linux Forensics (Task 5):
    * Authentication syslog analysis: Attacker IP `65.2.161.68` executing 48 rapid failed SSH logins in 9 seconds.
    * Successful `root` authentication spawning interactive systemd Session `37` at 06:32:44 UTC.
    * Binary `wtmp` analysis via Python script `utmp.py`, highlighting UTC timezone correction.
    * Genuine HTB completion proof badge: `HTB-Brutus-All-8-Tasks-Completed.png.png`.
* **Source Assets & Evidence:**
  * `HawkEye/screenshots/*.png`
  * `FINAL-SUBMISSION-PACKAGE/Datasets/hawkeye_verified_seven_cycle_timeline.csv`
  * `Brutus/Evidence/HTB-Brutus-All-8-Tasks-Completed.png.png`
  * `Brutus/utmp.py`
* **On-Screen Badges:** `4,003 Packets Verified` | `100% Challenge Solved (24/24 HawkEye, 8/8 HTB Brutus)`.

---

### Scene 5: Multi-Stage APT & Threat Intelligence (2:30 – 3:15 | 45 Seconds)
* **Visual Composition (1920×1080):**
  * **2:30–2:45:** Animated 5-Stage APT Cyber Kill Chain:
    * Stage 1: Initial Access (Spear-phishing attachment spawning PowerShell).
    * Stage 2: Execution & Persistence (Encoded command & Scheduled Task creation).
    * Stage 3: Privilege Escalation (`SeDebugPrivilege` abuse).
    * Stage 4: Lateral Movement (Remote WMI process spawn across subnet).
    * Stage 5: Exfiltration (Covert DNS tunneling with TXT queries).
  * **2:45–3:00:** Multi-tier Blue Team response demonstration:
    * Python SIEM correlation engine (`siem_detector.py`) executing against normalized APT telemetry.
    * Terminal output showing 7 staged alerts generated matching the attack chain.
  * **3:00–3:15:** Threat Sharing & Case Management Artifacts:
    * Production-standard TheHive 5 case template (`thehive-case-template.json`) displaying task workflows.
    * RFC-compliant MISP threat sharing JSON (`misp-training-event.json`) with indexed IOCs.
    * YARA signature file (`apt_training_marker.yar`) validating binary detection markers.
* **Source Assets & Evidence:**
  * `APT-Simulation/threat-intelligence/misp-training-event.json`
  * `APT-Simulation/threat-intelligence/thehive-case-template.json`
  * `APT-Simulation/rules/sigma/*.yml`
  * `APT-Simulation/rules/yara/apt_training_marker.yar`
* **On-Screen Badges:** `Offline Calibrated Simulation` | `MISP / TheHive Ready` | `NIST SP 800-61 Aligned`.

---

### Scene 6: Conclusion & Professional Reflection (3:15 – 3:45 | 30 Seconds)
* **Visual Composition (1920×1080):**
  * **3:15–3:30:** Portfolio Synthesis & Technical Toolkit Grid:
    * Technical skills acquired: Packet Forensics (Wireshark), Host Auditing (`auth.log`/`wtmp`), Detection Engineering (Sigma/ElastAlert/DSL), Incident Response (NIST SP 800-61), and Custom Telemetry Dashboarding.
    * Academic synergy: Intersecting Artificial Intelligence, Data Science normalization, and Cybersecurity operations.
  * **3:30–3:45:** Final Professional Outro Card:
    * ElevanceSkills Internship Capstone Complete.
    * Student: Aiswarya | Jyothi Engineering College (Autonomous), Thrissur.
    * Clean thank-you message with animated glowing perimeter shield.
* **Source Assets & Evidence:**
  * `Consolidated-Internship-Report.pdf`, `README.md`.
* **On-Screen Badges:** `Capstone Verified` | `ElevanceSkills 2026` | `Thank You`.
