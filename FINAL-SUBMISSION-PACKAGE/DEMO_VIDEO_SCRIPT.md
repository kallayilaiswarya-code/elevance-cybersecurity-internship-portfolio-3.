# ElevanceSkills SOC Internship — Demo Video Presentation Script
## 2–5 Minute Technical Walkthrough: SOC Engineering, Cyber Threat Forensics & Telemetry Dashboarding

**Author / Presenter:** Aiswarya
**Degree / Branch:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science
**Academic Institution:** Jyothi Engineering College (Autonomous), Thrissur, Kerala
**Internship Role:** SOC Analyst & Cybersecurity Intern (ElevanceSkills)
**Target Video Duration:** 3 minutes 45 seconds (Acceptable Range: 2:00 – 5:00 minutes)
**Video Resolution:** 1080p Full HD (1920×1080, 30 or 60 FPS)
**Audio Target:** Clear microphone narration, minimal background noise
**Recording Mode:** Split screen or full-screen capture showing VS Code / PowerShell on the left and Web Browser (Chrome/Edge) on the right

---

> [!IMPORTANT]
> **LIVE DEMONSTRATION MANDATE:**
> In accordance with strict SOC integrity standards, this demonstration must show **the actual running SIEM dashboard backend and frontend**, genuine test executions, and authentic forensic evidence. Never present static slides or simulated mockups in place of running software.

---

## Chronological Presentation Timeline

| Time Index | Segment Title | Core Visual Focus | Spoken Narration Objective |
|:---:|:---|:---|:---|
| **0:00 – 0:30** | **Project & Portfolio Introduction** | Live GitHub Portfolio (`index.html`) | Introduce student, institution, internship scope, and 6 core SOC tasks. |
| **0:30 – 1:15** | **HawkEye Network Forensics (Tasks 1 & 4)** | Wireshark screenshots & PCAP findings | Explain malware download, IP lookup, SMTP exfiltration, and 10-min interval. |
| **1:15 – 1:55** | **HTB Brutus Linux Host Forensics (Task 5)** | `auth.log`, `utmp.py`, & HTB badge | Explain 48 failed SSH attempts, root Session 37, backdoor `cyberjunkie`, UTC fix. |
| **1:55 – 2:35** | **Detection Engineering & SIEM Rules (Task 2)** | Rule files & Python terminal execution | Run `detect.py`, show Credential Stuffing, DNS Tunneling, and PowerShell rules. |
| **2:35 – 3:05** | **Multi-Stage APT & SOAR Artifacts (Task 3)** | Terminal test & MISP/TheHive JSON | Demonstrate `siem_engine.py` (7 alerts) and explain offline template compliance. |
| **3:05 – 4:05** | **Live Custom SIEM Dashboard (Task 6)** | **Running Web Browser (`localhost:8080`)** | **Demonstrate live running dashboard: 3 pillars, filters, KPIs, and event inspector.** |
| **4:05 – 4:35** | **Technical Decisions & Hardware Limits** | VS Code / Dual-Mode Architecture | Explain memory optimization (7.67 GB RAM) and conclude professionally. |

---

## Detailed Word-for-Word Script & Action Guide

---

### [0:00 – 0:30] Segment 1: Project & Portfolio Introduction

* **Visual Action:**
  * Screen shows the web browser open to the live portfolio landing page (`index.html` or GitHub Pages).
  * Smoothly scroll past the hero header, academic credentials, and the six-task navigation matrix.
* **Spoken Narration:**
  > *"Hello everyone. My name is Aiswarya, an undergraduate student pursuing my Bachelor of Technology in Artificial Intelligence and Data Science at Jyothi Engineering College, affiliated with APJ Abdul Kalam Technological University.*
  >
  > *Today, I am presenting my final capstone portfolio for the ElevanceSkills Cybersecurity SOC Analyst Internship. Over the course of this internship, I completed six rigorous, hands-on tasks simulating the full operational lifecycle of a modern Security Operations Center—ranging from network packet forensics and Linux host intrusion analysis to custom SIEM correlation engineering and telemetry visualization."*

---

### [0:30 – 1:15] Segment 2: HawkEye Network Forensics (Tasks 1 & 4)

* **Visual Action:**
  * Switch tab to `HawkEye/cyberdefenders-hawkeye/hawkeye-lab-report.md` or PDF report.
  * Show Wireshark packet capture screenshots: Figure 1 (Frame 204 DNS query), Figure 2 (HTTP download), Figure 4 (WhatIsMyIP response payload), and Figure 7 (SMTP transmission).
* **Spoken Narration:**
  > *"In Tasks 1 and 4, I analyzed the CyberDefenders HawkEye keylogger intrusion from a 4,003-packet PCAP capture using Wireshark.*
  >
  > *From the raw packets, I carved the malicious Windows executable `tkraw_Protected99.exe` downloaded over HTTP from `217.182.138.150`. Following payload staging, the malware executed automated reconnaissance via `bot.whatismyipaddress.com`, which returned the victim's true public IP—`173.66.146.112`.*
  >
  > *The malware then initiated encrypted and authenticated SMTP communication to `23.229.162.69` on port 587, systematically transmitting keylogger dumps. By calculating timestamp deltas across all 7 transmission cycles, I determined an exact automated beacon cadence of 604 to 606 seconds—precisely 10 minutes. I solved 100% of the 24 forensic challenge questions and authored dedicated Red, Blue, and Purple Team reports."*

---

### [1:15 – 1:55] Segment 3: HTB Brutus Linux Host Forensics (Task 5)

* **Visual Action:**
  * Switch window to `Brutus/reports/Task-5-HTB-Brutus-Lab-Report.md`.
  * Highlight the timeline table and the genuine HTB 8/8 completion proof badge screenshot (`HTB-Brutus-All-8-Tasks-Completed.png.png`).
* **Spoken Narration:**
  > *"Moving to Task 5, I investigated an SSH intrusion on a Linux server from Hack The Box Sherlock 'Brutus'.*
  >
  > *Correlating 385 lines of `auth.log` syslogs with the binary login database `/var/log/wtmp`, I identified external attacker IP `65.2.161.68` executing a high-velocity dictionary brute force—generating 48 failed logins across 5 accounts in just 9 seconds before guessing the `root` password.*
  >
  > *The attacker spawned interactive systemd Session `37` at 06:32:44 UTC. A key technical challenge was resolving an initial 5.5-hour timezone discrepancy in `utmp.py` by converting raw epoch timestamps to UTC using `time.gmtime()`. I traced the attacker establishing persistence by creating local user `cyberjunkie`, adding them to the administrative `sudo` group, and downloading a post-exploitation script via `curl linper.sh`. All 8 HTB challenge questions were verified and solved."*

---

### [1:55 – 2:35] Segment 4: SIEM Correlation Rules & Detection Engine (Task 2)

* **Visual Action:**
  * Open PowerShell terminal inside `SIEM-Correlation-Rules/`.
  * Run the command:
    ```powershell
    python validate_sigma.py; python validate_elastalert.py; python validate_elastic_dsl.py
    ```
  * Show all PASS outputs. Then execute:
    ```powershell
    python detect.py; python credential_stuffing_correlation.py
    ```
* **Spoken Narration:**
  > *"For Task 2, I engineered production SIEM correlation rules detecting three widespread threat vectors: Credential Stuffing, DNS Tunneling, and Obfuscated PowerShell.*
  >
  > *To ensure true multi-platform interoperability, each rule was authored in three industry standards: Sigma YAML, ElastAlert 2 YAML, and native Elasticsearch 8.x Query DSL JSON with sliding-window cardinality aggregations.*
  >
  > *As shown in the terminal, all zero-dependency validators pass completely. When running our detection engine against calibrated synthetic ECS events, the pipeline generated 4 high-fidelity alerts with zero false positives on benign notepad and standard DNS activity. Our sliding-window aggregator correctly identified 5 failed logins across 5 distinct usernames from IP `192.0.2.25`."*

---

### [2:35 – 3:05] Segment 5: Multi-Stage APT Simulation & SOAR Artifacts (Task 3)

* **Visual Action:**
  * In the terminal, switch to `APT-Simulation/simulation/` and run:
    ```powershell
    python validate_templates.py; python siem_engine.py
    ```
  * Point out the 7 alerts generated across the 6 MITRE ATT&CK stages.
* **Spoken Narration:**
  > *"Task 3 tackled an end-to-end simulated Advanced Persistent Threat campaign following NIST SP 800-61 guidelines.*
  >
  > *Our lightweight Python SIEM correlation engine evaluated 12 synthetic events against 7 modular Sigma rules—detecting initial Office macro execution, encoded PowerShell cradles, scheduled task persistence, `SeDebugPrivilege` elevation, remote WMI pivoting, and high-entropy DNS TXT tunneling. The pipeline achieved 100% True Positive Rate and 0% False Positive Rate. Furthermore, RFC-compliant MISP candidate events and TheHive 5 case templates were drafted and validated offline."*

---

### [3:05 – 4:05] Segment 6: Live Custom SIEM Dashboard (Task 6)

* **Visual Action:**
  * In PowerShell terminal, launch the dashboard:
    ```powershell
    cd ..\SIEM-Dashboard
    python backend\dashboard_server.py
    ```
  * Switch to browser and refresh **`http://127.0.0.1:8080/`**.
  * **Interact with the live UI:**
    1. Point to the top KPI cards: Total Events (79), Active Incidents (69), High/Critical Alerts (69).
    2. Scroll through the **Three Attack Pillars**:
       - *Pillar 1:* Show the Brute-Force timeline chart and top attacked usernames (`root`, `server_adm`).
       - *Pillar 2:* Show the Privilege Escalation bar chart (`cyberjunkie` account creation and `sudo` addition).
       - *Pillar 3:* Show the Data Exfiltration byte volume chart (DNS TXT anomalies and recurring SMTP bursts).
    3. Click on the Category Filter buttons: click **"Brute Force"** (table filters to 57 events), click **"Data Exfiltration"** (table filters to 7 events).
    4. Type `65.2.161.68` in the live search bar; show instant table filtering.
    5. Click the **"View JSON"** button on an event row to display the formatted ECS modal inspector.
* **Spoken Narration:**
  > *"Now, let us examine the cornerstone of Task 6: our Custom SIEM Dashboard, running live on local port 8080.*
  >
  > *The dashboard consolidates 79 normalized security events formatted to the Elastic Common Schema, uniting synthetic training logs with real forensic evidence from HawkEye and Brutus with explicit provenance tagging.*
  >
  > *The interface visualizes our three critical attack pillars using responsive Chart.js graphing. All metrics are calculated dynamically from raw event objects—there are zero hardcoded values. In Pillar 1, we observe the exact SSH brute-force attempt spike. In Pillar 2, we track unauthorized account creation and privilege tokens. In Pillar 3, we monitor data exfiltration anomalies.*
  >
  > *Analysts can dynamically filter by attack category, search by IP address or username in real time, and inspect complete raw ECS JSON payloads via interactive modals. For enterprise deployment, a complete Kibana 8.x NDJSON package was also exported."*

---

### [4:05 – 4:35] Segment 7: Technical Decisions, Hardware Limits & Conclusion

* **Visual Action:**
  * Return to the repository `README.md` or `Internship-Report.md`.
  * Highlight the "Transparency & Evidentiary Integrity Disclosure" block.
* **Spoken Narration:**
  > *"A key architectural decision throughout this project was our Zero-Overhead Dual-Mode Strategy. Operating on a Windows 11 workstation with 7.67 GB RAM, running live multi-node Elasticsearch clusters or Security Onion would have caused severe memory starvation.*
  >
  > *Instead, we delivered production-grade compliance through official specifications—Kibana NDJSON, MISP JSON, ElastAlert YAML, and Sigma—verified with lightweight standard-library Python engines consuming less than 30 MB RAM.*
  >
  > *All seven academic PDF reports, sanitized datasets, source code, and checklists are packaged in our final submission directory. This internship has provided me with deep, defensible expertise in threat hunting, forensics, and SOC operations.*
  >
  > *Thank you very much for your time and evaluation."*

---

## 4. Pre-Recording Technical Checklist

- [ ] Python 3.10+ installed and added to PATH.
- [ ] Terminal window opened and sized to half-screen (or secondary monitor).
- [ ] Browser window open to `http://127.0.0.1:8080/` (verify server starts cleanly with `python backend\dashboard_server.py`).
- [ ] Browser zoom set to 100% or 110% for crisp readability on 1080p recording.
- [ ] Microphone input tested; volume levels normalized to avoid clipping.
- [ ] Rehearse spoken timing with a stopwatch to stay comfortably within the 3.5 to 4.0-minute window.
