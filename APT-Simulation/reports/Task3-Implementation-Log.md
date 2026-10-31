# Task 3: Multi-Stage APT Simulation & Response — Implementation Log

**Author:** AI-assisted preparation; no independent human reviewer
**Student:** Aiswarya
**Internship Project:** Elevance Health SOC Internship — Task 3
**Project Path:** `APT-Simulation`
**Date of Execution:** 2026-10-24
**Operating System:** Windows 11 Home / Pro (64-bit)
**Execution Shell:** Windows PowerShell 5.1 / MSYS2 Python 3.12.11

---

## 1. Overview & Purpose

This Implementation Log serves as the permanent, verifiable audit trail of all commands, environment checks, detection script runs, detection rule validations, and incident response artifact generation conducted for **Internship Task 3: "Simulate and respond to a multi-stage Advanced Persistent Threat (APT) using open-source SOC tools."**

In accordance with strict SOC evidentiary standards:
- All commands, working directories, execution timestamps, and exit codes are recorded verbatim.
- Original project files were fingerprinted and backed up before testing.
- No live compromise, destructive attack, or unauthorized software installation was performed.
- All detection results are clearly delineated between synthetic training simulations and verified local tool executions.

---

## 2. Chronological Execution Log

### 2.1 Stage 1: Environment & Virtual Machine Audit

#### Step 1.1: Physical Memory & Storage Space Audit
- **Timestamp:** `2026-10-24T20:27:26Z`
- **Working Directory:** `local user directory`
- **Command:**
  ```powershell
  Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory; Get-PSDrive C | Select-Object Free, Used
  ```
- **Exit Code:** `0`
- **Output:**
  - Total Visible Memory: `8,046,284 KB` (~7.67 GB)
  - Free Physical Memory: `2,673,776 KB` (~2.55 GB)
  - Drive C Free Space: `56,060,567,552 bytes` (~52.2 GB free)
- **SOC Assessment:** Host physical memory is severely constrained. With only ~2.55 GB RAM available, running a multi-gigabyte virtualized SIEM (such as Security Onion requiring 16 GB, or an all-in-one Wazuh manager requiring 4–8 GB) would cause severe swapping, hypervisor crash, or Windows host instability.

#### Step 1.2: VirtualBox Virtual Machine Inspection
- **Timestamp:** `2026-10-24T20:27:39Z`
- **Command:**
  ```powershell
  & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list vms; & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list runningvms
  ```
- **Exit Code:** `0`
- **Output:**
  - Registered VMs: `"Kali Linux" {3d008d85-245f-4167-8148-b071395e8071}`, `"Ubuntu_Honeypot" {54f694c1-8a91-45c8-92a5-faa362197965}`
  - Running VMs: None (both powered off)
- **Detailed VM Hardware Inspection:**
  - `Kali Linux`: 5,070 MB RAM, 2 vCPUs, 8.72 GB VDI disk (`Kali Linux.vdi`). Last booted 2026-06-11.
  - `Ubuntu_Honeypot`: 2,048 MB RAM, 1 vCPU, 8.00 GB VDI disk (`Ubuntu_Honeypot.vdi`). Last booted 2026-10-13.
- **Decision:** Starting Kali (5 GB RAM) exceeds free host RAM. Starting Ubuntu (2 GB) leaves <550 MB RAM for Windows and lacks sufficient memory for an in-guest Wazuh stack. Both VMs were kept safely powered off.

#### Step 1.3: Security Binaries & Container Engine Audit
- **Timestamp:** `2026-10-24T20:27:54Z`
- **Command:**
  ```powershell
  Get-Command docker, wazuh-agent, python, python3, pip, yara, sigma -ErrorAction SilentlyContinue
  ```
- **Exit Code:** `0`
- **Output:**
  - `python.exe`: `C:\msys64\mingw64\bin\python.exe` (v3.12.11)
  - `yara.exe`: `YARA executable` (v4.5.5)
  - `pip`: Available inside virtualenv `local user directory\venv\bin\pip.exe` (v25.0.1)
  - `docker`, `wazuh`, `sigma-cli`: Not installed on host.
  - `wsl.exe -l -v`: WSL installed, but 0 Linux distributions registered.

#### Step 1.4: Existing Project Inventory & Cryptographic Baseline
- **Timestamp:** `2026-10-24T20:32:20Z`
- **Command:**
  ```powershell
  Get-ChildItem -Recurse "APT-Simulation" | Where-Object { -not $_.PSIsContainer } | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)`t$($_.Length)`t$($_.FullName)" }
  ```
- **Baseline Cryptographic Fingerprints:**
  - `evidence\yara-training-marker.txt` (25 B): `481006E97663432D110638E3E5A850EACD63C3F738E27B855F95FDE84A7E9D18`
  - `logs\apt-events.jsonl` (1,550 B): `C0E00BD83F2A98C5A1092C367AA843372210DBED623FD8C33ED53370E67CEA40`
  - `reports\apt-alerts.json` (2,192 B): `1B588AC5A1CB83E170F97B32CE2AC4AE145014F78CB14CCB7D011D1B53349420`
  - `reports\APT-Incident-Investigation-Report.md` (4,946 B): `6705506AF48D8E8AEA91865766F46D85BE1EB70F837F8F5B790410E735CAEC23`
  - `reports\incident-timeline.md` (2,528 B): `12B3C7D233A031D113DF40D30DA19F0D41400DB413F06FBB8A5FC4622694DE5B`
  - `rules\sigma\apt-suspicious-powershell.yml` (679 B): `F40EC60360597596667FC7DA4EC8AD770F4E820D429BD071BA1CA3A1247CE4E1`
  - `rules\yara\apt_training_marker.yar` (380 B): `C83D6246248852F2603281CDF9EFFC230387F2045BBD59F6B7F45B205D77C904`
  - `simulation\detect_apt.py` (1,518 B): `FDEDF81F31488E0E117BF20BFA90ED9604C6A6959E6274CCB0928483F29CF4EF`
  - `threat-intelligence\training-iocs.csv` (602 B): `ADA0277CDFDFC0AB38E6C2EEDB171AAFAFD4919356BA9D39E744EE0651F1DCC6`
- **Gap Analysis Generated:** Written to `reports\Task3-Gap-Analysis.md`.

---

### 2.2 Stage 2: Baseline Detection & Rule Validation

#### Step 2.1: Pre-Execution Backup
- **Timestamp:** `2026-10-24T20:35:22Z`
- **Action:** Created directory `backups\stage1_baseline\` and backed up `reports\apt-alerts.json` and `logs\apt-events.jsonl`.
- **Exit Code:** `0`

#### Step 2.2: Execution of Baseline APT Detector
- **Timestamp:** `2026-10-24T20:35:30Z`
- **Working Directory:** `APT-Simulation`
- **Command:**
  ```powershell
  & "C:\msys64\mingw64\bin\python.exe" "simulation\detect_apt.py"
  ```
- **Exit Code:** `0`
- **Output:**
  ```text
  Events analyzed: 6
  Alerts generated: 6
  [MEDIUM] initial_access | LAB-WIN01 | suspicious_email_attachment
  [HIGH] execution | LAB-WIN01 | suspicious_powershell
  [MEDIUM] persistence | LAB-WIN01 | scheduled_task_created
  [HIGH] privilege_escalation | LAB-WIN01 | privilege_change
  [MEDIUM] lateral_movement | LAB-SRV01 | remote_logon
  [HIGH] exfiltration | LAB-SRV01 | unusual_outbound_dns
  Report saved: APT-Simulation\reports\apt-alerts.json
  ```
- **Hash Verification:** Output file hash `1B588AC5A1CB83E170F97B32CE2AC4AE145014F78CB14CCB7D011D1B53349420` matched pre-run backup identically.

#### Step 2.3: YARA 4.5.5 Execution Against Training Marker
- **Timestamp:** `2026-10-24T20:35:47Z`
- **Working Directory:** `APT-Simulation`
- **Command:**
  ```powershell
  & "YARA executable" -m -s "rules\yara\apt_training_marker.yar" "evidence\yara-training-marker.txt"
  ```
- **Exit Code:** `0`
- **Output:**
  ```text
  APT_Training_Marker [description="Demonstration rule for a synthetic APT training marker",author="ElevanceSkills Internship Training",purpose="YARA syntax and workflow demonstration only",warning="Not a malware detection rule"] APT-Simulation\evidence\yara-training-marker.txt
  0x0:$marker: APT_TRAINING_MARKER_001
  ```
- **Result:** Successfully confirmed rule match at offset `0x0`.

#### Step 2.4: Sigma Specification Structure Verification
- **Timestamp:** `2026-10-24T20:36:16Z`
- **Command:** Python standard library schema checker evaluating `rules\sigma\apt-suspicious-powershell.yml` with `utf-8-sig` encoding.
- **Exit Code:** `0`
- **Result:** Verified that all 11 required Sigma top-level keys exist, the UUIDv4 is structurally valid, the condition evaluates to mapped selections, and severity is `high`.

---

### 2.3 Stage 3: Route D SIEM-Compatible Correlation Engine & Rule Suite

#### Step 3.1: Enriched Synthetic Event Creation
- **File:** `simulation\events\synthetic_ecs_events.jsonl`
- **Content:** 12 synthetic events:
  - 6 Positive Kill-Chain Events (`APT-POS-001` through `APT-POS-006`) covering all 6 stages with rich Windows Security (4688, 4672, 4624) and Sysmon (1, 22) fields.
  - 6 Negative Benign Baseline Events (`BENIGN-NEG-001` through `BENIGN-NEG-006`) representing benign Word printing, admin PowerShell, task querying, standard desktop logon, backup share access, and standard Microsoft update DNS resolution.
  - Every event tagged with `"synthetic_flag": true` and `"data_tier": "synthetic_training_simulation"`.

#### Step 3.2: Multi-Stage Sigma Rule Authoring
- Authored 5 additional modular Sigma rules in `rules\sigma\`:
  1. `stage1-initial-access-office-spawn.yml` (T1566.001 / T1059.001)
  2. `stage2-execution-encoded-powershell.yml` (T1059.001 - standardized UTF-8 clone of baseline)
  3. `stage3-persistence-scheduled-task.yml` (T1053.005)
  4. `stage4-privilege-escalation-sensitive-privilege.yml` (T1078 / T1134)
  5. `stage5-lateral-movement-remote-wmi.yml` (T1047 / T1021.002)
  6. `stage6-exfiltration-dns-tunneling.yml` (T1071.004)
  *(Original baseline rule `apt-suspicious-powershell.yml` preserved untouched).*

#### Step 3.3: Engine Execution & Test Diagnosis
- **Initial Test:** During the first test pass of `siem_engine.py`, 4 events produced false negatives because Sigma `Image|endswith: '\powershell.exe'` expects leading backslashes, whereas telemetry containing bare process names (`powershell.exe`) failed standard Python `.endswith('\\powershell.exe')`.
- **Engineering Fix:** Enhanced `match_field_value` in `siem_engine.py` to strip leading path delimiters when comparing against bare process names while preserving full path checks.
- **Final Benchmark Run:**
  - **Timestamp:** `2026-10-24T20:48:53Z`
  - **Command:** `& "C:\msys64\mingw64\bin\python.exe" "simulation\siem_engine.py"`
  - **Exit Code:** `0`
  - **Output Summary:**
    - Events analyzed: 12
    - True Positives: 7 alerts across 6 positive events (100% True Positive Rate)
    - False Positives: 0 alerts across 6 negative events (0% False Positive Rate)
    - False Negatives: 0 missed attacks
    - Benchmark Lucene Queries: 5 out of 5 executed with exact matching hits.
  - **Output File:** `reports\siem-alerts-synthetic.json` (explicitly documented as synthetic).

#### Explanation of Alert Count (7 Alerts for 6 Events):
In Stage 2 (Execution), two Sigma rules exist in `rules\sigma\`:
1. `apt-suspicious-powershell.yml` (the original baseline rule from previous tasks).
2. `stage2-execution-encoded-powershell.yml` (the standardized naming-convention clone).
Both rules evaluated the event `APT-POS-002` and triggered distinct alerts (`SIEM-ALT-0002` and `SIEM-ALT-0003`). Thus, exactly 6 unique attack events triggered detections with zero false negatives and zero false positives.

---

### 2.4 Stage 4: Threat Intelligence & Case Management Templates

#### Step 4.1: Template Creation
- Created `threat-intelligence\misp-training-event.json` conforming to MISP Core JSON format (Event, UUID, Attributes, Categories, Galaxy ATT&CK tags).
- Created `threat-intelligence\thehive-case-template.json` conforming to TheHive 5 Case & Observable API format (7 structured investigation tasks, 6 case observables).
- Both files explicitly declared as offline candidate templates, with warnings that they have not been imported into live servers.

#### Step 4.2: Template Schema & Syntax Validation
- **Timestamp:** `2026-10-24T20:48:45Z`
- **Command:** `& "C:\msys64\mingw64\bin\python.exe" "simulation\validate_templates.py"`
- **Exit Code:** `0`
- **Output:**
  ```text
  [*] Validating MISP Template: misp-training-event.json
      - Attributes parsed: 9
      - Tags parsed: 8
  [+] MISP Template Structure: VALID

  [*] Validating TheHive 5 Template: thehive-case-template.json
      - Investigation tasks parsed: 7
      - Case observables parsed: 6
  [+] TheHive 5 Template Structure: VALID

  [SUCCESS] Both offline candidate templates passed schema and syntax validation.
  ```

---

## 3. Summary of Verification Status

All stages were performed locally, reversibly, safely, and with zero changes to host security settings or VM states.
