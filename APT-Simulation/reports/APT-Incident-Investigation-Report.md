# APT Incident Investigation Report

## 1. Case Information

- **Case ID:** APT-TRAINING-001
- **Scenario:** Synthetic multi-stage APT simulation
- **Environment:** Local training workspace
- **Status:** Initial analysis completed; no real compromise established
- **Evidence source:** Synthetic JSONL events and locally generated detection alerts

## 2. Objective

To demonstrate how a defensive analyst can identify, correlate, document, and investigate indicators representing a multi-stage intrusion.

## 3. Scenario Summary

Six synthetic events represent initial access, execution, persistence, privilege escalation, lateral movement, and possible exfiltration. The detector analyzed the events and generated six alerts.

The scenario includes two fictional lab hosts: LAB-WIN01 and LAB-SRV01. The events are illustrative and do not establish that the listed actions occurred on real systems.

## 4. Detection Results

| Stage | Host | Event type | Severity assigned by training detector |
|---|---|---|---|
| Initial access | LAB-WIN01 | Suspicious email attachment | Medium |
| Execution | LAB-WIN01 | Suspicious PowerShell | High |
| Persistence | LAB-WIN01 | Scheduled task created | Medium |
| Privilege escalation | LAB-WIN01 | Unusual privilege change | High |
| Lateral movement | LAB-SRV01 | Remote logon | Medium |
| Possible exfiltration | LAB-SRV01 | Unusual outbound DNS | High |

Severity levels are assigned by the custom training script. They are not validated vendor SIEM severity ratings.

## 5. Investigation Findings

### Initial access
A synthetic event records a suspicious email attachment being opened. In a real investigation, review email headers, attachment hashes, endpoint process activity, and the user's actions.

### Execution
An encoded PowerShell argument is reported. Review the original command line, process ancestry, script-block logs, and related endpoint events before determining whether the activity is malicious.

### Persistence
An unexpected scheduled task is reported. Examine the task's creation time, author, action, executable path, and associated account.

### Privilege escalation
An unusual privilege change is reported. Correlate account, process, and security audit records to determine whether privileges were legitimately or improperly changed.

### Lateral movement
A remote logon is reported on LAB-SRV01. Correlate source and destination hosts, account identity, authentication method, and surrounding network activity.

### Possible exfiltration
An unusually long DNS query is reported. Inspect full DNS logs, query frequency, domain reputation, and network traffic. The synthetic event alone does not prove data exfiltration.

## 6. Indicators and Evidence

- **Scenario event IDs:** APT001–APT006
- **Scenario hosts:** LAB-WIN01 and LAB-SRV01
- **Source address:** 192.0.2.50 (documentation-only address used in training)
- **Evidence files:** logs/apt-events.jsonl and reports/apt-alerts.json
- **Timeline:** reports/incident-timeline.md

These are scenario artifacts, not verified indicators from a real incident. No malicious file hash, real attacker infrastructure, or confirmed exfiltrated data was established.

## 7. Incident Response Recommendations

1. **Validate:** Collect original endpoint, authentication, process, scheduled-task, and DNS logs.
2. **Scope:** Identify affected accounts, endpoints, and any related hosts.
3. **Contain:** If a real compromise is confirmed, isolate affected systems according to the organization's response procedure.
4. **Eradicate:** Remove verified malicious persistence and remediate the initial access vector.
5. **Recover:** Restore trusted systems and monitor for recurrence.
6. **Learn:** Document the root cause, detection gaps, and preventive improvements.

These are recommended actions, not actions performed against a real system.

## 8. Tools and Method

- Python 3: parsed synthetic JSONL events and generated alerts.
- PowerShell: created the local training workspace and report files.
- Markdown: documented the investigation timeline and findings.

Wazuh, Security Onion, Kibana, TheHive/Cortex, and MISP were not used to generate the current results. Integration with those platforms remains future work.

## 9. Limitations

- All input events are synthetic.
- No real endpoint telemetry, packet capture, malware sample, or forensic image was analyzed for this scenario.
- Detection thresholds and severity assignments are demonstration logic, not validated production rules.
- No live SIEM ingestion, automated response, or real-world detection effectiveness was tested.

## 10. Conclusion

The exercise demonstrates a basic Python-based workflow for parsing synthetic security events, generating alerts, and documenting a multi-stage intrusion scenario. Further validation with a real lab telemetry source and an open-source SIEM is required before treating the detections as operational security controls.
