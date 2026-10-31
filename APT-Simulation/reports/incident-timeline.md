# APT Incident Timeline

**Case ID:** APT-TRAINING-001
**Environment:** Synthetic lab scenario
**Date:** 13 October 2026
**Evidence status:** Simulated events; not collected from a real compromised system.

| Time (UTC) | Event ID | Stage | Host | Observed event | Initial defensive interpretation |
|---|---|---|---|---|---|
| 09:00:00 | APT001 | Initial access | LAB-WIN01 | Suspicious email attachment opened | Investigate the attachment, email source, and endpoint activity. |
| 09:02:00 | APT002 | Execution | LAB-WIN01 | Encoded PowerShell argument observed | Review the command line and related process events. |
| 09:05:00 | APT003 | Persistence | LAB-WIN01 | Unexpected scheduled task creation | Inspect the task name, action, creator, and creation time. |
| 09:08:00 | APT004 | Privilege escalation | LAB-WIN01 | Unusual privilege change | Verify the account, privilege change, and associated security events. |
| 09:12:00 | APT005 | Lateral movement | LAB-SRV01 | Unusual remote logon | Correlate the logon with source host, account, and authentication records. |
| 09:16:00 | APT006 | Possible exfiltration | LAB-SRV01 | Unusually long DNS query | Examine DNS logs, query patterns, destination, and outbound traffic. |

## Initial assessment

The synthetic event sequence represents a possible multi-stage intrusion progressing from a suspicious attachment to execution, persistence, privilege escalation, remote logon, and a possible data-exfiltration indicator.

The events justify investigation in a training scenario, but they do not independently prove that a real attack occurred. In particular, the unusual DNS query is an indicator requiring validation, not proof of exfiltration.

## Evidence limitations

- All six events were created as synthetic training data.
- The timestamps and host names belong to the scenario.
- No live endpoint, network capture, Wazuh, Security Onion, or Kibana evidence is represented by this timeline.
- Each event requires corroboration from appropriate logs and forensic evidence in a real investigation.

## Recommended defensive follow-up

1. Preserve relevant endpoint, authentication, process, scheduled-task, and DNS logs.
2. Correlate events by timestamp, host, account, and source address.
3. Review suspicious processes and persistence mechanisms in an isolated investigation environment.
4. Validate indicators before blocking or declaring compromise.
5. Document containment, eradication, recovery, and lessons learned if an actual incident is confirmed.
