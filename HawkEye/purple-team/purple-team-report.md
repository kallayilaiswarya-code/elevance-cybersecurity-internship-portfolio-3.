# HawkEye - Purple Team Handover Report

## 1. Executive Summary

This report combines the Red Team and Blue Team perspectives of the HawkEye network-forensics investigation.

The purpose of the Purple Team analysis is to connect the observed attack behaviors with corresponding detection opportunities and defensive actions.

The investigation identified the internal host:

`10.4.10.132`

as the primary host involved in the observed network activity.

The main sequence identified in the PCAP was:

DNS resolution
    |
HTTP executable download
    |
External-IP lookup
    |
External HTTP communication
    |
SMTP connection
    |
SMTP authentication
    |
Credential-related email submission
    |
Repeated SMTP activity

The observed behavior is consistent with a compromised Windows host downloading a suspicious executable and subsequently communicating with an external SMTP service. The repeated SMTP activity occurred at approximately 10-minute intervals.

## 2. Investigation Scope

The Purple Team handover is based on network evidence from:

- `stealer.pcap`
- Extracted file: `tkraw_Protected99.exe`
- Internal host: `10.4.10.132`
- Hostname: `Beijing-5cd1-PC`
- DNS server: `10.4.10.4`

The analysis focuses on observable network behavior and does not claim facts that cannot be established from the PCAP.

## 3. Red Team Findings

The Red Team perspective identified the following attack-relevant behaviors:

1. DNS resolution associated with the suspicious activity.
2. HTTP download of `tkraw_Protected99.exe`.
3. Communication with the downloaded file's web host.
4. External-IP discovery through `bot.whatismyipaddress.com`.
5. SMTP communication with `23.229.162.69:587`.
6. Repeated SMTP activity at approximately 10-minute intervals.

The extracted executable was identified using the filename and file hash evidence from the investigation.

SHA-256:

`62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11`

MD5:

`71826BA081E303866CE2A2534491A2F7`

## 4. Blue Team Findings

The Blue Team identified several network-level detection opportunities.

### 4.1 Suspicious Executable Download

An internal host downloaded:

`tkraw_Protected99.exe`

through HTTP from:

`proforma-invoices.com`

The associated IP address was:

`217.182.138.150`

### 4.2 External-IP Lookup

The host contacted:

`bot.whatismyipaddress.com`

This activity can be correlated with other suspicious events occurring shortly afterward.

### 4.3 SMTP Communication

The host established SMTP communication with:

`23.229.162.69:587`

The SMTP server was identified as Exim 4.91.

### 4.4 Periodic Communication

Repeated SMTP activity occurred at approximately 10-minute intervals.

This periodicity provides a behavioral detection opportunity for identifying automated processes.

## 5. Detection-to-Response Handover

| Observed Behavior | Detection Opportunity | Recommended Response |
|---|---|---|
| HTTP executable download | Monitor executable downloads from external domains | Investigate source, file hash and initiating host |
| Suspicious executable | Alert on suspicious file indicators | Isolate host and perform endpoint investigation |
| External-IP lookup | Correlate external-IP services with suspicious downloads | Review surrounding network activity |
| SMTP connection from endpoint | Detect unusual SMTP traffic from user endpoints | Investigate destination, account and process |
| Repeated SMTP activity | Detect periodic outbound connections | Investigate automated or scheduled behavior |
| Multiple related indicators | Correlate network indicators into one incident | Escalate for incident response |

## 6. Key Indicators for Detection

| Indicator Type | Indicator |
|---|---|
| Internal IP | `10.4.10.132` |
| Hostname | `Beijing-5cd1-PC` |
| DNS Server | `10.4.10.4` |
| Download Domain | `proforma-invoices.com` |
| Download IP | `217.182.138.150` |
| Downloaded File | `tkraw_Protected99.exe` |
| File MD5 | `71826BA081E303866CE2A2534491A2F7` |
| File SHA-256 | `62099532750DAD1054B127689680C38590033FA0BDFA4FB40C7B4DCB2607FB11` |
| IP Lookup Domain | `bot.whatismyipaddress.com` |
| SMTP Server | `23.229.162.69` |
| SMTP Port | `587` |
| SMTP Software | `Exim 4.91` |

## 7. Suggested Purple Team Detection Logic

The following detection chain can be used as a correlation model:

External executable download
          +
External-IP lookup
          +
SMTP connection
          +
Repeated periodic communication
          |
          v
Potential automated malicious activity
          |
          v
Investigate endpoint and network evidence

A single event may not be sufficient to identify malicious activity. Correlating several related indicators increases the value of the detection.

## 8. Recommended Defensive Actions

1. Investigate the affected internal host `10.4.10.132`.
2. Search network logs for connections to the identified domains and IP addresses.
3. Search endpoint telemetry for `tkraw_Protected99.exe`.
4. Compare the file hash against available endpoint and malware records.
5. Review unusual outbound SMTP connections from internal workstations.
6. Investigate repeated approximately 10-minute communication patterns.
7. Preserve relevant PCAP, logs and endpoint evidence.
8. If malicious activity is confirmed, isolate the affected host according to the organization's incident-response procedure.
9. Review other hosts for the same indicators.
10. Document findings and update detection rules based on the observed behavior.

## 9. Red-to-Blue Handover

The Red Team findings provide the behaviors that should be reproduced or detected from a defensive perspective.

The Blue Team can use the following observations for detection engineering:

- Suspicious HTTP executable download.
- Known malicious file indicators.
- External-IP discovery.
- Outbound SMTP communication from an internal endpoint.
- Periodic SMTP communication.
- Correlation of multiple indicators within the same host and time window.

The primary handover objective is to convert these observations into repeatable detections and investigation procedures.

## 10. Investigation Limitations

The PCAP provides network-level evidence but does not independently establish:

- The original initial-access method.
- The identity of the attacker.
- Whether the downloaded executable was manually or automatically executed.
- The complete endpoint process tree.
- Persistence mechanisms that did not generate observable network traffic.
- The complete contents of any compromised endpoint.

Therefore, these findings should be interpreted within the scope of the available network evidence.

## 11. Conclusion

The Purple Team analysis connects the observed attack behavior with practical defensive detection opportunities.

The most useful correlation is the sequence of suspicious executable download, external-IP lookup, SMTP communication and repeated approximately 10-minute activity from the same internal host.

These observations provide a foundation for detection engineering, incident investigation and future Red Team/Blue Team validation exercises.

The identified indicators should be treated as investigation leads and correlated with additional endpoint, DNS, proxy, firewall and email telemetry where available.
