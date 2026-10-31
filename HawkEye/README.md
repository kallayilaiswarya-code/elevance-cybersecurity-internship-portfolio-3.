# HawkEye Lab — ElevanceSkills Internship

## Lab
CyberDefenders HawkEye

## Purpose
Network forensics investigation of a HawkEye keylogger
data-exfiltration incident.

## Teams
- Red Team — Attack analysis
- Blue Team — Detection and investigation
- Purple Team — Attack and defense handover

## Tools
- CyberDefenders
- Wireshark
- Brim
- Apackets
- MaxMind GeoIP
- VirusTotal
- CyberChef

## Evidence
All screenshots and investigation evidence are stored in the
screenshots/ and evidence/ folders.

## Important
All findings in this repository will be based on my own
HawkEye lab investigation.
## Project Structure

- `red-team/` - Red Team attack-analysis report
- `blue-team/` - Blue Team detection and investigation report
- `purple-team/` - Purple Team handover report
- `cyberdefenders-hawkeye/` - CyberDefenders lab documentation
- `evidence/` - Original PCAP and extracted executable
- `screenshots/` - Investigation screenshots
- `notes/` - Investigation notes, IOCs and timeline

## Key Findings

The investigation identified suspicious executable download activity followed by external-IP discovery and SMTP communication from the internal host `10.4.10.132`.

The observed SMTP activity repeated at approximately 10-minute intervals, providing a useful behavioral detection opportunity.

## Evidence Integrity

The original PCAP and extracted executable are retained in the `evidence/` directory. File hashes were documented separately in the evidence-integrity report.

## Scope

The findings are based on network-level evidence available from the HawkEye PCAP. The investigation does not independently establish the original initial-access method, attacker identity, or complete endpoint activity.
