# HawkEye Investigation Log

## Lab Information

**Lab:** CyberDefenders HawkEye

**Evidence file:** stealer.pcap

**File type:** PCAP (packet capture)

**File size:** 2,454,198 bytes

**Investigation objective:** Reconstruct the network activity associated with the HawkEye stealer/keylogger incident and identify relevant evidence.

---

## Step 1 — Obtaining the Evidence

**Action:** Downloaded the HawkEye lab files from CyberDefenders.

**Downloaded archive:** 91-hawkeye.zip

**Action:** Extracted the archive using the password provided by CyberDefenders.

**Finding:** The extracted lab contained a network capture named `stealer.pcap`.

**Action:** Copied `stealer.pcap` into the project's `evidence` directory for analysis.

**Tool:** Windows PowerShell / File Explorer

**Evidence location:**

`evidence/stealer.pcap`

---

## Investigation Steps

### Step 2

**Action:**

Opened `stealer.pcap` in Wireshark and reviewed the packet capture, IPv4 endpoints, and protocol hierarchy.

**Tool:** Wireshark

**Observation:**

The capture contained 4,003 packets with communication between internal and external hosts. TCP traffic represented the majority of the packets. HTTP and SMTP traffic were identified as important areas for further investigation.

**Evidence/Screenshot:**

Relevant evidence is documented in the screenshots stored in:

`screenshots/`

---

### Step 3

**Action:**

Followed relevant HTTP and SMTP streams to reconstruct the network activity associated with the incident.

**Tool:** Wireshark

**Observation:**

The investigation identified an HTTP executable download followed by repeated external communication and SMTP message-submission activity containing HawkEye keylogger/password-log information.

**Evidence/Screenshot:**

Relevant screenshots are referenced in the findings below.

---

# Important Findings

## 1. Initial PCAP Observations

- PCAP file: `stealer.pcap`
- Total packets: 4,003
- Internal IP observed: `10.4.10.132`
- Internal IP observed: `10.4.10.4`
- TCP traffic is present.
- Kerberos (KRB5) traffic is visible.
- TCP port 88 is being used in the displayed traffic.
- The first displayed packets show communication between `10.4.10.132` and `10.4.10.4`.

---

## 2. IPv4 Endpoint Analysis

Wireshark's IPv4 Endpoints view shows multiple internal and external IPv4 addresses in the capture.

Key observed endpoints:

- `10.4.10.132` — 4,003 packets, approximately 2 MB
- `10.4.10.4` — 513 packets, approximately 114 kB
- `10.4.10.2` — 42 packets, approximately 5 kB
- `10.4.10.255` — 30 packets, approximately 3 kB
- `23.229.162.69` — 280 packets, approximately 39 kB
- `66.171.248.178` — 63 packets, approximately 5 kB
- `216.58.193.131` — 20 packets, approximately 8 kB
- `217.182.138.150` — 2,947 packets, approximately 2 MB

The capture also contains multicast/broadcast traffic.

At this stage, endpoint frequency alone is not sufficient to determine whether an address represents the victim, attacker, command-and-control server, or another service.

---

## 3. Protocol Hierarchy Analysis

Wireshark Protocol Hierarchy Statistics show that the capture contains 4,003 packets.

Key protocol observations:

- TCP: 3,734 packets (93.3%)
- UDP: 246 packets (6.1%)
- HTTP: 16 packets (0.4%)
- SMTP: 147 packets (3.7%)
- NetBIOS Session Service: 118 packets (2.9%)
- SMB2: 112 packets (2.8%)
- Kerberos: 18 packets (0.4%)
- TLS: 9 packets (0.2%)

The most notable observation is HTTP traffic. Although HTTP represents only 16 packets (0.4% of the packets), it accounts for approximately 2,027,645 bytes, or 84.8% of the captured bytes.

This makes the HTTP traffic a high-priority area for further investigation. At this stage, no conclusion is made about whether the HTTP traffic represents malicious communication or data exfiltration.

---

## 4. HTTP Stream 14 — Executable Download

Wireshark Follow HTTP Stream identified Stream 14 containing an HTTP executable download.

**Observed request:**

```text
GET /proforma/tkraw_Protected99.exe HTTP/1.1
