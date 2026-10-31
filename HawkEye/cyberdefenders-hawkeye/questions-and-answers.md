# CyberDefenders HawkEye — Questions and Answers

## Lab Information

- Platform: CyberDefenders
- Challenge: HawkEye
- Category: Network Forensics
- Primary tool used: Wireshark
- Capture analyzed: stealer.pcap

## Questions and Answers

### Q1. How many packets does the capture have?

**Answer:** 4003

### Q2. At what time was the first packet captured (UTC)?

**Answer:** 2019-04-10 20:37

### Q3. What is the duration of the capture?

**Answer:** 1:03:41

### Q4. What is the most active computer at the link level?

**Answer:** 0:08:02:1c:47:ae

### Q5. What is the manufacturer of the NIC of the most active system?

**Answer:** Hewlett-Packard

### Q6. Where is the headquarters of the company that manufactured the NIC?

**Answer:** Palo Alto

### Q7. How many computers in the organization were involved?

**Answer:** 3

### Q8. What is the name of the most active computer at the network level?

**Answer:** Beijing-5cd1-PC

### Q9. What is the DNS server IP address?

**Answer:** 10.4.10.4

### Q10. What domain appears in packet 204?

**Answer:** proforma-invoices.com

### Q11. What IP address does the domain resolve to?

**Answer:** 217.182.138.150

### Q12. What country is the IP address located in?

**Answer:** France

### Q13. What operating system is identified?

**Answer:** Windows NT 6.1

### Q14. What is the name of the malicious file?

**Answer:** tkraw_Protected99.exe

### Q15. What is the MD5 hash of the malicious file?

**Answer:** 71826BA081E303866CE2A2534491A2F7

### Q16. What web server software is being used?

**Answer:** LiteSpeed

### Q17. What is the public IP address of the victim?

**Answer:** 173.66.146.112

### Q18. What country is the email server located in?

**Answer:** United States

### Q19. What email server software is being used?

**Answer:** Exim 4.91

### Q20. What email account is involved?

**Answer:** sales.del@macwinlogistics.in

### Q21. What password is observed during SMTP authentication?

**Answer:** [REDACTED_LAB_PASSWORD]

> Note: This credential is included because it was required to answer the CyberDefenders lab question. It should not be reused, exposed publicly, or included in public-facing documentation unless specifically required by the internship submission.

### Q22. What malware variant is identified?

**Answer:** HawkEye Keylogger - Reborn v9

### Q23. What are the Bank of America access credentials identified in the captured data?

**Answer:** oman.mcguire:[REDACTED_LAB_PASSWORD]

> Note: This is a lab credential contained in the supplied challenge evidence. It should be treated as sensitive and should not be reused or unnecessarily exposed in public documentation.

### Q24. What is the interval between the exfiltration activities?

**Answer:** 10 minutes

## Completion Summary

All 24 questions of the CyberDefenders HawkEye challenge were investigated and answered using the supplied network-forensics evidence and Wireshark analysis.

The investigation identified the affected host, malicious executable, associated network infrastructure, SMTP-based data submission, malware variant, and recurring exfiltration pattern.

Sensitive credentials are documented here only because they were required for the corresponding lab questions.
