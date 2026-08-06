---
name: False Negative Report
about: Report a malicious app or file that bypassed HydraDragonAV Mobile
title: '[FN] '
labels: false negative
assignees: ''

---

**Note: False Negative Reports**
Please use this template ONLY for reporting malware, ransomware, phishing, or malicious activity that HydraDragonAV Mobile failed to detect or block.

**⚠️ IMPORTANT: Check Logs First ⚠️**
Before reporting a false negative, **please verify if the file was actually missed** by HydraDragonAV Mobile. Check the in-app scan logs and notification history to confirm.

**Malware / Threat Information**
- App Name / Package Name (if known):
- APK SHA256 Hash:
- Download Link (Password-protected ZIP, e.g., password 'infected'):
- Threat Type: [Malware / Ransomware / Phishing / SMS Scam / Spyware / Clickjacking / Other]

**Which component should have detected it?**
- [ ] YARA-X Signature Scan (native Rust engine)
- [ ] ClamAV Signature Scan
- [ ] ML Anomaly Detection (Burn binary classifier)
- [ ] AIEngine (DEX-level behavioral scoring)
- [ ] Network Security Scanner (malicious IP/C2 / MITM / ARP)
- [ ] Web Shield / DNS Filtering (malicious domain)
- [ ] Ransomware File Traps
- [ ] Rename-Burst Ransomware Detection
- [ ] On-Screen Text Scanner (ransomware / phishing / smishing)
- [ ] Native-Code Emulation (Unicorn Engine)
- [ ] Malicious/Phishing URL String Scanner
- [ ] Behavioral Detection Suite

**Describe the bypass**
Explain how the threat was executed and what actions it took that were not detected or blocked.

**VirusTotal / Analysis Link**
Provide a link to VirusTotal or any other malware analysis platform:

**Environment:**
 - Device:
 - Android Version:
 - HydraDragonAV Version/Commit:
 - Scan Mode Used: [Quick / Full / On-Install / Real-Time]

**Additional context**
Add any other context about the threat here.
