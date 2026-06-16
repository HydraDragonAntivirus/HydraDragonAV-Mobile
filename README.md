# 🐉 HydraDragonAV Mobile
**Military-Grade Advanced Android Cybersecurity & Threat Protection**

![Android](https://img.shields.io/badge/Android-10.0%2B-3DDC84?style=for-the-badge&logo=android)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Security](https://img.shields.io/badge/Security-Zero_Trust-red?style=for-the-badge)
![Languages](https://img.shields.io/badge/Languages-EN%20%7C%20TR-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

HydraDragonAV Mobile is a state-of-the-art Android Antivirus and Security suite built to stop the most advanced threats, including Ransomware, Clickjacking, and zero-day spyware. Designed with a **Zero-Trust architecture**, it actively defends Android ecosystems using dynamic behavior analysis and AI-powered static scanning.

## 🚀 Key Features

- **⚡ Photon Technology:** Ultra-fast, multi-threaded scanning engine utilizing `ConcurrentHashMap` caching to instantly verify previously scanned safe applications with zero CPU overhead.
- **🛡️ Ransomware Mitigation:** Real-time Dynamic Behavior Analysis powered by Android Accessibility Services to detect ransom notes and forcefully terminate ransomware screen-lockers.
- **🔍 On-Install & On-Demand Scanner:** Actively monitors the device using BroadcastReceivers to automatically intercept malicious APKs the exact second they are installed.
- **🧬 Deep Bytecode Analysis (DEX):** Advanced static code inspection to detect hardcoded malicious IPs, suspicious Base64 payloads, and obfuscated malware signatures.
- **🌐 Network Security Monitor:** Tracks active connections and warns against insecure or malicious domains.
- **🗃️ Bloom Filter Whitelisting:** O(1) instantaneous verification of safe developer signatures (e.g., Open Source apps from GitHub and Termux) using Google Guava's Bloom Filter.
- **🌍 Multilingual Support:** Fully localized and supports both **English** and **Turkish** languages seamlessly.

## 🛠️ Technical Architecture

HydraDragonAV Mobile operates on three core pillars:
1. **GuardService:** A persistent Foreground Service acting as the brain of the active defense system, monitoring threats 24/7.
2. **DynamicAnalysisService:** An Accessibility Service that prevents automated UI hijacking (Clickjacking) and blocks overlay attacks.
3. **ScanEngine:** The core analysis engine evaluating X.509 Certificates, SHA-256 Hashes, Dangerous Permissions, and App Install Sources.

## ⚙️ How to Build & Install

1. Clone the repository:
   ```bash
   git clone https://github.com/HydraDragonAntivirus/HydraDragonAV-Mobile.git
   cd HydraDragonAV-Mobile
