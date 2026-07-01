# 🐉 HydraDragonAV Mobile
**Military-Grade Advanced Android Cybersecurity & Threat Protection**

![Android](https://img.shields.io/badge/Android-10.0%2B-3DDC84?style=for-the-badge&logo=android)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-Native_Engine-DEA584?style=for-the-badge&logo=rust&logoColor=black)
![Security](https://img.shields.io/badge/Security-Zero_Trust-red?style=for-the-badge)
![Languages](https://img.shields.io/badge/Languages-20-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

HydraDragonAV Mobile is a multi-layered Android Antivirus and Security suite combining static analysis (YARA-X + ClamAV signatures + code anomaly detection), dynamic behavior analysis, and a lightweight on-device ML classifier — all gated by a NSRL-backed whitelist so known-good software is never a false positive. Designed with a **Zero-Trust architecture**, it actively defends the device against ransomware, clickjacking, spyware, SMS scams/phishing, and zero-day threats.

> **📋 Requirements: Android 10 (API 29) or newer.** The per-app dynamic network
> analysis — attributing each DNS/connection to the exact app that made it and
> feeding it to the YARA-X `hydradragon` module — relies on
> `ConnectivityManager.getConnectionOwnerUid`, which is only available on
> Android 10+. On older versions the rest of the suite still runs, but per-app
> connection attribution is unavailable.

## 🚀 Key Features

- **⚡ Photon Technology:** Ultra-fast, multi-threaded scanning engine utilizing `ConcurrentHashMap` caching to instantly re-verify previously scanned safe applications with zero CPU overhead.
- **🧠 Native Rust Scan Engine:** A JNI-bridged Rust core (`libhydradragonandroid.so`) does the heavy lifting — YARA-X + ClamAV signature matching, archive extraction (zip/gz/tar/xz/lzma/7z/rar, including nested APKs), AXML manifest parsing, and dangerous-permission counting, all straight from bytes in memory (no temp files required).
- **🔎 One-Class ML Anomaly Detection:** A MinHash/LSH + Isolation Forest model scores every scanned sample with a Jaccard similarity and anomaly score, flagging outliers that don't match any known-clean or known-malware profile — a lightweight logistic-regression classifier (`AIEngine`) also scores DEX-level behavior (obfuscation, dynamic loading, crypto/socket/shell APIs, adware SDKs).
- **🧬 TLSH Fuzzy Hashing:** Compares scanned APK/ELF/DEX files against a MalwareBazaar-derived TLSH digest database to catch samples that are similar-but-not-identical to known malware.
- **🛡️ Ransomware & Screen-Locker Mitigation:** Real-time on-screen text detection (via Accessibility Service + OCR) recognizes ransom notes and forcefully terminates screen-locking ransomware, in **20 languages**.
- **📵 SMS Scam & Phishing Detection:** The same multi-language on-screen text scanner catches smishing lures (fake account verification, prize scams, parcel-delivery scams, OTP requests, bank alerts) wherever they're rendered — Messages app, notification previews, or a spoofed WebView — without ever reading your SMS inbox directly.
- **🖥️ Live Screen OCR:** A MediaProjection-based capture service periodically OCRs the foreground screen and feeds the extracted text into the native threat scanner, catching scams that only ever appear as rendered pixels.
- **🚫 UI Hijacking / Clickjacking Protection:** Detects and blocks automated rapid-click permission-granting attacks, notification-spam floods, and repeated overlay/dialog abuse from malicious apps.
- **🔍 On-Install & On-Demand Scanner:** Quick (installed apps + Downloads) or Full (entire storage including SD card) scans; a `BroadcastReceiver` intercepts and scans newly installed/updated APKs automatically.
- **🌐 Network Security Monitor:** Tracks live connections, flags known-malicious IPs/C2/Tor nodes and suspicious domains (dyndns, ngrok, .onion), detects MITM/TLS interception via untrusted CAs, and can spot ARP spoofing on the local network.
- **🌐 DNS-Filtering VPN (Web Shield):** A local, on-device VPN service blocks resolution of known-malicious/phishing domains — no traffic proxying, decryption, or inspection, only DNS lookups are filtered.
- **🗃️ NSRL-Backed Whitelisting:** Known-good software is cleared through two independent NSRL-derived layers — a binary-fuse XOR filter of whole-file SHA-256 hashes (native, in-memory) and a SQLite database of full NSRL package metadata (name, version, manufacturer, OS) — so a legitimate app is never flagged, while a malicious hash can never "borrow" a whitelist entry by luck.
- **🔒 Zero-Trust Mode:** Optional stricter mode where any app that merely *survives* every detector (rather than being explicitly cleared) is still flagged as suspicious, with a full audit trail.
- **🧹 Bloatware Cleaner, App Lock, Self-Protection & Root Detection:** Rounds out the suite with background-app cleanup, PIN-protected app lock, tamper/uninstall resistance, and rooted-device detection.
- **🌍 Multilingual Support:** Fully localized UI and threat-detection keyword lists across **20 languages**: English, Turkish, Spanish, German, French, Russian, Portuguese, Arabic, Italian, Dutch, Polish, Ukrainian, Chinese (Simplified), Japanese, Korean, Hindi, Indonesian, Vietnamese, Persian, and Thai.

## 🛠️ Technical Architecture

HydraDragonAV Mobile operates across four core pillars:
1. **GuardService:** A persistent Foreground Service acting as the brain of the active defense system — watches the Downloads folder in real time and orchestrates scans, monitoring threats 24/7.
2. **DynamicAnalysisService:** An Accessibility Service that prevents automated UI hijacking (Clickjacking), blocks overlay/notification-spam attacks, and scans on-screen text for ransomware/SMS-scam/phishing wording in 20 languages.
3. **ScreenCaptureService:** A MediaProjection-based OCR service that periodically captures and reads the foreground screen, feeding extracted text into the native scanner for live threat detection.
4. **ScanEngine + NativeScanner:** The Java orchestration layer and its Rust-native counterpart (`libhydradragonandroid.so`) — evaluating X.509 certificates, SHA-256/TLSH hashes, dangerous permissions, app install sources, YARA-X/ClamAV signatures, and ML anomaly scores.

A local **DnsVpnService** additionally filters DNS lookups against known-malicious domains, and a **NetworkSecurityScanner**/**NetworkMonitor** pair watches live connections for MITM interception, ARP spoofing, and malicious IP/C2 traffic.

*Designed with 💻 by @elnureisayeva1-cloud (creator) & @Siradankullanici (backend development)*

About original HydraDragonAntivirus: This only detects Android viruses and minimalist version of original HydraDragonAntivirus.

**Note: Max file size is 650MB for this antivirus**

## ⚙️ How to Build & Install

1. Clone the repository (submodules included — the native engine vendors a custom [YARA-X fork](https://github.com/Siradankullanici/yara-x) with `hydradragon`/`androguard` scanning modules):
   ```bash
   git clone --recurse-submodules https://github.com/HydraDragonAntivirus/HydraDragonAV-Mobile.git
   cd HydraDragonAV-Mobile
   ```

2. Build the native Rust engine for Android (see `hydradragonandroid/build-android.sh` for prerequisites — `rustup` Android targets, `cargo-ndk`, and `ANDROID_NDK_HOME`):
   ```bash
   cd hydradragonandroid
   ./build-android.sh
   ```

3. Build the Android app as usual (Gradle) — the native `.so` output is picked up automatically from `app/src/main/jniLibs/`.

## 🗄️ Data Pipeline (Whitelists, Signatures & Filters)

The on-device detection assets are generated offline from public threat-intel and NSRL sources, then bundled into the app:

- **`gen_whitelist_packages.py`** — builds `whitelist_packages.db` (SQLite), a full-detail NSRL Android package whitelist (name, version, manufacturer, OS, hashes) joined from the NSRL RDS database.
- **`gen_whitelist_apk.py`** — extracts whole-APK NSRL MD5 hashes for the native binary-fuse XOR whitelist filter.
- **`gen_tlsh_db.py`** — builds a TLSH fuzzy-hash database from MalwareBazaar samples (APK/ELF/SO/DEX) for similarity-based malware detection.
- **`gen_ip_lists.py`** / **`build_url_blooms.py`** / **`build_xfilters.sh`** — build the malicious IP/URL/domain filters (XOR-filter based) used by the native IP/URL threat scanners.
- **`clam_juice.py`** — filters ClamAV signatures to keep only Android-relevant platforms (Andr, Unix, Linux, Email, PUA) plus all Phishing signatures; excludes Win/Osx/Java:
  ```bash
  python clam_juice.py --directory database_non_filtered --output database_filtered --profile cross-platform
  ```
