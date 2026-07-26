import "hydradragon"
import "androguard"
import "math"

// -- UI Spam ------------------------------------------------------------------

rule HIPS_UI_Spam
{
  meta:
    description = "Detects UI spam (repeated click/window events within a short window)"
    severity = "high"
    category = "UI_SPAM"
    suggestion = "uninstall"
  condition:
    hydradragon.ui_spam(/./) >= 30
}

rule HIPS_UI_Spam_Excessive
{
  meta:
    description = "Detects excessive UI spam (high-volume click events)"
    severity = "critical"
    category = "UI_SPAM"
    suggestion = "uninstall"
  condition:
    hydradragon.ui_spam(/./) >= 100
}

// -- Notification Spam --------------------------------------------------------

rule HIPS_Notification_Spam
{
  meta:
    description = "Detects notification spam (excessive notifications from one app)"
    severity = "high"
    category = "NOTIFICATION_SPAM"
    suggestion = "warn"
  condition:
    hydradragon.notification_spam(/./) >= 20
}

rule HIPS_Notification_Spam_Excessive
{
  meta:
    description = "Detects excessive notification spam"
    severity = "critical"
    category = "NOTIFICATION_SPAM"
    suggestion = "uninstall"
  condition:
    hydradragon.notification_spam(/./) >= 50
}

// -- Clickjacking -------------------------------------------------------------

rule HIPS_Clickjack
{
  meta:
    description = "Detects clickjacking (rapid automated clicks on package installer/settings)"
    severity = "critical"
    category = "CLICKJACK"
    suggestion = "uninstall"
  condition:
    hydradragon.clickjack(/./) >= 3
}

rule HIPS_Clickjack_PackageInstaller
{
  meta:
    description = "Detects clickjacking targeting package installer"
    severity = "critical"
    category = "CLICKJACK"
    suggestion = "uninstall"
  condition:
    hydradragon.clickjack(/com\.android\.packageinstaller/) >= 1
}

// -- Ransomware ---------------------------------------------------------------

rule HIPS_Ransomware
{
  meta:
    description = "Detects ransomware rename burst pattern"
    severity = "critical"
    category = "RANSOMWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.ransomware_behavior(/./) >= 5
}

rule HIPS_Ransomware_Mass_Encryption
{
  meta:
    description = "Detects mass file encryption pattern"
    severity = "critical"
    category = "RANSOMWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.ransomware_behavior(/./) >= 20
}

// -- Canary Traps -------------------------------------------------------------

rule HIPS_Canary_Triggered
{
  meta:
    description = "Detects decoy file (canary) trap triggered"
    severity = "high"
    category = "CANARY"
    suggestion = "warn"
  condition:
    hydradragon.canary_triggered(/./) >= 1
}

rule HIPS_Canary_And_Flags
{
  meta:
    description = "Detects canary triggered on a flagged app"
    severity = "critical"
    category = "CANARY"
    suggestion = "uninstall"
  condition:
    hydradragon.canary_triggered(/./) >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

// -- StrandHogg ---------------------------------------------------------------

rule HIPS_StrandHogg
{
  meta:
    description = "Detects StrandHogg exploitation (suspicious activity patterns)"
    severity = "high"
    category = "STRANDHOGG"
    suggestion = "warn"
  condition:
    hydradragon.strandhogg(/./) >= 1
}

rule HIPS_StrandHogg_With_Flags
{
  meta:
    description = "Detects StrandHogg on a flagged app"
    severity = "critical"
    category = "STRANDHOGG"
    suggestion = "uninstall"
  condition:
    hydradragon.strandhogg(/./) >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

// -- System Security ----------------------------------------------------------

rule HIPS_Rooted
{
  meta:
    description = "Detects rooted device"
    severity = "high"
    category = "SYSTEM"
    suggestion = "warn"
  condition:
    hydradragon.rooted() >= 1
}

rule HIPS_Debug_Mode
{
  meta:
    description = "Detects USB/wireless debugging enabled"
    severity = "medium"
    category = "SYSTEM"
    suggestion = "warn"
  condition:
    hydradragon.debug_mode() >= 1
}

rule HIPS_Rooted_And_Debug
{
  meta:
    description = "Detects combined root + debug mode"
    severity = "critical"
    category = "SYSTEM"
    suggestion = "warn"
  condition:
    hydradragon.rooted() >= 1 and hydradragon.debug_mode() >= 1
}

// -- Behavioral Combinations --------------------------------------------------

rule HIPS_Multiple_Flags
{
  meta:
    description = "Detects apps with 3+ behavioral flags"
    severity = "high"
    category = "BEHAVIOR"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/./) >= 3
}

rule HIPS_Extensive_Flags
{
  meta:
    description = "Detects apps with 5+ behavioral flags"
    severity = "critical"
    category = "BEHAVIOR"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/./) >= 5
}

rule HIPS_UI_And_Notification_Spam
{
  meta:
    description = "Detects both UI spam and notification spam"
    severity = "critical"
    category = "BEHAVIOR"
    suggestion = "uninstall"
  condition:
    hydradragon.ui_spam(/./) >= 10 and hydradragon.notification_spam(/./) >= 10
}

rule HIPS_Ransomware_And_Canary
{
  meta:
    description = "Detects ransomware confirmed by rename burst + canary"
    severity = "critical"
    category = "BEHAVIOR"
    suggestion = "uninstall"
  condition:
    hydradragon.ransomware_behavior(/./) >= 1 and hydradragon.canary_triggered(/./) >= 1
}

rule HIPS_Network_And_Flags
{
  meta:
    description = "Detects suspicious network behavior + behavioral flags"
    severity = "high"
    category = "BEHAVIOR"
    suggestion = "warn"
  condition:
    hydradragon.network_connections(/./) >= 10 and hydradragon.behavior_flagged(/./) >= 1
}

// -- Foreground Threats -------------------------------------------------------

rule HIPS_Foreground_Threat
{
  meta:
    description = "Detects a flagged app currently in the foreground"
    severity = "high"
    category = "FOREGROUND"
    suggestion = "warn"
  condition:
    hydradragon.foreground_package(/./) >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

// -- URL Threats --------------------------------------------------------------

rule HIPS_Malicious_URL
{
  meta:
    description = "Detects apps communicating with known malicious URL patterns"
    severity = "high"
    category = "URL"
    suggestion = "warn"
  condition:
    hydradragon.url(/(?i)(tor2web|\.onion\/|\.i2p\/|bitcoin:|malware|exploit|shell|cmd=download|payload|backdoor|rat\b|crypt)/) >= 1
}

rule HIPS_Phishing_URL
{
  meta:
    description = "Detects phishing URLs in app network traffic"
    severity = "critical"
    category = "URL"
    suggestion = "uninstall"
  condition:
    hydradragon.url(/(?i)(login|signin|verify.*account|secure.*bank|paypal.*auth|password.*reset|credential|2fa.*bypass)/) >= 1
}

rule HIPS_URL_And_Flags
{
  meta:
    description = "Detects malicious URLs combined with behavioral flags"
    severity = "critical"
    category = "URL"
    suggestion = "uninstall"
  condition:
    hydradragon.url(/(?i)(tor2web|\.onion\/|\.i2p\/|bitcoin:|malware|exploit|backdoor|rat\b)/) >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

// -- DEX Static Analysis ------------------------------------------------------

rule HIPS_DEX_And_Behavior
{
  meta:
    description = "Detects severe DEX findings combined with behavioral flags"
    severity = "critical"
    category = "DEX"
    suggestion = "uninstall"
  condition:
    hydradragon.dex_severe_finding_count() >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

// -- System Package (self-protection observation) -----------------------------

rule HIPS_Suspicious_System_Package
{
  meta:
    description = "Detects suspicious package name in system self-protection state"
    severity = "high"
    category = "SYSTEM"
    suggestion = "warn"
  condition:
    hydradragon.system_package(/(?i)(spy|stalk|camera|sms|call_recorder|keylogger|trojan|malware|rat|backdoor)/) >= 1
}

// -- Observed Packages --------------------------------------------------------

rule HIPS_Multiple_Observed_Packages
{
  meta:
    description = "Detects an unusually high number of observed packages (scatter-gather behavior)"
    severity = "low"
    category = "OBSERVED"
    suggestion = "warn"
  condition:
    hydradragon.observed_packages(/./) >= 50
}

// -- Cuckoo-Compatible Network (HTTP from packet captures) --------------------

rule HIPS_HTTP_Suspicious_Request
{
  meta:
    description = "Detects HTTP requests to suspicious URIs (cleartext packet capture)"
    severity = "high"
    category = "HTTP"
    suggestion = "warn"
  condition:
    hydradragon.network.http_request(/(?i)(admin|config|shell|cmd|exec|upload|download|bypass|backdoor|phpmyadmin|wp-admin)/) >= 1
}

rule HIPS_HTTP_Data_Exfil
{
  meta:
    description = "Detects potential data exfiltration via HTTP POST"
    severity = "critical"
    category = "HTTP"
    suggestion = "uninstall"
  condition:
    hydradragon.network.http_post(/(?i)(upload|send|data|log|report|collect|sync|submit|gate)/) >= 1 and hydradragon.behavior_flagged(/./) >= 1
}

rule HIPS_HTTP_Suspicious_UserAgent
{
  meta:
    description = "Detects suspicious or spoofed HTTP User-Agent strings"
    severity = "medium"
    category = "HTTP"
    suggestion = "warn"
  condition:
    hydradragon.network.http_user_agent(/(?i)(curl|wget|python|perl|ruby|java|php|powershell|go-http|okhttp|dalvik)/) >= 1
}

rule HIPS_TCP_Suspicious_Port
{
  meta:
    description = "Detects TCP connections to suspicious ports"
    severity = "medium"
    category = "NETWORK"
    suggestion = "warn"
  condition:
    hydradragon.network.tcp(/^(4444|5555|6666|6667|6668|6669|1337|1338|4443|4445|8080|8443|9000|9001)$/) >= 1
}

rule HIPS_TCP_Unknown_Service
{
  meta:
    description = "Detects TCP connections to high/dynamic ports (potential C2)"
    severity = "high"
    category = "NETWORK"
    suggestion = "warn"
  condition:
    hydradragon.network.tcp(/^(1024\d{0,}|[1-9]\d{4,})$/) >= 1
}

rule HIPS_UDP_Suspicious_Port
{
  meta:
    description = "Detects UDP connections to suspicious ports"
    severity = "medium"
    category = "NETWORK"
    suggestion = "warn"
  condition:
    hydradragon.network.udp(/^(4444|5353|6666|6667|1337|1900|4500|5000|5001|8080)$/) >= 1
}

// -- Aggressive Adware / Launcher Hijack --------------------------------------
// Behavioral rules for detecting adware that hijacks the home screen or
// aggressively pushes ads, even when the APK claims to have no ads.
// Specifically targets the behavior pattern of com.murder.back.look.win
// and similar aggressive adware families.

rule HIPS_Adware_Aggressive_Notification_UI
{
  meta:
    description = "Detects aggressive adware: massive notification spam combined with high UI event volume (typical of forced full-screen or interstitial ads)"
    severity = "critical"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.notification_spam(/./) >= 15 and hydradragon.ui_spam(/./) >= 20
}

rule HIPS_Adware_Launcher_Hijack_Behavior
{
  meta:
    description = "Detects an app forcing itself into the foreground repeatedly while spamming notifications and UI events — the behavioral fingerprint of launcher-hijacking adware"
    severity = "critical"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.foreground_package(/./) >= 1 and
    hydradragon.notification_spam(/./) >= 10 and
    hydradragon.ui_spam(/./) >= 10
}

rule HIPS_Adware_Overlay_Abuse
{
  meta:
    description = "Detects apps abusing SYSTEM_ALERT_WINDOW / draw-over-apps (StrandHogg-style) combined with ad-like UI or notification spam — hallmark of overlay adware"
    severity = "critical"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.strandhogg(/./) >= 1 and
    (
      hydradragon.notification_spam(/./) >= 5 or
      hydradragon.ui_spam(/./) >= 10
    )
}

rule HIPS_Adware_Ad_Network_URL_UI_Spam
{
  meta:
    description = "Detects apps actively contacting major ad networks while generating excessive UI events — aggressive in-app advertising behaviour even if the app claims ad-free"
    severity = "high"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.url(/(?i)(googlesyndication\.com|doubleclick\.net|adnxs\.com|admob\.com|adcolony\.com|applovin\.com|unityads\.unity3d\.com|ironsource\.com|mopub\.com|vungle\.com|tapjoy\.com|startappservice\.com|inmobi\.com|chartboost\.com|wortise\.com)/) >= 1 and
    hydradragon.ui_spam(/./) >= 15
}

rule HIPS_Adware_Boot_Persist_Notification_Spam
{
  meta:
    description = "Detects adware that persists across reboots (via foreground package observations) and spams notifications — typical of aggressive adware that auto-starts to show ads"
    severity = "high"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.foreground_package(/./) >= 1 and
    hydradragon.notification_spam(/./) >= 20
}

rule HIPS_Adware_Multiple_Ad_Network_Connections
{
  meta:
    description = "Detects apps contacting multiple different advertising networks simultaneously — a clear sign of aggressive or SDK-stacked adware monetisation abuse"
    severity = "high"
    category = "ADWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.url(/(?i)(googlesyndication\.com|doubleclick\.net)/) >= 1 and
    hydradragon.url(/(?i)(applovin\.com|unityads\.unity3d\.com|ironsource\.com|adcolony\.com|tapjoy\.com|startappservice\.com|chartboost\.com)/) >= 1
}

// -- Static Adware / Launcher Hijack (androguard module) ----------------------
// These rules fire during APK static scan using manifest and DEX analysis.
// Specifically targets apps that hijack the home screen and show ads even
// when claiming to be ad-free (e.g. com.murder.back.look.win).

rule Android_Murder_Back_Look_Win : android adware
{
  meta:
    author      = "Emirhan Ucan"
    date        = "2026-07-23"
    description = "Detects com.murder.back.look.win — aggressive adware that hijacks the Android home screen and displays ads despite claiming otherwise"
    reference   = "https://play.google.com/store/apps/details?id=com.murder.back.look.win"
    severity    = "critical"
    category    = "adware"
    suggestion  = "uninstall"
  condition:
    androguard.package_name(/com\.murder\.back\.look\.win/)
}

rule Android_Aggressive_Adware_Launcher_Hijack : android adware
{
  meta:
    author      = "Emirhan Ucan"
    date        = "2026-07-23"
    description = "Detects APKs that register as an Android HOME screen launcher AND embed ad SDKs — aggressive adware that silently replaces the home screen to inject ads"
    severity    = "critical"
    category    = "adware"
    suggestion  = "uninstall"
  strings:
    $ad_admob    = "com/google/android/gms/ads"
    $ad_admob2   = "com/google/ads"
    $ad_unity    = "com/unity3d/ads"
    $ad_applovin = "com/applovin"
    $ad_mopub    = "com/mopub"
    $ad_fb       = "com/facebook/ads"
    $ad_ironsrc  = "com/ironsource/mediationsdk"
    $ad_vungle   = "com/vungle/warren"
    $ad_chartb   = "com/chartboost"
    $ad_inmobi   = "com/inmobi"
    $ad_startapp = "com/startapp"
    $ad_tapjoy   = "com/tapjoy"
    $ad_adcolony = "com/adcolony"
    $ad_wortise  = "com/wortise"
    $ag_intrstl  = "InterstitialAd"
    $ag_reward   = "RewardedAd"
    $ag_fullscr  = "FullScreenAdActivity"
    $ag_overlay  = "OverlayAd"
  condition:
    androguard.activity(/android\.intent\.category\.HOME/) and
    (2 of ($ad_*) or 1 of ($ag_*)) and
    (
      androguard.permission(/android\.permission\.SYSTEM_ALERT_WINDOW/) or
      androguard.permission(/android\.permission\.RECEIVE_BOOT_COMPLETED/) or
      androguard.permission(/android\.permission\.FOREGROUND_SERVICE/)
    )
}

rule Android_Launcher_Hijack_Hidden_Ads : android adware
{
  meta:
    author      = "Emirhan Ucan"
    date        = "2026-07-23"
    description = "Detects APKs that register as a HOME/DEFAULT launcher and contain ad network domains or overlay-injection code — catches adware that falsely claims 'no ads'"
    severity    = "high"
    category    = "adware"
    suggestion  = "uninstall"
  strings:
    $home        = "android.intent.category.HOME"
    $default_cat = "android.intent.category.DEFAULT"
    $net_google  = "googlesyndication.com"
    $net_dclick  = "doubleclick.net"
    $net_admob   = "admob.com"
    $net_adnxs   = "adnxs.com"
    $net_adsys   = "adsystem.g.doubleclick.net"
    $net_applovin= "applovin.com"
    $net_unity   = "unityads.unity3d.com"
    $net_ironsrc = "ironSource.com"
    $net_startapp= "startappservice.com"
    $net_tapjoy  = "tapjoy.com"
    $inj_popup   = "android/widget/PopupWindow"
    $inj_wm_add  = "android/view/WindowManager;->addView"
    $inj_alarm   = "android/app/AlarmManager;->setRepeating"
    $inj_setcomp = "android/content/pm/PackageManager;->setComponentEnabledSetting"
  condition:
    androguard.package_name(/./) and
    $home and $default_cat and
    (2 of ($net_*) or 2 of ($inj_*))
}

// ── HIPS: high-entropy device-admin hidden rootkit (behavioral scan) ────────

rule HIPS_Packed_DeviceAdmin_HiddenRootkit
{
  meta:
    description = "Runtime-observed package with high entropy, active device admin, and hidden launcher icon — packed stealth-rootkit"
    severity = "critical"
    category = "MALWARE"
    suggestion = "uninstall"
  condition:
    math.entropy(0, filesize) > 7.0 and
    hydradragon.device_admin(/./) >= 1 and
    hydradragon.hidden_app(/./) >= 1
}

// ── Crypto Miner Detection (behavioral: CPU + memory via miner_events) ───────

rule HIPS_Miner_BehaviorFlag
{
  meta:
    description = "Detects apps flagged for cryptomining behavior via runtime CPU/memory profiling"
    severity = "high"
    category = "MINER"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/MINER/) >= 1
}

rule HIPS_Miner_HighCpuAndMemory
{
  meta:
    description = "Detects sustained high CPU usage combined with large memory allocation — behavioral miner fingerprint"
    severity = "high"
    category = "MINER"
    suggestion = "warn"
  condition:
    hydradragon.miner_cpu(/./) >= 80 or
    hydradragon.miner_memory(/./) >= 64
}

rule HIPS_Miner_KnownProcess
{
  meta:
    description = "Detects known cryptominer process names via runtime profiling"
    severity = "critical"
    category = "MINER"
    suggestion = "uninstall"
  condition:
    hydradragon.miner_known_name(/xmrig|xmr-stak|minerd|ccminer|cpuminer|cryptominer/i) >= 1
}

rule HIPS_Miner_MultipleFlags
{
  meta:
    description = "Detects apps flagged for multiple miner indicators simultaneously"
    severity = "critical"
    category = "MINER"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/MINER/) >= 1 and
    hydradragon.behavior_flagged(/./) >= 3
}

// ── Ransomware + High Memory ─────────────────────────────────────────────────
// Some ransomware families encrypt files in-memory (e.g. SimpleLocker variants)
// or exfiltrate data before encryption — detectable as both file rename burst
// AND abnormally high resident memory.

rule HIPS_Ransomware_And_HighMemory
{
  meta:
    description = "Detects ransomware file rename burst combined with abnormally high process memory — in-memory encryption or data exfiltration"
    severity = "critical"
    category = "RANSOMWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.ransomware_behavior(/./) >= 1 and
    hydradragon.miner_memory(/./) >= 64
}

rule HIPS_Ransomware_With_MemoryFlag
{
  meta:
    description = "Detects ransomware app that also has sustained high process memory (>64MB) — stronger indicator of active in-memory encryption"
    severity = "critical"
    category = "RANSOMWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/RANSOMWARE/) >= 1 and
    hydradragon.behavior_flagged(/RANSOMWARE_HIGH_MEM/) >= 1
}

rule HIPS_Ransomware_All_Sensors
{
  meta:
    description = "Detects ransomware confirmed by all four sensors: rename suffix, high entropy, system memory pressure, and high per-process memory"
    severity = "critical"
    category = "RANSOMWARE"
    suggestion = "uninstall"
  condition:
    hydradragon.behavior_flagged(/RANSOMWARE/) >= 1 and
    hydradragon.behavior_flagged(/RANSOMWARE_HIGH_MEM/) >= 1 and
    hydradragon.behavior_flagged(/RANSOMWARE_HIGH_ENTROPY/) >= 1
}

// ── File Read Estimation ─────────────────────────────────────────────────────
// FileReadEstimator uses /proc/<pid>/io read_bytes deltas + known file sizes +
// cache ratio + timing + memory to estimate which file a process read.
// This is an estimation, not a certainty — see FileReadEstimator.java.

rule HIPS_FileRead_Detected
{
  meta:
    description = "Detects behavioural file-read estimation — a process was observed reading a file whose size matches a known file on disk (estimation, see FileReadEstimator.java)"
    severity = "low"
    category = "FILE_READ"
    suggestion = "none"
  condition:
    hydradragon.behavior_flagged(/FILE_READ/) >= 1
}

rule HIPS_FileRead_HighConfidence
{
  meta:
    description = "Detects high-confidence file-read estimation (≥80% confidence) — the I/O delta closely matches a known file size and was recently modified"
    severity = "medium"
    category = "FILE_READ"
    suggestion = "warn"
  condition:
    hydradragon.behavior_flagged(/FILE_READ.*conf=(8[0-9]|9[0-9]|100)/) >= 1
}

rule HIPS_FileRead_DataExfil
{
  meta:
    description = "Detects an app reading sensitive document files with minimal cache (cold read) — possible data exfiltration"
    severity = "high"
    category = "FILE_READ"
    suggestion = "warn"
  condition:
    hydradragon.behavior_flagged(/FILE_READ.*file=.*\.(doc|docx|xls|xlsx|pdf|txt|csv|json|db|sqlite)/i) >= 1 and
    hydradragon.behavior_flagged(/FILE_READ.*cache=(0|[0-9]|[1-2][0-9])/) >= 1
}

rule HIPS_FileRead_WithNetwork
{
  meta:
    description = "Detects file read estimation combined with network activity — app reads local files and communicates externally (exfiltration pattern)"
    severity = "high"
    category = "FILE_READ"
    suggestion = "warn"
  condition:
    hydradragon.behavior_flagged(/FILE_READ/) >= 1 and
    (
      hydradragon.network_connections(/./) >= 5 or
      hydradragon.behavior_flagged(/NETWORK/) >= 1
    )
}
