import "hydradragon"

// ── UI Spam ──────────────────────────────────────────────────────────────────

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

// ── Notification Spam ────────────────────────────────────────────────────────

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

// ── Clickjacking ─────────────────────────────────────────────────────────────

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

// ── Ransomware ───────────────────────────────────────────────────────────────

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

// ── Canary Traps ─────────────────────────────────────────────────────────────

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

// ── StrandHogg ───────────────────────────────────────────────────────────────

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

// ── System Security ──────────────────────────────────────────────────────────

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

// ── Behavioral Combinations ──────────────────────────────────────────────────

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

// ── Foreground Threats ───────────────────────────────────────────────────────

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
