package com.hydradragon.antivirus.engine;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Combines several independently-weak DYNAMIC signals into one risk score per
 * installed app, instead of alerting on any single one alone (each is noisy
 * enough on its own to false-positive on legitimate apps):
 *
 * <ul>
 *   <li><b>Permission pattern</b> — dangerous permission COMBINATIONS actually
 *       granted (a single permission like INTERNET is meaningless; overlay +
 *       accessibility together is a banker-trojan signature).</li>
 *   <li><b>Time pattern</b> — how recently the app was installed. The same
 *       suspicious-domain hit is far more suspicious in the first hour after
 *       install (classic dropper first-run beacon) than from a years-old,
 *       frequently-used app.</li>
 *   <li><b>Network behaviour</b> — plain-DNS lookups of anonymizer/tunnel-
 *       service-shaped domains (see {@link #SUSPICIOUS_PATTERNS}), attributed
 *       to the querying app via {@link NetworkObservations} (which resolves
 *       the query's owner UID in the VPN, see DnsVpnService).</li>
 * </ul>
 *
 * <p><b>Honest limitation — this is NOT "Tor connection detection":</b>
 * DnsVpnService only intercepts DNS (port 53) by design, never TCP/UDP
 * payload, so it can't see an actual established Tor circuit at all — real
 * Tor traffic connects straight to a hardcoded relay IP:port over its own
 * protocol and typically never asks the device's DNS resolver anything. What
 * this DOES genuinely catch: an app plain-DNS-querying a ".onion" name (some
 * apps try normal resolution before falling back to SOCKS, which fails
 * loudly and visibly here) and legitimate, fully DNS-resolvable tunnel/DDNS
 * services (ngrok.io, serveo.net, dyndns/no-ip/ddns hosts) that malware
 * genuinely does use for C2 over ordinary DNS. Treat a hit here as "this app
 * looked up something anonymizer/tunnel-shaped", not as proof of Tor use.
 *
 * <p>Static signature/YARA detection already covers "is this APK known-bad" —
 * this class is for the opposite case: an app with a clean static scan that
 * only reveals itself through what it actually DOES after being installed.
 * A high combined score is written to {@link BehaviorFlags} (the same store
 * ScanEngine already reads to report a behaviourally-flagged app as malware
 * on its next scan) and raised as an immediate notification.
 */
public final class DynamicRiskEngine {

    private static final String TAG = "HydraDragon-DynRisk";

    /** Suspicious/anonymizer-shaped domain patterns — same list NetworkMonitor
     *  already uses for its own (non-attributed) domain check. */
    private static final String[] SUSPICIOUS_PATTERNS = {
        ".onion", "tor2web", "i2p", "ngrok.io", "serveo.net", "dyndns", "no-ip", "ddns"
    };

    /** How long after first install a Tor/C2-shaped hit is treated as a strong
     *  "dropper beaconing on first run" signal rather than routine background
     *  activity from an app the user has had for a while. */
    private static final long FRESH_INSTALL_WINDOW_MS = 60L * 60L * 1000L; // 1 hour

    private static final int SCORE_THRESHOLD = 70;

    private static final Map<String, Integer> torHitCounts = new HashMap<>();
    private static final AtomicInteger notifId = new AtomicInteger(0xD19_000);

    private DynamicRiskEngine() {}

    /** Called for every DNS query the Web Shield VPN resolves to a package —
     *  see DnsVpnService's handleUdpDns/handleTcpDns (NetworkObservations.addDomain
     *  call sites). Cheap no-op for the overwhelming majority of normal domains. */
    public static void onDomainObserved(Context context, String pkg, String host) {
        if (!BehaviorDetectionSettings.isEnabled(context, BehaviorDetectionSettings.DYNAMIC_RISK)) return;
        if (pkg == null || pkg.isEmpty() || host == null) return;
        if (BehaviorFlags.isFlagged(context, pkg)) return; // already flagged, don't re-score
        if (TrustedPackages.isTrusted(context, pkg)) return; // never flag Google/OEM/system apps
        if (UserDecisions.isThreatAllowed(context, pkg)) return; // user already said "safe, ignore"
        String lower = host.toLowerCase(java.util.Locale.ROOT);
        boolean suspicious = false;
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (lower.contains(pattern)) { suspicious = true; break; }
        }
        if (!suspicious) return;

        int hits;
        synchronized (torHitCounts) {
            hits = torHitCounts.merge(pkg, 1, Integer::sum);
        }

        try {
            evaluate(context, pkg, host, hits);
        } catch (Throwable t) {
            Log.w(TAG, "evaluate failed for " + pkg, t);
        }
    }

    private static void evaluate(Context context, String pkg, String triggerHost, int torHits) {
        PackageManager pm = context.getPackageManager();
        PackageInfo info;
        try {
            info = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS);
        } catch (PackageManager.NameNotFoundException e) {
            return; // uninstalled between the query and this check
        }

        int score = 0;
        StringBuilder reasons = new StringBuilder();

        // Network signal: repeated plain-DNS lookups of anonymizer/tunnel-shaped
        // domains from this app — NOT proof of an actual Tor connection, see
        // class javadoc; DnsVpnService never sees non-DNS traffic at all.
        int netScore = Math.min(50, torHits * 20);
        score += netScore;
        reasons.append("Suspicious DNS lookup: anonymizer/tunnel-service domain (")
            .append(torHits).append("x, e.g. ").append(triggerHost).append(")");

        // Time pattern: fresh install + this DNS pattern == likely dropper beacon.
        long age = System.currentTimeMillis() - info.firstInstallTime;
        if (age >= 0 && age < FRESH_INSTALL_WINDOW_MS) {
            score += 25;
            reasons.append("; installed ").append(age / 60000).append(" min ago");
        }

        // Permission pattern: dangerous COMBINATIONS actually granted, not any
        // single permission alone.
        String[] granted = info.requestedPermissions;
        boolean hasOverlay = false, hasAccessibility = false, hasSms = false,
                hasInternet = false, hasDeviceAdmin = false, hasInstallPkgs = false;
        if (granted != null) {
            for (String p : granted) {
                if (p == null) continue;
                if (p.equals(android.Manifest.permission.SYSTEM_ALERT_WINDOW)) hasOverlay = true;
                else if (p.equals(android.Manifest.permission.BIND_ACCESSIBILITY_SERVICE)) hasAccessibility = true;
                else if (p.equals(android.Manifest.permission.RECEIVE_SMS)
                        || p.equals(android.Manifest.permission.READ_SMS)) hasSms = true;
                else if (p.equals(android.Manifest.permission.INTERNET)) hasInternet = true;
                else if (p.equals(android.Manifest.permission.BIND_DEVICE_ADMIN)) hasDeviceAdmin = true;
                else if (p.equals("android.permission.REQUEST_INSTALL_PACKAGES")) hasInstallPkgs = true;
            }
        }
        if (hasOverlay && hasAccessibility) {
            score += 25;
            reasons.append("; overlay+accessibility permission combo (banker-trojan pattern)");
        }
        if (hasSms && hasInternet) {
            score += 20;
            reasons.append("; SMS-read/receive + Internet permission combo (SMS exfiltration pattern)");
        }
        if (hasDeviceAdmin) {
            score += 10;
            reasons.append("; Device Administrator rights (removal-resistance pattern)");
        }
        if (hasInstallPkgs) {
            score += 10;
            reasons.append("; can install other packages (dropper pattern)");
        }

        if (score < SCORE_THRESHOLD) return;

        String reasonText = "Dynamic risk score " + score + "/100: " + reasons;
        Log.e(TAG, "DYNAMIC BEHAVIOUR FLAG (" + pkg + "): " + reasonText);
        BehaviorFlags.flag(context, pkg, reasonText);
        com.hydradragon.antivirus.service.ThreatLogger.logThreat(context, pkg, pkg, reasonText);
        alert(context, pkg, score);
        BehaviorResponse.killAndPromptUninstall(context, pkg);
    }

    private static void alert(Context context, String pkg, int score) {
        if (!ProtectionState.isEnabled(context)) return;
        NotificationManager nm = context.getSystemService(NotificationManager.class);
        if (nm == null) return;
        String appName = pkg;
        try {
            appName = context.getPackageManager()
                .getApplicationLabel(context.getPackageManager().getApplicationInfo(pkg, 0)).toString();
        } catch (Throwable ignore) { }

        int id = notifId.incrementAndGet();
        android.content.Intent ignoreIntent = new android.content.Intent(
                context, com.hydradragon.antivirus.service.UserActionReceiver.class)
            .setAction(com.hydradragon.antivirus.service.UserActionReceiver.ACTION_IGNORE)
            .putExtra(com.hydradragon.antivirus.service.UserActionReceiver.EXTRA_ID, pkg)
            .putExtra(com.hydradragon.antivirus.service.UserActionReceiver.EXTRA_NOTIF, id);
        android.app.PendingIntent ignorePi = android.app.PendingIntent.getBroadcast(
            context, pkg.hashCode(), ignoreIntent,
            android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT);

        Notification n = new NotificationCompat.Builder(context, "hydradragon_guard")
            .setSmallIcon(com.hydradragon.antivirus.R.drawable.ic_threat)
            .setContentTitle(context.getString(com.hydradragon.antivirus.R.string.dynamic_risk_title))
            .setContentText(appName + " — " + score + "/100")
            .setStyle(new NotificationCompat.BigTextStyle().bigText(
                context.getString(com.hydradragon.antivirus.R.string.dynamic_risk_msg, appName)))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(0xFF0040)
            .addAction(0, context.getString(com.hydradragon.antivirus.R.string.btn_ignore), ignorePi)
            .build();
        nm.notify(id, n);
    }
}
