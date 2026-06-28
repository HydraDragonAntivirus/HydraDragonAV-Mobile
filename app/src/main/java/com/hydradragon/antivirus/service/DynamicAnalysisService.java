package com.hydradragon.antivirus.service;

import android.accessibilityservice.AccessibilityService;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.core.app.NotificationCompat;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.BehaviorFlags;

import java.util.HashMap;
import java.util.Map;

public class DynamicAnalysisService extends AccessibilityService {
    private static final String TAG = "HydraDragon-Dynamic";
    private static final String CHANNEL_ID = "hydradragon_dynamic_alert";

    private long lastClickTime = 0;
    private int rapidClickCount = 0;

    // ── Behavioural spam detection ──────────────────────────────────────────
    /** Same event signature N+ times within the window => spam => malware. */
    private static final int SPAM_THRESHOLD = 30;
    private static final long SPAM_WINDOW_MS = 8_000;
    /** Notification spam: N+ notifications from one app in the window => malware. */
    private static final int NOTIF_THRESHOLD = 20;
    private static final long NOTIF_WINDOW_MS = 10_000;
    /** signature -> [windowStartMs, count]. */
    private final Map<String, long[]> spamCounters = new HashMap<>();
    private final Map<String, Long> spamFlagged = new HashMap<>();
    /** package -> [windowStartMs, notificationCount]. */
    private final Map<String, long[]> notifCounters = new HashMap<>();

    /** Foreground package of the event currently being processed. */
    private volatile String fgPackage = "";

    /** Browsers: a flagged URL HERE is actually being navigated to -> hard block. */
    private static final java.util.Set<String> BROWSERS = new java.util.HashSet<>(java.util.Arrays.asList(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev",
        "org.mozilla.firefox", "org.mozilla.focus",
        "com.opera.browser", "com.opera.mini.native", "com.opera.gx",
        "com.brave.browser", "com.microsoft.emmx",
        "com.sec.android.app.sbrowser", "com.android.browser",
        "com.duckduckgo.mobile.android", "com.kiwibrowser.browser",
        "com.vivaldi.browser", "com.yandex.browser", "mark.via.gp"));

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        Log.i(TAG, "Dynamic Analysis Accessibility Service Connected");
        createNotificationChannel();
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;
        CharSequence packageName = event.getPackageName();
        if (packageName == null) return;

        // Don't scan our OWN UI: the scan report shows malicious URLs/keywords as
        // text, which would otherwise re-trigger the URL/ransomware detector and
        // falsely "block" + kick to home. Skip our own package entirely.
        String pkg = packageName.toString();
        if (pkg.equals(getPackageName())
            || pkg.equals("com.hydradragon.antivirus")
            || pkg.equals("com.hydradragon.antivirus.debug")) {
            return;
        }

        int eventType = event.getEventType();

        // Whitelist: never flag trusted apps (Google/OEM/system) as behavioural
        // malware — keeps legit apps from being called a virus.
        boolean trusted = com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, pkg);

        // Notification spam: an app firing many notifications in a short window.
        if (eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED) {
            if (!trusted) checkNotificationSpam(pkg);
            return;
        }

        // Behavioural detection: an app that repeats the SAME event/content far
        // too often (overlay/dialog/toast/click spam) is acting maliciously.
        if (!trusted) checkSpamBehavior(event, pkg);

        boolean isInstaller = packageName.toString().contains("packageinstaller") ||
                              packageName.toString().contains("permissioncontroller");
        boolean isSettings = packageName.toString().equals("com.android.settings");

        if (eventType == AccessibilityEvent.TYPE_VIEW_CLICKED) {
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastClickTime < 300) { 
                rapidClickCount++;
            } else {
                rapidClickCount = 1;
            }
            lastClickTime = currentTime;

            if (rapidClickCount >= 3 && (isInstaller || isSettings)) {
                Log.w(TAG, "DETECTED: Automated Clickjacking/Permission granting!");
                sendAlert("CRITICAL: Automated UI Hijacking Detected", "Malware is trying to auto-click permissions. Action blocked!");
                
                performGlobalAction(GLOBAL_ACTION_BACK);
                performGlobalAction(GLOBAL_ACTION_HOME);
                rapidClickCount = 0;
            }
        }

        if (eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED ||
            eventType == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {

            fgPackage = pkg;   // remember which app's content we're scanning
            AccessibilityNodeInfo rootNode = getRootInActiveWindow();
            if (rootNode != null) {
                checkNodesForSuspiciousKeywords(rootNode);
                rootNode.recycle();
            }
        }
    }

    private void checkNodesForSuspiciousKeywords(AccessibilityNodeInfo node) {
        if (node == null) return;
        
        CharSequence text = node.getText();
        if (text != null) {
            String lowerText = text.toString().toLowerCase();
            // RANSOMWARE MITIGATION
            if (lowerText.contains("your files are encrypted") || 
                lowerText.contains("pay bitcoin") ||
                lowerText.contains("recover your files") ||
                lowerText.contains("bitcoin address")) {
                Log.e(TAG, "RANSOMWARE TEXT DETECTED in " + fgPackage);
                // Relatedness: a standalone app showing a full-screen "files
                // encrypted" lock IS ransomware -> nuke. The same text inside a
                // browser is almost always an article/tech-support-scam page ->
                // warn only, don't close the browser.
                if (!BROWSERS.contains(fgPackage)) {
                    sendAlert("RANSOMWARE BLOCKED", "Ransomware lock screen detected. Sent to home screen!");
                    performGlobalAction(GLOBAL_ACTION_HOME);
                } else {
                    sendAlert("Possible scam page", "Ransom/scam text on a web page.");
                }
            }

            if (lowerText.contains("activate device admin") ||
                lowerText.contains("cihaz yöneticisini etkinleştir") ||
                lowerText.contains("cihaz yöneticisi")) {
                Log.d(TAG, "Device Admin activation screen visible.");
            }

            // Website scan: pull http(s):// URLs from on-screen text (browser bar
            // etc.) and check the malware/phishing blooms. Passive read of the
            // URL the browser already shows — no MITM/TLS interception.
            try {
                com.hydradragon.antivirus.engine.UrlThreatScanner scanner =
                    com.hydradragon.antivirus.engine.UrlThreatScanner.get(this);
                for (String url : com.hydradragon.antivirus.engine.UrlThreatScanner
                        .extractUrls(text.toString())) {
                    String cat = scanner.scanUrl(url);
                    if (cat != null) {
                        Log.e(TAG, "MALICIOUS URL (" + cat + "): " + url + " in " + fgPackage);
                        sendAlert("MALICIOUS WEBSITE", cat + ": " + url);
                        // Only hard-block (kick home) when the foreground app is
                        // actually RELATED to the threat: a browser navigating to
                        // it, or an app already flagged for malicious behaviour.
                        // A legit app merely displaying the URL as text isn't the
                        // virus — just warn there (the DNS VPN blocks navigation).
                        boolean related = BROWSERS.contains(fgPackage)
                            || BehaviorFlags.isFlagged(this, fgPackage);
                        if (related) {
                            performGlobalAction(GLOBAL_ACTION_HOME);
                        }
                        break;
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "url scan failed", t);
            }
        }
        
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                checkNodesForSuspiciousKeywords(child);
                child.recycle();
            }
        }
    }

    /**
     * Flag an app whose accessibility events repeat the same signature far more
     * than any legitimate UI would in a short window (overlay/dialog/toast/click
     * spam = classic adware/clicker/ransomware behaviour).
     */
    private void checkSpamBehavior(AccessibilityEvent event, String pkg) {
        try {
            int type = event.getEventType();
            CharSequence cls = event.getClassName();
            CharSequence txt = (event.getText() != null && !event.getText().isEmpty())
                ? event.getText().get(0) : null;
            String sig = pkg + "|" + type + "|" + (cls != null ? cls : "") + "|"
                + (txt != null ? txt : "");

            long now = System.currentTimeMillis();
            long[] c = spamCounters.get(sig);
            if (c == null || now - c[0] > SPAM_WINDOW_MS) {
                spamCounters.put(sig, new long[]{now, 1});
            } else {
                c[1]++;
                if (c[1] >= SPAM_THRESHOLD) {
                    // Rate-limit alerts per package to once per window.
                    Long last = spamFlagged.get(pkg);
                    if (last == null || now - last > SPAM_WINDOW_MS) {
                        spamFlagged.put(pkg, now);
                        String reason = "Spam behaviour: same UI event x" + c[1]
                            + " in " + (SPAM_WINDOW_MS / 1000) + "s";
                        Log.e(TAG, "BEHAVIOUR MALWARE (" + pkg + "): " + reason);
                        BehaviorFlags.flag(this, pkg, reason);
                        sendAlert("MALWARE BEHAVIOUR BLOCKED",
                            pkg + " — " + reason);
                        performGlobalAction(GLOBAL_ACTION_HOME);
                    }
                    spamCounters.put(sig, new long[]{now, 1});  // reset window
                }
            }

            // Bound memory: drop the map if it grows large.
            if (spamCounters.size() > 600) spamCounters.clear();
        } catch (Throwable ignore) {
        }
    }

    /**
     * Flag an app that posts a flood of notifications in a short window
     * (notification-spam adware). Trusted apps are filtered out by the caller.
     */
    private void checkNotificationSpam(String pkg) {
        try {
            long now = System.currentTimeMillis();
            long[] c = notifCounters.get(pkg);
            if (c == null || now - c[0] > NOTIF_WINDOW_MS) {
                notifCounters.put(pkg, new long[]{now, 1});
            } else {
                c[1]++;
                if (c[1] >= NOTIF_THRESHOLD) {
                    String reason = "Notification spam: " + c[1] + " notifications in "
                        + (NOTIF_WINDOW_MS / 1000) + "s";
                    Log.e(TAG, "BEHAVIOUR MALWARE (" + pkg + "): " + reason);
                    BehaviorFlags.flag(this, pkg, reason);
                    sendAlert("NOTIFICATION SPAM (malware)", pkg + " — " + reason);
                    notifCounters.put(pkg, new long[]{now, 1});  // reset window
                }
            }
            if (notifCounters.size() > 400) notifCounters.clear();
        } catch (Throwable ignore) {
        }
    }

    @Override
    public void onInterrupt() {}

    private void sendAlert(String title, String message) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        // Bring HydraDragon to the foreground (popup + redirect), not just a
        // silent notification: open MainActivity with the alert details.
        android.content.Intent open = new android.content.Intent(this,
                com.hydradragon.antivirus.MainActivity.class);
        open.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                | android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                | android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP);
        open.putExtra("alert_title", title);
        open.putExtra("alert_message", message);
        android.app.PendingIntent pi = android.app.PendingIntent.getActivity(
                this, (int) System.currentTimeMillis(), open,
                android.app.PendingIntent.FLAG_IMMUTABLE
                        | android.app.PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_threat)
                .setContentTitle(title)
                .setContentText(message)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setColor(0xFF0000)
                .setAutoCancel(true)
                .setContentIntent(pi)
                .setFullScreenIntent(pi, true);   // heads-up / full-screen popup

        nm.notify((int) System.currentTimeMillis(), builder.build());

        // Also try to redirect immediately (accessibility services can usually
        // start activities even from the background).
        try {
            startActivity(open);
        } catch (Throwable ignore) {
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Dynamic Analysis Alerts",
                    NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Alerts for malicious UI interactions");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }
}