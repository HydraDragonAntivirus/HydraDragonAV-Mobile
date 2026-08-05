package com.hydradragon.antivirus.service;

import android.accessibilityservice.AccessibilityService;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.core.app.NotificationCompat;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.BehaviorFlags;
import com.hydradragon.antivirus.model.ThreatResult;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class DynamicAnalysisService extends AccessibilityService {
    private static final String TAG = "HydraDragon-Dynamic";
    private static final String CHANNEL_ID = "hydradragon_dynamic_alert";

    // Each AccessibilityNodeInfo access (getChild/getText) is a Binder call
    // into the FOREGROUND app's own process. A slow, hung, or deliberately
    // obstructive app (the exact profile of "unknown/malware") can stall
    // those calls indefinitely; running the walk on this service's event
    // thread would then block all further accessibility event delivery until
    // it finally returns. Run it on its own thread instead, so a stuck target
    // app only stalls this one worker, never event dispatch. Single-threaded:
    // walks are cheap/rare enough (window-switch only) that overlap isn't a
    // concern, and it keeps ordering simple.
    private final ExecutorService nodeWalkExecutor = Executors.newSingleThreadExecutor();
    /** True while a walk is in flight — a second window switch during a stuck
     *  walk is dropped rather than queued, since a queued backlog against a
     *  hung target would only grow forever. */
    private final AtomicBoolean nodeWalkBusy = new AtomicBoolean(false);
    /** Hard cap on nodes visited per walk — bounds worst-case cost even
     *  against a hostile app that returns a huge/cyclic-looking tree. */
    private static final int MAX_NODES_PER_WALK = 500;

    private long lastClickTime = 0;
    private int rapidClickCount = 0;

    // ── Behavioural spam detection ──────────────────────────────────────────
    /** Same event signature N+ times within the window => spam => malware. */
    private static final int SPAM_THRESHOLD = 100;
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
    /** Same value, static so ScreenCaptureService (a separate service, not this
     *  Accessibility instance) can attribute an OCR'd screen frame to the app
     *  that was actually on screen when it was captured. */
    private static volatile String sForegroundPackage = "";

    /** Best-known foreground package name, or "" if none observed yet. */
    public static String getForegroundPackage() { return sForegroundPackage; }

    private static volatile DynamicAnalysisService sInstance = null;

    /** @return the current service instance, or null if not connected. */
    public static DynamicAnalysisService getInstance() { return sInstance; }

    // Single, self-replacing alert notification (no spam).
    private static final int ALERT_NOTIF_ID = 0xA1E7;
    private volatile String lastUrlAlert = "";
    private long lastAlertTime = 0;
    private String lastAlertMsg = "";

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
        sInstance = this;
        Log.i(TAG, "Dynamic Analysis Accessibility Service Connected");
        createNotificationChannel();
    }

    /** Last time (elapsedRealtime ms) the user pressed a physical volume key,
     *  or -1 if none yet. GuardService#checkAudioScareware uses this to tell a
     *  USER-initiated volume rise (finger on the rocker → not malware) apart
     *  from an app slamming the volume programmatically. Written from this
     *  service's main thread; read from GuardService's scheduler thread —
     *  volatile is enough since the value is a single monotonic timestamp. */
    public static volatile long lastUserVolumeKeyMs = -1L;

    @Override
    public boolean onKeyEvent(android.view.KeyEvent event) {
        if (event != null) {
            int code = event.getKeyCode();
            if (code == android.view.KeyEvent.KEYCODE_VOLUME_UP
                || code == android.view.KeyEvent.KEYCODE_VOLUME_DOWN) {
                if (event.getAction() == android.view.KeyEvent.ACTION_DOWN) {
                    lastUserVolumeKeyMs = android.os.SystemClock.elapsedRealtime();
                }
                // Never consume the event — let the system adjust volume as normal.
            }
        }
        return super.onKeyEvent(event);
    }

    /** Convenience: true if the user pressed a physical volume key within
     *  {@code windowMs} before {@code now} (elapsedRealtime). */
    public static boolean userPressedVolumeKeyWithin(long now, long windowMs) {
        long last = lastUserVolumeKeyMs;
        return last != -1L && (now - last) <= windowMs;
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;
        // Protection paused by the user -> the antivirus stays silent: no
        // behaviour/URL detection, no alerts, no block pages.
        if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(this)) return;
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
        boolean uiSpamEnabled = com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(
            this, com.hydradragon.antivirus.engine.BehaviorDetectionSettings.UI_SPAM);

        // Notification spam: an app firing many notifications in a short window.
        if (eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED) {
            if (!trusted && uiSpamEnabled) checkNotificationSpam(pkg);
            return;
        }

        // Behavioural detection: an app that repeats the SAME event/content far
        // too often (overlay/dialog/toast/click spam) is acting maliciously.
        // Restricted to click/window events — TYPE_VIEW_SCROLLED,
        // TYPE_VIEW_TEXT_CHANGED, TYPE_WINDOW_CONTENT_CHANGED etc. fire
        // constantly during completely normal use (scrolling a list, a video
        // player's progress ticking, a chat/game UI updating) and were
        // tripping this at 30 identical events / 8s — a false positive, not a
        // sign of adware/clicker/ransomware behaviour.
        if (!trusted && uiSpamEnabled && (eventType == AccessibilityEvent.TYPE_VIEW_CLICKED
                || eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED)) {
            checkSpamBehavior(event, pkg);
        }

        boolean isInstaller = packageName.toString().contains("packageinstaller") ||
                              packageName.toString().contains("permissioncontroller");
        boolean isSettings = packageName.toString().equals("com.android.settings");

        if (eventType == AccessibilityEvent.TYPE_VIEW_CLICKED) {
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastClickTime < 200) { 
                rapidClickCount++;
            } else {
                rapidClickCount = 1;
            }
            lastClickTime = currentTime;

            if (rapidClickCount >= 8 && (isInstaller || isSettings)) {
                Log.w(TAG, "DETECTED: Automated Clickjacking/Permission granting!");
                com.hydradragon.antivirus.engine.HipsMonitor.reportClickjack(pkg, rapidClickCount,
                    packageName.toString(), 2, true);
                sendAlert("CRITICAL: Automated UI Hijacking Detected", "Malware is trying to auto-click permissions. Action blocked!", pkg);

                performGlobalAction(GLOBAL_ACTION_BACK);   // dismiss the overlay
                redirectIfNotDismissed(pkg);                // -> antivirus screen, not home
                rapidClickCount = 0;
            }
        }

        if (eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED ||
            eventType == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {

            if (eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                // prevPkg (still the OLD fgPackage here) is the candidate
                // "target" if this switch lands on a device-admin/uninstall
                // screen — see RemovalResistanceGuard.
                com.hydradragon.antivirus.engine.RemovalResistanceGuard.onWindowSwitch(
                    this, pkg, fgPackage, isInstaller || isSettings);

                sForegroundPackage = pkg;
                // fgPackage is STILL the previous foreground here: if that
                // previous app is already behavior-flagged, it brought this
                // new app (and its activity class) on screen — "malware opened
                // Chrome". See checkLaunchTransition.
                checkLaunchTransition(fgPackage, pkg, event.getClassName());
                boolean behFlagged = BehaviorFlags.isFlagged(this, pkg)
                    && !com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, pkg);
                boolean scanFlagged = com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(pkg, "SCAN_MALWARE")
                    || com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(pkg, "DOWNLOAD_MALWARE");
                if (!trusted && (behFlagged || scanFlagged)) {
                    Log.e(TAG, "FLAGGED MALWARE OPENED ON SCREEN: " + pkg);
                    // Prefer the full stored reason (BehaviorFlags keeps every
                    // detection reason joined with newlines); fall back to the
                    // generic scan-detected string only if nothing was stored.
                    String stored = BehaviorFlags.reasonFor(this, pkg);
                    String reason = (stored != null && !stored.isEmpty())
                        ? stored : getString(R.string.reason_scan_detected_malware);
                    java.util.List<String> reasonList = java.util.Arrays.asList(reason.split("\n"));
                    ThreatResult threat = new ThreatResult.Builder(pkg)
                            .setAppName(pkg)
                            .setRiskScore(100)
                            .setThreatType(ThreatResult.ThreatType.MALWARE)
                            .setReasons(reasonList)
                            .build();
                    com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(this, threat);
                }
            }

            fgPackage = pkg;   // remember which app's content we're scanning
            sForegroundPackage = pkg;
            if (!trusted) {
                com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.onForegroundPermissionCheck(this, pkg);
            }

            // Trusted system apps (Settings, SystemUI, ...) have no legitimate
            // reason to be scanned for ransomware/phishing text — EXCEPT we
            // still need to read the installer/settings screen itself to spot
            // an uninstall/device-admin prompt (RemovalResistanceGuard), so
            // those two aren't skipped here despite being trusted. Also only
            // on an actual window switch, not TYPE_WINDOW_CONTENT_CHANGED
            // (fires continuously during scrolling/list updates).
            if ((!trusted || isInstaller || isSettings)
                    && eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                AccessibilityNodeInfo rootNode = getRootInActiveWindow();
                if (rootNode != null) {
                    // Every node.getChild()/getText() below is a Binder call
                    // into the FOREGROUND app's own process. A slow, hung, or
                    // deliberately obstructive app — the exact profile of
                    // "unknown/malware" — can stall those calls for a long
                    // time; running the walk inline here would block this
                    // service's event-handling thread until it returns,
                    // backing up ALL further accessibility event delivery
                    // (the actual cause of the lag, not event frequency).
                    // Offload to a dedicated worker so a stuck target only
                    // stalls that one thread. Drop (don't queue) a new walk
                    // while one is still in flight — queuing against a
                    // genuinely hung target would only grow unbounded.
                    if (nodeWalkBusy.compareAndSet(false, true)) {
                        nodeWalkExecutor.execute(() -> {
                            try {
                                checkNodesForSuspiciousKeywords(rootNode, new int[]{0});
                            } finally {
                                rootNode.recycle();
                                nodeWalkBusy.set(false);
                            }
                        });
                    } else {
                        rootNode.recycle();
                    }
                }
            }
        }
    }

    /** {@code budget[0]} is the running node count, shared across the whole
     *  recursive walk — caps total Binder calls even against a hostile app
     *  that returns a huge or effectively-cyclic-looking tree. */
    private void checkNodesForSuspiciousKeywords(AccessibilityNodeInfo node, int[] budget) {
        if (node == null || budget[0]++ >= MAX_NODES_PER_WALK) return;

        CharSequence text = node.getText();
        if (text != null) {
            String lowerText = text.toString().toLowerCase();
            // RANSOMWARE MITIGATION (multi-language — see ScreenThreatKeywords)
            if (com.hydradragon.antivirus.engine.ScreenThreatKeywords.containsAtLeast(
                    lowerText, com.hydradragon.antivirus.engine.ScreenThreatKeywords.RANSOMWARE, 2)) {
                Log.e(TAG, "RANSOMWARE TEXT DETECTED in " + fgPackage);
                // Relatedness: a standalone app showing a full-screen "files
                // encrypted" lock IS ransomware -> nuke. The same text inside a
                // browser is almost always an article/tech-support-scam page ->
                // warn only, don't close the browser.
                if (!BROWSERS.contains(fgPackage)) {
                    if (!com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, fgPackage)) {
                        sendAlert(getString(R.string.ransomware_blocked_title),
                            getString(R.string.ransomware_blocked_msg), fgPackage);
                        redirectIfNotDismissed(fgPackage);
                    }
                } else {
                    sendAlert(getString(R.string.scam_page_title), getString(R.string.scam_page_msg));
                }
            }

            if (com.hydradragon.antivirus.engine.ScreenThreatKeywords.containsAny(
                    lowerText, com.hydradragon.antivirus.engine.ScreenThreatKeywords.DEVICE_ADMIN)) {
                Log.d(TAG, "Device Admin activation/deactivation screen visible.");
                com.hydradragon.antivirus.engine.RemovalResistanceGuard.confirmSensitiveScreenText("device_admin");
            }

            if (com.hydradragon.antivirus.engine.ScreenThreatKeywords.containsAny(
                    lowerText, com.hydradragon.antivirus.engine.ScreenThreatKeywords.UNINSTALL)) {
                com.hydradragon.antivirus.engine.RemovalResistanceGuard.confirmSensitiveScreenText("uninstall");
            }

            // SMS SCAM / PHISHING MITIGATION (multi-language). Screen-text based —
            // catches smishing lures wherever they're displayed (Messages app,
            // notification preview, a WebView popup impersonating a bank/carrier),
            // not just in a real browser. Never blocks the app (it's usually the
            // legitimate Messages/notification UI showing someone else's scam
            // text) — just warns so the user doesn't tap the link or reply.
            // Threshold match (2+ distinct lures) — most individual phrases also
            // show up in genuine account/shipping texts, so a single hit alone
            // isn't strong enough evidence.
            if (com.hydradragon.antivirus.engine.ScreenThreatKeywords.containsAtLeast(
                    lowerText, com.hydradragon.antivirus.engine.ScreenThreatKeywords.SMS_PHISHING, 2)) {
                String id = "smsphish:" + fgPackage;
                if (!com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, id)) {
                    Log.w(TAG, "SMS SCAM/PHISHING TEXT DETECTED in " + fgPackage);
                    sendAlert(getString(R.string.sms_phishing_title),
                        getString(R.string.sms_phishing_msg, fgPackage), id);
                }
            }

            // FAKE VIRUS WARNING / TECH-SUPPORT SCAM MITIGATION (multi-language).
            // Screen-text based — a full-screen "N viruses found, call this number"
            // popup is virtually always a browser/WebView scam page, never a real
            // scan result (this app's own scan UI is excluded above). Warn only —
            // it's a web page, not malware to remove.
            if (com.hydradragon.antivirus.engine.ScreenThreatKeywords.containsAtLeast(
                    lowerText, com.hydradragon.antivirus.engine.ScreenThreatKeywords.FAKE_VIRUS_WARNING, 2)) {
                String id = "fakevirus:" + fgPackage;
                if (!com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, id)) {
                    Log.w(TAG, "FAKE VIRUS WARNING TEXT DETECTED in " + fgPackage);
                    sendAlert(getString(R.string.fake_virus_warning_title),
                        getString(R.string.fake_virus_warning_msg, fgPackage), id);
                }
            }

            // Website scan: ONLY in a real browser (or an already-flagged malware
            // app), where the URL is actually being VISITED. We don't scan URLs
            // that merely appear as text elsewhere (a scan result showing a URL
            // found inside an APK, a chat message, a note) — that's not a visit,
            // so calling it "blocked" would be wrong.
            boolean urlContext = BROWSERS.contains(fgPackage)
                || BehaviorFlags.isFlagged(this, fgPackage);
            if (urlContext) {
                try {
                    com.hydradragon.antivirus.engine.UrlThreatScanner scanner =
                        com.hydradragon.antivirus.engine.UrlThreatScanner.get(this);
                    for (String url : com.hydradragon.antivirus.engine.UrlThreatScanner
                            .extractUrls(text.toString())) {
                        String cat = scanner.scanUrl(url);
                        if (cat != null && !url.equals(lastUrlAlert)
                                && !com.hydradragon.antivirus.engine.UserDecisions
                                        .isThreatAllowed(this, url)) {
                            lastUrlAlert = url;   // dedup: don't re-alert same URL
                            Log.e(TAG, "MALICIOUS URL (" + cat + "): " + url + " in " + fgPackage);
                            sendAlert("MALICIOUS WEBSITE BLOCKED", cat + ": " + url, url);
                            showBlockPageIfNotDismissed(url, cat);
                            break;
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "url scan failed", t);
                }
            }
        }
        
        for (int i = 0; i < node.getChildCount() && budget[0] < MAX_NODES_PER_WALK; i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                checkNodesForSuspiciousKeywords(child, budget);
                child.recycle();
            }
        }
    }

    /**
     * A window switch where the PREVIOUS foreground package is already
     * behavior-flagged means that app brought the new app on screen. Record
     * the exact activity class (AccessibilityEvent.getClassName, e.g.
     * {@code org.chromium.chrome.browser.ChromeLauncherActivity}) as an
     * APP_LAUNCH flag so the YARA-X {@code hydradragon.behavior_flagged} check
     * can match "malware opened Chrome" without shipping static rules.
     */
    private void checkLaunchTransition(String fromPkg, String toPkg, CharSequence className) {
        try {
            if (fromPkg == null || fromPkg.isEmpty() || fromPkg.equals(toPkg)) return;
            if (toPkg == null || toPkg.isEmpty() || toPkg.startsWith("com.hydradragon.antivirus")) return;
            if (!com.hydradragon.antivirus.engine.HipsMonitor.hasAnyBehaviorFlag(fromPkg)) return;

            String flag = "APP_LAUNCH:from=" + fromPkg + ":to=" + toPkg;
            if (className != null && className.length() > 0) {
                flag += ":class=" + className;
            }
            com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(fromPkg, flag);
        } catch (Throwable t) {
            Log.w(TAG, "checkLaunchTransition failed", t);
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
                // Report to HIPS monitor regardless of threshold
                com.hydradragon.antivirus.engine.HipsMonitor.reportUiSpam(pkg, (int)c[1], 1, SPAM_WINDOW_MS, c[1] >= SPAM_THRESHOLD);
                if (c[1] >= SPAM_THRESHOLD) {
                    // Rate-limit alerts per package to once per window.
                    Long last = spamFlagged.get(pkg);
                    if ((last == null || now - last > SPAM_WINDOW_MS)
                            && !com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, pkg)) {
                        spamFlagged.put(pkg, now);
                        String reason = "Spam behaviour: same UI event x" + c[1]
                            + " in " + (SPAM_WINDOW_MS / 1000) + "s";
                        Log.e(TAG, "BEHAVIOUR MALWARE (" + pkg + "): " + reason);
                        BehaviorFlags.flag(this, pkg, reason);
                        sendAlert("MALWARE BEHAVIOUR BLOCKED", pkg + " — " + reason, pkg);
                        redirectIfNotDismissed(pkg);
                        com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(this, pkg);
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
                // Report to HIPS monitor
                com.hydradragon.antivirus.engine.HipsMonitor.reportNotificationSpam(pkg, (int)c[1], NOTIF_WINDOW_MS, c[1] >= NOTIF_THRESHOLD);
                if (c[1] >= NOTIF_THRESHOLD
                        && !com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, pkg)) {
                    String reason = "Notification spam: " + c[1] + " notifications in "
                        + (NOTIF_WINDOW_MS / 1000) + "s";
                    Log.e(TAG, "BEHAVIOUR MALWARE (" + pkg + "): " + reason);
                    BehaviorFlags.flag(this, pkg, reason);
                    sendAlert("NOTIFICATION SPAM (malware)", pkg + " — " + reason, pkg);
                    redirectIfNotDismissed(pkg);
                    com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(this, pkg);
                    notifCounters.put(pkg, new long[]{now, 1});  // reset window
                }
            }
            if (notifCounters.size() > 400) notifCounters.clear();
        } catch (Throwable ignore) {
        }
    }

    @Override
    public void onInterrupt() {}

    @Override
    public void onDestroy() {
        super.onDestroy();
        nodeWalkExecutor.shutdownNow();
    }

    private void sendAlert(String title, String message) {
        sendAlert(title, message, null);
    }

    private void sendAlert(String title, String message, String threatId) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        // Anti-spam: drop a repeat of the same message within 5s, and always
        // reuse one notification id so a new alert REPLACES the previous one
        // instead of stacking dozens.
        long now = System.currentTimeMillis();
        if (message != null && message.equals(lastAlertMsg) && now - lastAlertTime < 5_000) {
            return;
        }
        lastAlertMsg = message;
        lastAlertTime = now;

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
                .setContentIntent(pi);   // tap to open HydraDragon (no full-screen popup)

        if (threatId != null && !threatId.isEmpty()) {
            // "Safe (ignore)" -> allowlist this package/URL, never flag again.
            android.content.Intent ig = new android.content.Intent(
                    this, UserActionReceiver.class)
                    .setAction(UserActionReceiver.ACTION_IGNORE)
                    .putExtra(UserActionReceiver.EXTRA_ID, threatId)
                    .putExtra(UserActionReceiver.EXTRA_NOTIF, ALERT_NOTIF_ID);
            android.app.PendingIntent igPi = android.app.PendingIntent.getBroadcast(
                    this, threatId.hashCode(), ig,
                    android.app.PendingIntent.FLAG_IMMUTABLE
                            | android.app.PendingIntent.FLAG_UPDATE_CURRENT);
            builder.addAction(R.drawable.ic_threat, "Safe (ignore)", igPi);

            // Swiping the alert away records a redirect dismissal for this id.
            android.content.Intent dm = new android.content.Intent(
                    this, UserActionReceiver.class)
                    .setAction(UserActionReceiver.ACTION_DISMISS)
                    .putExtra(UserActionReceiver.EXTRA_ID, threatId);
            android.app.PendingIntent dmPi = android.app.PendingIntent.getBroadcast(
                    this, threatId.hashCode() + 1, dm,
                    android.app.PendingIntent.FLAG_IMMUTABLE
                            | android.app.PendingIntent.FLAG_UPDATE_CURRENT);
            builder.setDeleteIntent(dmPi);
        }

        nm.notify(ALERT_NOTIF_ID, builder.build());   // fixed id -> replaces previous

        // Record every live detection (URL / ransomware / spam / clickjacking)
        // in the threat history.
        try {
            ThreatLogger.logThreat(this, threatId != null ? threatId : "-", title, message);
        } catch (Throwable ignore) {
        }
    }

    /**
     * Show a full-screen HTML "site blocked" warning page INSTEAD of the
     * malicious site (and instead of kicking the user to the antivirus screen),
     * unless the user dismissed the block for this URL.
     */
    private void showBlockPageIfNotDismissed(String url, String cat) {
        if (url != null
                && com.hydradragon.antivirus.engine.UserDecisions.isRedirectDismissed(this, url)) {
            return;
        }
        try {
            android.content.Intent i = new android.content.Intent(
                    this, com.hydradragon.antivirus.ui.BlockActivity.class);
            i.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                    | android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                    | android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP);
            i.putExtra(com.hydradragon.antivirus.ui.BlockActivity.EXTRA_URL, url);
            i.putExtra(com.hydradragon.antivirus.ui.BlockActivity.EXTRA_CAT, cat);
            startActivity(i);
        } catch (Throwable ignore) {
        }
    }

    /** Redirect to the antivirus screen unless the user dismissed it for this id. */
    private void redirectIfNotDismissed(String threatId) {
        if (threatId == null
                || !com.hydradragon.antivirus.engine.UserDecisions
                        .isRedirectDismissed(this, threatId)) {
            redirectToApp(threatId);
        }
    }

    private void redirectToApp() {
        redirectToApp(null);
    }

    /**
     * Bring the HydraDragon screen to the foreground — used INSTEAD of kicking
     * the user to the home screen. We never send the device home from the UI;
     * we redirect to the antivirus screen so the user lands on protection, not
     * an empty launcher.
     */
    private void redirectToApp(String threatId) {
        try {
            android.content.Intent open = new android.content.Intent(this,
                    com.hydradragon.antivirus.MainActivity.class);
            open.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                    | android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                    | android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP);
            open.putExtra("open_scan_tab", true);
            if (threatId != null && !threatId.isEmpty()) {
                String appName = threatId;
                try {
                    android.content.pm.ApplicationInfo ai = getPackageManager().getApplicationInfo(threatId, 0);
                    appName = getPackageManager().getApplicationLabel(ai).toString();
                } catch (Throwable ignored) {}
                open.putExtra("alert_threat_name", appName);
                open.putExtra("alert_threat_pkg", threatId);
                open.putExtra("alert_threat_reason", "Malicious behavior detected");
                open.putExtra("alert_threat_risk", 100);
            }
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