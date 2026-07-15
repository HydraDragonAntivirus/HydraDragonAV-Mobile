package com.hydradragon.antivirus.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.hydradragon.antivirus.MainActivity;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.AIEngine;
import com.hydradragon.antivirus.engine.NetworkMonitor;
import com.hydradragon.antivirus.engine.ProcessDetector;
import com.hydradragon.antivirus.engine.ScanEngine;
import com.hydradragon.antivirus.model.ProcessInfo;
import com.hydradragon.antivirus.model.ThreatResult;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class GuardService extends Service {

    /** Opt-in (Settings > "Real-time full storage monitoring", off by default —
     *  see startFullStorageMonitor). Downloads is always watched regardless. */
    public static final String KEY_REALTIME_STORAGE_WATCH = "realtime_storage_watch";

    private android.os.FileObserver downloadObserver;
    private final java.util.List<android.os.FileObserver> extraStorageObservers = new java.util.ArrayList<>();

    private void startDownloadMonitor() {
        java.io.File downloadDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS);
        if (downloadDir.exists()) {
            // CLOSE_WRITE alone isn't enough: while a download is still in
            // progress, Android/the browser writes to a TEMPORARY
            // ".pending-<id>-realname.ext" file (MediaStore's "pending"
            // convention) — CLOSE_WRITE can fire on THAT file while it's
            // still incomplete (zip central directory not fully written
            // yet), so scanning it there fails to even open the archive and
            // never finds anything. Once the download finishes, the system
            // renames it to its final visible name — a MOVED_TO event, not
            // another CLOSE_WRITE — which the old mask never listened for,
            // so the completed file was never scanned at all. Also skip the
            // ".pending-" file itself outright: it's guaranteed incomplete.
            int mask = android.os.FileObserver.CLOSE_WRITE | android.os.FileObserver.MOVED_TO;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                downloadObserver = new android.os.FileObserver(downloadDir, mask) {
                    @Override
                    public void onEvent(int event, String path) {
                        if (path == null || path.startsWith(".pending-")) return;
                        com.hydradragon.antivirus.engine.RansomwareBehaviorGuard
                            .onFileEvent(GuardService.this, downloadDir.getAbsolutePath(), path);
                        java.io.File file = new java.io.File(downloadDir, path);
                        scanDownloadedFile(file);
                    }
                };
            } else {
                downloadObserver = new android.os.FileObserver(downloadDir.getAbsolutePath(), mask) {
                    @Override
                    public void onEvent(int event, String path) {
                        if (path == null || path.startsWith(".pending-")) return;
                        com.hydradragon.antivirus.engine.RansomwareBehaviorGuard
                            .onFileEvent(GuardService.this, downloadDir.getAbsolutePath(), path);
                        java.io.File file = new java.io.File(downloadDir, path);
                        scanDownloadedFile(file);
                    }
                };
            }
            downloadObserver.startWatching();
        }
    }

    /** Optional (Settings toggle, default OFF — battery/CPU cost of one watcher
     *  thread per storage root): real-time detection for files dropped straight
     *  onto external/SD storage from a computer (USB/MTP), OUTSIDE Downloads —
     *  the periodic Full Scan above still catches those, just not instantly.
     *  Each observer only watches its root's immediate children (Android's
     *  FileObserver isn't recursive) — a file copied into a SUBFOLDER of a
     *  storage root still waits for the periodic Full Scan, same trade-off the
     *  user was told about when enabling this. */
    private void startFullStorageMonitor() {
        if (!getSharedPreferences("hydra_prefs", MODE_PRIVATE)
                .getBoolean(KEY_REALTIME_STORAGE_WATCH, false)) {
            return;
        }
        java.util.LinkedHashSet<String> roots = new java.util.LinkedHashSet<>();
        try {
            java.io.File primary = android.os.Environment.getExternalStorageDirectory();
            if (primary != null) roots.add(primary.getAbsolutePath());
        } catch (Throwable ignore) { }
        try {
            java.io.File[] vols = new java.io.File("/storage").listFiles();
            if (vols != null) for (java.io.File v : vols) {
                String n = v.getName();
                if (v.isDirectory() && v.canRead() && !n.equals("self") && !n.equals("emulated"))
                    roots.add(v.getAbsolutePath());
            }
        } catch (Throwable ignore) { }

        for (String rootPath : roots) {
            java.io.File root = new java.io.File(rootPath);
            android.os.FileObserver obs;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                obs = new android.os.FileObserver(root, android.os.FileObserver.CLOSE_WRITE) {
                    @Override
                    public void onEvent(int event, String path) {
                        if (path == null) return;
                        com.hydradragon.antivirus.engine.RansomwareBehaviorGuard
                            .onFileEvent(GuardService.this, rootPath, path);
                        scanDownloadedFile(new java.io.File(root, path));
                    }
                };
            } else {
                obs = new android.os.FileObserver(rootPath, android.os.FileObserver.CLOSE_WRITE) {
                    @Override
                    public void onEvent(int event, String path) {
                        if (path == null) return;
                        com.hydradragon.antivirus.engine.RansomwareBehaviorGuard
                            .onFileEvent(GuardService.this, rootPath, path);
                        scanDownloadedFile(new java.io.File(root, path));
                    }
                };
            }
            obs.startWatching();
            extraStorageObservers.add(obs);
        }
        Log.i(TAG, "Real-time full storage monitoring: watching " + roots.size() + " root(s)");
    }

    /** Fired by the Downloads-folder FileObserver on CLOSE_WRITE — a file just
     *  finished being written (download complete, or moved/copied in). Runs a
     *  REAL scan (native YARA/ClamAV/ML for any file type, the full analyzeApp
     *  pipeline for an APK) off the observer thread. On a hit, the file is NOT
     *  auto-deleted — the user is asked via a Remove/Ignore notification, same
     *  as every other detection path in this app. */
    private void scanDownloadedFile(java.io.File file) {
        com.hydradragon.antivirus.engine.ScanEngine.runOrchestrated(() -> {
            ThreatResult threat = null;
            try {
                threat = scanEngine.scanSingleFile(file);
            } catch (Throwable t) {
                Log.e(TAG, "download scan failed: " + file, t);
            }

            android.app.NotificationManager nm = getSystemService(android.app.NotificationManager.class);
            if (nm == null) return;
            int notifId = (int) System.currentTimeMillis();
            androidx.core.app.NotificationCompat.Builder builder = new androidx.core.app.NotificationCompat.Builder(this, "hydradragon_guard")
                    .setAutoCancel(true)
                    .setPriority(androidx.core.app.NotificationCompat.PRIORITY_MAX)
                    .setDefaults(android.app.Notification.DEFAULT_ALL);

            if (threat == null) {
                builder.setSmallIcon(R.drawable.ic_shield_secure)
                       .setContentTitle(getString(R.string.safe_download_title))
                       .setContentText(file.getName() + " " + getString(R.string.safe_download_desc))
                       .setColor(0x00FF88);
            } else {
                Log.e(TAG, "MALICIOUS DOWNLOAD: " + file.getAbsolutePath());
                ThreatLogger.logThreat(this, threat, getString(R.string.danger_download_desc));
                if (callback != null) callback.onThreatDetected(threat);

                android.content.Intent removeIntent = new android.content.Intent(this, UserActionReceiver.class)
                        .setAction(UserActionReceiver.ACTION_REMOVE_FILE)
                        .putExtra(UserActionReceiver.EXTRA_ID, file.getAbsolutePath())
                        .putExtra(UserActionReceiver.EXTRA_NOTIF, notifId);
                PendingIntent removePI = PendingIntent.getBroadcast(this, notifId, removeIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

                android.content.Intent ignoreIntent = new android.content.Intent(this, UserActionReceiver.class)
                        .setAction(UserActionReceiver.ACTION_IGNORE)
                        .putExtra(UserActionReceiver.EXTRA_ID, file.getAbsolutePath())
                        .putExtra(UserActionReceiver.EXTRA_NOTIF, notifId);
                PendingIntent ignorePI = PendingIntent.getBroadcast(this, notifId + 1, ignoreIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

                builder.setSmallIcon(R.drawable.ic_shield_alert)
                       .setContentTitle(getString(R.string.danger_download_title))
                       .setContentText(file.getName() + ": " + getString(R.string.danger_download_desc))
                       .setColor(0xFF0040)
                       .addAction(0, getString(R.string.btn_destroy), removePI)
                       .addAction(0, getString(R.string.btn_ignore), ignorePI);
            }
            nm.notify(notifId, builder.build());
        });
    }


    public static java.util.Set<String> unlockedApps = new java.util.HashSet<>();
    private Thread lockThread;
    
    


    private static final String TAG = "HydraDragon-Guard";
    // Package-visible (not private): DnsVpnService reuses this SAME channel +
    // notification ID for its own foreground requirement (Android mandates
    // every foreground Service posts one) so Web Shield never shows as a
    // SECOND separate "HydraDragon Antivirus / System protected" notification
    // — see DnsVpnService#startForegroundShield / #teardown.
    static final String CHANNEL_ID = "hydradragon_guard";
    static final int NOTIFICATION_ID = 1001;
    private static final int ALERT_NOTIFICATION_BASE = 2000;

    private AIEngine aiEngine;
    private ScanEngine scanEngine;
    /** Separate engine for background periodic + startup scans — has its own
     *  {@code scanRunning}, so user-initiated scans on {@link #scanEngine}
     *  are NEVER blocked by background scans. */
    private ScanEngine backgroundScanEngine;
    private NetworkMonitor networkMonitor;
    private ProcessDetector processDetector;
    private volatile boolean engineLoading = true;
    private ScheduledExecutorService scheduler;
    private int alertNotificationId = ALERT_NOTIFICATION_BASE;
    /** Root state as of the LAST check — starts false since MainActivity already
     *  refuses to launch on an already-rooted device (see RootCheck), so any
     *  transition to true observed here happened WHILE this app was running. */
    private volatile boolean wasRooted = false;

    private final IBinder binder = new GuardBinder();
    private GuardCallback callback;
    /** ScanFragment's live UI callback — set/cleared via setUiScanCallback().
     *  NEVER replaces scanEngine's actual callback (see initializeEngines):
     *  that one is set ONCE, permanently, so notifications/ThreatLogger
     *  entries keep firing for a periodic BACKGROUND scan even while no UI is
     *  attached (or after the Scan tab has been closed) — it used to be that
     *  ScanFragment called scanEngine.setCallback(...) directly, silently
     *  replacing this permanent callback and killing all future
     *  notifications/logging the moment the user ever opened the Scan tab. */
    private volatile ScanEngine.ScanCallback uiScanCallback;

    /** Called by ScanFragment instead of touching ScanEngine's callback
     *  directly. Pass {@code null} when the fragment goes away (onStop) so a
     *  stale reference isn't held past the fragment's lifecycle. */
    public void setUiScanCallback(ScanEngine.ScanCallback cb) { this.uiScanCallback = cb; }

    public interface GuardCallback {
        void onThreatDetected(ThreatResult threat);
        void onSuspiciousProcess(ProcessInfo process);
        void onNetworkAlert(NetworkMonitor.NetworkEvent event);
        void onStatusUpdate(String status);
    }

    public class GuardBinder extends Binder {
        public GuardService getService() { return GuardService.this; }
    }

    @Override
    public void onCreate() {

        super.onCreate();
        Log.i(TAG, "HydraDragon Guard starting...");
        createNotificationChannel();
        // startForeground() MUST run before any heavy init: initializeEngines()
        // copies the whole native scan asset bundle to disk and runs nativeInit
        // (YARA/ClamAV/xor filter loading), which can take longer than the
        // few seconds Android allows between startForegroundService() and
        // Service.startForeground() before raising an ANR — this used to be
        // masked because the native .so failed to load, making init a no-op.
        try {
            // Not "System protected" yet — MainActivity starts this service
            // before it even shows the mandatory/optional permission dialogs
            // (all files access, notifications, accessibility, ...), and
            // initializeEngines() below hasn't loaded the native scan engine
            // either. Claiming the device is protected while both are still
            // pending is misleading; this switches to the real status once
            // initializeEngines() actually finishes, below.
            startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.engine_loading_status), true));
        } catch (Throwable t) {
            Log.e(TAG, "startForeground failed", t);
        }
        new Thread(() -> {
            initializeEngines();
            engineLoading = false;
            Log.i(TAG, "engineLoading=false (engines ready)");
            updateNotification(getString(R.string.guard_protecting_status), true);
            // Startup anti-FP scan on the BACKGROUND engine (separate
            // instance → never blocks user-initiated scans).
            try {
                backgroundScanEngine.setBackgroundScan(true);
                backgroundScanEngine.scanAllAppsAntiFp();
            } catch (Throwable t) {
                Log.e(TAG, "Initial Anti-FP scan failed", t);
            }
            startServiceMonitors();
            startPeriodicScans();
            startDownloadMonitor();
            startFullStorageMonitor();
            Log.i(TAG, "Guard Service active");
        }, "guard-init").start();
    }

    private void initializeEngines() {
        aiEngine = new AIEngine(this);
        scanEngine = new ScanEngine(this, aiEngine);
        backgroundScanEngine = new ScanEngine(this, aiEngine);
        backgroundScanEngine.setBackgroundScan(true);
        backgroundScanEngine.setCallback(new ScanEngine.ScanCallback() {
            @Override public void onProgress(int c, int t, String p) { }
            @Override public void onThreatFound(ThreatResult threat) {
                ThreatLogger.logThreat(GuardService.this, threat, "BACKGROUND SCAN");
                if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) {
                    try {
                        if (com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(GuardService.this)) {
                            com.hydradragon.antivirus.engine.BehaviorResponse.autoDeleteThreat(
                                GuardService.this, threat);
                        } else {
                            com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                                GuardService.this, threat);
                        }
                    } catch (Throwable t) {
                        Log.e(TAG, "background auto-kill failed", t);
                    }
                }
            }
            @Override public void onScanComplete(com.hydradragon.antivirus.model.ScanResult r) { }
            @Override public void onFileScanned(com.hydradragon.antivirus.model.ScannedFileInfo i) { }
            @Override public void onError(String e) { }
        });
        networkMonitor = new NetworkMonitor(this);
        processDetector = new ProcessDetector(this);

        // Set ONCE — see uiScanCallback's javadoc for why ScanFragment must
        // never call scanEngine.setCallback() itself.
        scanEngine.setCallback(new ScanEngine.ScanCallback() {
            @Override
            public void onProgress(int current, int total, String packageName) {
                if (scanEngine.isBackgroundScan()) return;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onProgress(current, total, packageName);
            }

            @Override
            public void onThreatFound(ThreatResult threat) {
                if (scanEngine.isBackgroundScan()) return;
                // Always record to history; stay silent (no notification) while
                // protection is paused. Isolated like sendThreatNotification
                // below — a logging failure must never block the UI
                // forwarding at the end of this method.
                try {
                    ThreatLogger.logThreat(GuardService.this, threat, "SCAN DETECTED");
                } catch (Throwable t) {
                    Log.e(TAG, "ThreatLogger.logThreat failed", t);
                }
                // Isolated in its own try/catch: this whole onThreatFound() call
                // runs INSIDE ScanEngine's per-app loop, itself wrapped in a
                // silent catch(Exception) — any exception thrown here (bad
                // PendingIntent, null NotificationManager, etc.) used to abort
                // the rest of this method too, which meant the UI forwarding
                // below NEVER ran either: the scan looked like it found nothing,
                // both in the system tray AND in the app's own threat list.
                if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) {
                    // Silently handle threats during background/auto scans — no
                    // user-facing notification, no foreground-notification update.
                    if (!scanEngine.isBackgroundScan()) {
                        try {
                            sendThreatNotification(threat);
                        } catch (Throwable t) {
                            Log.e(TAG, "sendThreatNotification failed", t);
                        }
                    }

                    if (callback != null) callback.onThreatDetected(threat);
                }
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onThreatFound(threat);
            }

            @Override
            public void onScanComplete(com.hydradragon.antivirus.model.ScanResult result) {
                if (scanEngine.isBackgroundScan()) return;
                try {
                    String status = result.isClean()
                        ? getString(R.string.system_clean)
                        : "⚠ " + result.getThreatsFound() + " " + getString(R.string.threat);
                    updateNotification(status, result.isClean());
                    if (callback != null) callback.onStatusUpdate(status);
                } catch (Throwable t) {
                    Log.e(TAG, "onScanComplete notification/status update failed", t);
                }
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onScanComplete(result);
            }

            @Override
            public void onFileScanned(com.hydradragon.antivirus.model.ScannedFileInfo info) {
                if (scanEngine.isBackgroundScan()) return;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onFileScanned(info);
            }

            @Override
            public void onError(String error) {
                if (scanEngine.isBackgroundScan()) return;
                Log.e(TAG, "Scan error: " + error);
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onError(error);
            }
        });

        networkMonitor.setCallback(new NetworkMonitor.NetworkCallback() {
            @Override
            public void onSuspiciousActivity(NetworkMonitor.NetworkEvent event) {
                ThreatLogger.logThreat(GuardService.this, event.destIp, "Network", event.reason);
                if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) return;
                sendNetworkAlert(event);
                if (callback != null) callback.onNetworkAlert(event);
            }

            @Override
            public void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed) {}

            @Override
            public void onNetworkChange(boolean isConnected, String networkType) {
                Log.d(TAG, "Network changed: " + networkType);
            }
        });

        processDetector.setCallback(new ProcessDetector.ProcessCallback() {
            @Override
            public void onSuspiciousProcess(ProcessInfo processInfo) {
                if (processInfo.isCritical()) {
                    sendProcessAlert(processInfo);
                    if (callback != null) callback.onSuspiciousProcess(processInfo);
                }
            }

            @Override
            public void onProcessListUpdated(List<ProcessInfo> processes) {}
        });

        networkMonitor.startMonitoring();
    }

    private void startPeriodicScans() {
        if (com.hydradragon.antivirus.engine.ScanSchedule.isPeriodicScanEnabled(this)) {
            int quickMin = com.hydradragon.antivirus.engine.ScanSchedule.getQuickScanIntervalMinutes(this);
            int fullMin = com.hydradragon.antivirus.engine.ScanSchedule.getFullScanIntervalMinutes(this);
            boolean wakelock = com.hydradragon.antivirus.engine.ScanSchedule.isScanWakeLockEnabled(this);
            // Must outlive the scheduled tasks, so reference from the enclosing
            // instance rather than a captured local (which would be collected
            // after the first completion). Each periodic scan uses the
            // backgroundScanEngine (separate instance → own scanRunning).
            ScanEngine bg = backgroundScanEngine;
            scheduler.scheduleAtFixedRate(() -> {
                try { bg.setBackgroundScan(true); bg.scanAllApps(false); }
                catch (Throwable t) { Log.e(TAG, "Periodic quick scan failed", t); }
            }, quickMin, quickMin, TimeUnit.MINUTES);
            scheduler.scheduleAtFixedRate(() -> {
                try { bg.setBackgroundScan(true); bg.scanAllApps(true); }
                catch (Throwable t) { Log.e(TAG, "Periodic full scan failed", t); }
            }, fullMin, fullMin, TimeUnit.MINUTES);
            Log.i(TAG, "Periodic scans scheduled: quick=" + quickMin + "m, full=" + fullMin + "m, wakelock=" + wakelock);
        } else {
            Log.i(TAG, "Periodic scans disabled by user setting");
        }
    }

    private void startServiceMonitors() {
        scheduler = Executors.newScheduledThreadPool(4);

        scheduler.scheduleAtFixedRate(() -> {
            processDetector.scanRunningProcesses();
        }, 10, 60, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(this::checkRootTransition, 15, 60, TimeUnit.SECONDS);
    }

    private void checkRootTransition() {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.ROOT_EXPLOIT)) return;
        try {
            boolean rooted = com.hydradragon.antivirus.engine.RootCheck.isRooted();
            com.hydradragon.antivirus.engine.HipsMonitor.setRooted(rooted);
            if (rooted && !wasRooted) {
                wasRooted = true;
                String suspect = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
                Log.e(TAG, "ROOT EXPLOIT: device became rooted mid-session (foreground=" + suspect + ")");
                sendRootExploitAlert(suspect);
                ThreatLogger.logThreat(this,
                    (suspect != null && !suspect.isEmpty()) ? suspect : "unknown",
                    "Root Exploit",
                    "Device became rooted while running — foreground app: "
                        + (suspect != null && !suspect.isEmpty() ? suspect : "unknown"));
                if (suspect != null && !suspect.isEmpty()
                        && !com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, suspect)
                        && !com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, suspect)) {
                    com.hydradragon.antivirus.engine.BehaviorFlags.flag(this, suspect,
                        "🔓 Root exploit: device rooted while this app was in the foreground");
                    com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(this, suspect);
                }
            } else if (!rooted) {
                // Recheck each tick — a root manager app can be uninstalled/su
                // revoked, and we want the NEXT genuine transition to fire again.
                wasRooted = false;
            }
        } catch (Throwable ignore) { }
    }

    private void sendRootExploitAlert(String suspectPackage) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_process_alert)
            .setContentTitle(getString(R.string.notif_root_exploit_title))
            .setContentText(getString(R.string.notif_root_exploit_text)
                + (suspectPackage != null && !suspectPackage.isEmpty() ? " — " + suspectPackage : ""))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setColor(0xFF0040)
            .build();
        nm.notify(alertNotificationId++, notification);
    }

    private void sendThreatNotification(ThreatResult threat) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_threat)
            .setContentTitle(getString(R.string.malware_found_title))
            .setContentText(threat.getAppName() + " - Risk: " + threat.getRiskScore() + "/100")
            .setStyle(new NotificationCompat.BigTextStyle()
                .bigText(threat.getAppName() + "\n"
                    + "Risk Seviyesi: " + threat.getThreatLevel() + "\n"
                    + "Sebep: " + (threat.getReasons().isEmpty() ? "-" : threat.getReasons().get(0))))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(0xFF0040);

        // "Remove" -> system uninstall dialog for THIS exact package (only for an
        // installed app, not an .apk file on disk). User confirms; we can't
        // silently uninstall. Targets the related app only.
        String pkg = threat.getPackageName();
        if (pkg != null && !pkg.isEmpty() && (threat.getApkPath() == null
                || !threat.getApkPath().toLowerCase().endsWith(".apk"))) {
            Intent del = new Intent(Intent.ACTION_DELETE,
                    android.net.Uri.parse("package:" + pkg));
            del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            android.app.PendingIntent pi = android.app.PendingIntent.getActivity(
                    this, pkg.hashCode(), del,
                    android.app.PendingIntent.FLAG_IMMUTABLE
                            | android.app.PendingIntent.FLAG_UPDATE_CURRENT);
            builder.setContentIntent(pi)
                   .addAction(R.drawable.ic_threat, "Remove", pi);
        }

        nm.notify(alertNotificationId++, builder.build());
    }

    private void sendNetworkAlert(NetworkMonitor.NetworkEvent event) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_network_alert)
            .setContentTitle(getString(R.string.notif_suspicious_network_title))
            .setContentText(event.destIp + ":" + event.destPort + " → " + event.reason)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setColor(0xFF6600)
            .build();
        nm.notify(alertNotificationId++, notification);
    }

    private void sendProcessAlert(ProcessInfo process) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_process_alert)
            .setContentTitle(getString(R.string.notif_suspicious_process_title))
            .setContentText("PID:" + process.getPid() + " - " + process.getProcessName())
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(0xFF0040)
            .build();
        nm.notify(alertNotificationId++, notification);
    }

    private Notification buildNotification(String text, boolean secure) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(secure ? R.drawable.ic_shield_secure : R.drawable.ic_shield_alert)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setColor(secure ? 0x00FF88 : 0xFF0040)
            .build();
    }

    private void updateNotification(String text, boolean secure) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;
        nm.notify(NOTIFICATION_ID, buildNotification(text, secure));
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            getString(R.string.guard_channel_name),
            NotificationManager.IMPORTANCE_LOW);
        channel.setDescription(getString(R.string.guard_channel_desc));
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.createNotificationChannel(channel);
        }
    }

    public boolean isEngineLoading() { return engineLoading; }
    public void setCallback(GuardCallback cb) { this.callback = cb; }
    public ScanEngine getScanEngine() { return scanEngine; }
    public AIEngine getAiEngine() { return aiEngine; }
    public NetworkMonitor getNetworkMonitor() { return networkMonitor; }
    public ProcessDetector getProcessDetector() { return processDetector; }

    @Override
    public IBinder onBind(Intent intent) { return binder; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Belt-and-suspenders: if the process was re-created by START_STICKY
        // and onCreate()'s startForeground() was never reached (e.g. crash
        // during early init), the service would otherwise run as a background
        // service with a 200s ANR timeout instead of the 20s foreground one.
        if (intent != null) try {
            String status = engineLoading ? getString(R.string.engine_loading_status)
                                           : getString(R.string.guard_protecting_status);
            startForeground(NOTIFICATION_ID, buildNotification(status, true));
        } catch (Throwable t) {
            Log.e(TAG, "onStartCommand startForeground failed", t);
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (scheduler != null) scheduler.shutdown();
        if (networkMonitor != null) networkMonitor.stopMonitoring();
        if (aiEngine != null) aiEngine.close();
        if (downloadObserver != null) downloadObserver.stopWatching();
        for (android.os.FileObserver obs : extraStorageObservers) obs.stopWatching();
        extraStorageObservers.clear();
        Log.i(TAG, "Guard Service destroyed");
    }
}
