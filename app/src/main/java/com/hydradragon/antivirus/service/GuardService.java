package com.hydradragon.antivirus.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
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

    /** Opt-in (Settings > "Real-time full storage monitoring", ON by default —
     *  see startFullStorageMonitor). Downloads is always watched regardless. */
    public static final String KEY_REALTIME_STORAGE_WATCH = "realtime_storage_watch";

    private android.database.ContentObserver downloadObserver;
    private volatile long lastDownloadCheckMs = 0L;
    private android.database.ContentObserver fullStorageObserver;
    private volatile long lastFullStorageCheckMs = 0L;
    private final java.util.concurrent.atomic.AtomicBoolean recentFilesScheduled = new java.util.concurrent.atomic.AtomicBoolean();

    /** Register a ContentObserver on MediaStore.Downloads so we catch every
     *  new downloaded file in real time — scoped storage (Android 10+) makes
     *  FileObserver unreliable for this path. */
    private void startDownloadMonitor() {
        try {
            // Guard against duplicate registration
            if (downloadObserver != null) return;
            android.net.Uri downloadsUri = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI;
            downloadObserver = new android.database.ContentObserver(new android.os.Handler(android.os.Looper.getMainLooper())) {
                @Override
                public void onChange(boolean selfChange) {
                    onChange(selfChange, null);
                }
                @Override
                public void onChange(boolean selfChange, android.net.Uri uri) {
                    scanMediaStoreDownloads();
                }
            };
            getContentResolver().registerContentObserver(downloadsUri, true, downloadObserver);
            Log.i(TAG, "MediaStore Downloads observer registered");
        } catch (Throwable t) {
            Log.e(TAG, "failed to register MediaStore observer", t);
        }
    }

    /** Query MediaStore.Downloads for files added/modified since our last poll,
     *  and submit any new ones for scanning. */
    private void scanMediaStoreDownloads() {
        com.hydradragon.antivirus.engine.ScanEngine.runOrchestrated(() -> {
            try {
                long now = System.currentTimeMillis();
                // Only scan files newer than our last check (with 2s margin)
                long minModified = lastDownloadCheckMs > 0 ? lastDownloadCheckMs - 2000 : now - 10_000;
                lastDownloadCheckMs = now;

                android.net.Uri downloadsUri = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI;
                String[] projection = {
                    android.provider.MediaStore.Downloads._ID,
                    android.provider.MediaStore.Downloads.DATA,        // file path (deprecated but works)
                    android.provider.MediaStore.Downloads.DATE_MODIFIED,
                    android.provider.MediaStore.Downloads.MIME_TYPE,
                };
                String selection = android.provider.MediaStore.Downloads.DATE_MODIFIED + " >= ?";
                String[] selArgs = new String[]{ String.valueOf(minModified / 1000) };
                // Newest first — so we process the latest download first
                String order = android.provider.MediaStore.Downloads.DATE_MODIFIED + " DESC";

                try (android.database.Cursor c = getContentResolver().query(
                        downloadsUri, projection, selection, selArgs, order)) {
                    if (c == null) return;
                    while (c.moveToNext()) {
                        String path = c.getString(c.getColumnIndexOrThrow(android.provider.MediaStore.Downloads.DATA));
                        String mime = c.getString(c.getColumnIndexOrThrow(android.provider.MediaStore.Downloads.MIME_TYPE));
                        if (path == null || path.isEmpty()) continue;
                        java.io.File file = new java.io.File(path);
                        if (!file.exists() || !file.isFile()) continue;
                        com.hydradragon.antivirus.engine.FileReadEstimator.observeFile(
                            GuardService.this, file.getAbsolutePath(), file.length());
                        // Feed the file event into the rename-burst + memory-pressure
                        // ransomware detection pipeline.
                        java.io.File parent = file.getParentFile();
                        if (parent != null) {
                            com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.onFileEvent(
                                this, parent.getAbsolutePath(), file.getName());
                        }
                        scanDownloadedFile(file);
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "MediaStore download scan failed", t);
            }
        });
    }

    /** Observes ALL files across all storage via MediaStore (unlike the
     *  root-only FileObserver approach which was not recursive). On any
     *  content change, queries MediaStore for recently modified files outside
     *  the Downloads folder (already covered by startDownloadMonitor) and
     *  scans them. ON by default (Settings toggle — aggressive real-time protection). */
    private void startFullStorageMonitor() {
        if (!getSharedPreferences("hydra_prefs", MODE_PRIVATE)
                .getBoolean(KEY_REALTIME_STORAGE_WATCH, true)) {
            return;
        }
        if (fullStorageObserver != null) return;
        android.net.Uri filesUri = android.provider.MediaStore.Files.getContentUri("external");
        fullStorageObserver = new android.database.ContentObserver(new android.os.Handler(android.os.Looper.getMainLooper())) {
            @Override
            public void onChange(boolean selfChange) { onChange(selfChange, null); }
            @Override
            public void onChange(boolean selfChange, android.net.Uri uri) {
                scanRecentFiles();
            }
        };
        getContentResolver().registerContentObserver(filesUri, true, fullStorageObserver);
        Log.i(TAG, "MediaStore full-storage observer registered");
    }

    /** Query MediaStore.Files for recently modified files outside Downloads
     *  and scan them. Runs debounced to avoid thrashing on bulk changes. */
    private void scanRecentFiles() {
        if (recentFilesScheduled.getAndSet(true)) return;
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            recentFilesScheduled.set(false);
            com.hydradragon.antivirus.engine.ScanEngine.runOrchestrated(() -> {
                try {
                    long now = System.currentTimeMillis();
                    long minModified = lastFullStorageCheckMs > 0 ? lastFullStorageCheckMs - 2000 : now - 30_000;
                    lastFullStorageCheckMs = now;
                    android.net.Uri uri = android.provider.MediaStore.Files.getContentUri("external");
                    String[] projection = {
                        android.provider.MediaStore.Files.FileColumns._ID,
                        android.provider.MediaStore.Files.FileColumns.DATA,
                        android.provider.MediaStore.Files.FileColumns.DATE_MODIFIED,
                        android.provider.MediaStore.Files.FileColumns.MIME_TYPE,
                    };
                    // Exclude Downloads (covered by scanMediaStoreDownloads)
                    String downloadsPath = android.os.Environment
                        .getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
                        .getAbsolutePath();
                    String selection = android.provider.MediaStore.Files.FileColumns.DATE_MODIFIED + " >= ? AND "
                        + android.provider.MediaStore.Files.FileColumns.DATA + " NOT LIKE ?";
                    String[] selArgs = new String[]{ String.valueOf(minModified / 1000), downloadsPath + "/%" };
                    try (android.database.Cursor c = getContentResolver().query(
                            uri, projection, selection, selArgs, null)) {
                        if (c == null) return;
                        while (c.moveToNext()) {
                            String path = c.getString(1);
                            if (path == null || path.isEmpty()) continue;
                            java.io.File file = new java.io.File(path);
                            if (!file.exists() || !file.isFile()) continue;
                            com.hydradragon.antivirus.engine.FileReadEstimator.observeFile(
                                GuardService.this, file.getAbsolutePath(), file.length());
                            java.io.File parent = file.getParentFile();
                            if (parent != null) {
                                com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.onFileEvent(
                                    this, parent.getAbsolutePath(), file.getName());
                            }
                            scanDownloadedFile(file);
                        }
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "MediaStore full-storage scan failed", t);
                }
            });
        }, 2000);
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
                String dlPkg = threat.getPackageName();
                if (dlPkg != null && !dlPkg.isEmpty()) {
                    com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(dlPkg, "DOWNLOAD_MALWARE");
                    // Dropper attribution: MediaStore records which app actually
                    // downloaded the file (Android 10+). If that owner is an
                    // untrusted app (not Chrome/system), remember it so the later
                    // install of this APK is credited to the dropper.
                    String ownerPkg = queryDownloadOwner(file);
                    if (ownerPkg != null && !ownerPkg.isEmpty()
                            && !com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, ownerPkg)) {
                        com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(ownerPkg, "DOWNLOAD_MALWARE");
                        com.hydradragon.antivirus.engine.HipsMonitor.recordDownloadedApk(dlPkg, ownerPkg);
                    }
                }

                if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(this)) {
                    try {
                        if (com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(this)) {
                            com.hydradragon.antivirus.engine.BehaviorResponse.autoDeleteThreat(
                                this, threat);
                        } else {
                            com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                                this, threat);
                            // Even without auto-delete, try to remove the file if it's a standalone APK
                            if (threat.isStandaloneFile()) {
                                String path = threat.getApkPath();
                                if (path != null && !path.isEmpty()) {
                                    try {
                                        boolean deleted = new java.io.File(path).delete();
                                        Log.i(TAG, "download scan: file " + (deleted ? "deleted" : "delete failed") + ": " + path);
                                    } catch (Throwable t) {
                                        Log.w(TAG, "download scan file delete failed", t);
                                    }
                                }
                            }
                        }
                    } catch (Throwable t) {
                        Log.e(TAG, "download auto-kill failed", t);
                    }
                }

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

    /** MediaStore records which app initiated a download (Android 10+); null on
     *  older platforms, for files outside MediaStore, or when unavailable. */
    private String queryDownloadOwner(java.io.File file) {
        try {
            if (Build.VERSION.SDK_INT < 29 || file == null) return null;
            android.net.Uri u = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI;
            String[] proj = { android.provider.MediaStore.Downloads.DATA,
                android.provider.MediaStore.Downloads.OWNER_PACKAGE_NAME };
            try (android.database.Cursor c = getContentResolver().query(u, proj,
                    android.provider.MediaStore.Downloads.DATA + "=?",
                    new String[]{ file.getAbsolutePath() }, null)) {
                if (c != null && c.moveToFirst()) {
                    int idx = c.getColumnIndex(android.provider.MediaStore.Downloads.OWNER_PACKAGE_NAME);
                    if (idx >= 0) return c.getString(idx);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "queryDownloadOwner failed", t);
        }
        return null;
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
    private com.hydradragon.antivirus.engine.MinerDetector minerDetector;
    private volatile boolean engineLoading = true;
    private ScheduledExecutorService scheduler;
    private int alertNotificationId = ALERT_NOTIFICATION_BASE;
    /** Last seen wallpaper ID — when it changes, some app called setWallpaper. */
    private volatile int lastWallpaperId = -1;
    /** Installed packages previously seen WITH a launcher icon, so we can tell
     *  when one suppresses its own icon (T1628.001). */
    private final java.util.Set<String> pkgsSeenWithLauncher = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** Event-driven icon-suppression detector: fires on ACTION_PACKAGE_CHANGED
     *  (an app disabling its own launcher activity delivers exactly this), so
     *  detection is instant instead of waiting for the periodic poll. */
    private final BroadcastReceiver packageChangeReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(android.content.Context ctx, android.content.Intent intent) {
            try {
                if (intent == null || intent.getAction() == null) return;
                String action = intent.getAction();
                android.net.Uri data = intent.getData();
                if (data == null) return;
                String pkg = data.getSchemeSpecificPart();
                if (pkg == null || pkg.isEmpty()) return;
                if (com.hydradragon.antivirus.engine.HipsMonitor.isSelfPackage(pkg)) return;

                if (android.content.Intent.ACTION_PACKAGE_ADDED.equals(action) 
                        || android.content.Intent.ACTION_PACKAGE_REPLACED.equals(action)) {
                    // New install or update -> scan immediately
                    Log.i(TAG, "Package installed/updated, scanning: " + pkg);
                    ScanEngine.invalidateCache(pkg);
                    scanInstalledPackage(ctx, pkg);
                } else if (android.content.Intent.ACTION_PACKAGE_CHANGED.equals(action)) {
                    checkPackageForHiddenIcon(pkg);
                }
            } catch (Throwable t) {
                Log.e(TAG, "packageChangeReceiver failed", t);
            }
        }
    };
    /** Root state as of the LAST check — starts false since MainActivity already
     *  refuses to launch on an already-rooted device (see RootCheck), so any
     *  transition to true observed here happened WHILE this app was running. */
    private volatile boolean wasRooted = false;
    /** Audio-scareware detector state: last music-stream volume level and the
     *  time it was sampled, so a sudden low→max jump (scareware tactic) can be
     *  caught even though Android 10+ blocks 3rd-party setStreamVolume. */
    private volatile int lastVolumeLevel = -1;
    private volatile long lastVolumeSampleMs = 0L;
    /** Tracks which package starts playback with alarm/emergency audio usage —
     *  the strongest audio-abuse signal on Android 10+ (setStreamVolume blocked).
     *  Nulled in onDestroy (unregistered) — API 26+, our minSdk. */
    private android.media.AudioManager.AudioPlaybackCallback audioPlaybackCallback;

    /** Clipboard-read monitoring: the last sensitive-looking primary-clip text
     *  and which package was foreground when it changed, so a switch into a
     *  suspicious app while sensitive data is still on the clipboard can be
     *  attributed as a read. Android 10+ only lets the foreground app read the
     *  clipboard, so a new foreground package seeing it is meaningful. */
    private volatile String lastSensitiveClipboardText = null;
    private volatile String lastSensitiveClipboardPkg = null;
    private volatile long lastSensitiveClipboardMs = 0L;

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

    /** Holds the last onScanComplete result when the UI fragment is detached
     *  (screen off). Consumed by ScanFragment on reconnect. */
    private volatile com.hydradragon.antivirus.model.ScanResult pendingUiScanResult;

    /** Threats found while the UI fragment was detached. Drained by
     *  ScanFragment on reconnect so no detections are lost when the user
     *  navigates away from the scan screen mid-scan. */
    private final java.util.List<ThreatResult> pendingUiThreats = new java.util.ArrayList<>();

    /** Called by ScanFragment instead of touching ScanEngine's callback
     *  directly. Pass {@code null} when the fragment goes away (onStop) so a
     *  stale reference isn't held past the fragment's lifecycle. */
    public void setUiScanCallback(ScanEngine.ScanCallback cb) { this.uiScanCallback = cb; }

    /** Returns the last scan result that completed while no UI was attached,
     *  then clears it. Used by ScanFragment on reconnect to detect scans that
     *  finished while the screen was off. */
    public com.hydradragon.antivirus.model.ScanResult consumePendingUiScanResult() {
        com.hydradragon.antivirus.model.ScanResult r = pendingUiScanResult;
        pendingUiScanResult = null;
        return r;
    }

    /** Returns all threats found while the UI fragment was detached, then
     *  clears the queue. Used by ScanFragment on reconnect so threats found
     *  while the user was on another tab are not lost. */
    public java.util.List<ThreatResult> consumePendingUiThreats() {
        synchronized (pendingUiThreats) {
            if (pendingUiThreats.isEmpty()) return java.util.Collections.emptyList();
            java.util.List<ThreatResult> drained = new java.util.ArrayList<>(pendingUiThreats);
            pendingUiThreats.clear();
            return drained;
        }
    }

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
            startServiceMonitors();
            startPeriodicScans();
            startDownloadMonitor();
            startFullStorageMonitor();
            Log.i(TAG, "Guard Service active");
        }, "guard-init").start();
    }

    private void registerPackageChangeReceiver() {
        try {
            android.content.IntentFilter filter = new android.content.IntentFilter();
            filter.addAction(android.content.Intent.ACTION_PACKAGE_ADDED);
            filter.addAction(android.content.Intent.ACTION_PACKAGE_REPLACED);
            filter.addAction(android.content.Intent.ACTION_PACKAGE_CHANGED);
            filter.addAction(android.content.Intent.ACTION_PACKAGE_REMOVED);
            filter.addDataScheme("package");
            registerReceiver(packageChangeReceiver, filter);
        } catch (Throwable t) {
            Log.e(TAG, "register packageChangeReceiver failed", t);
        }
    }

    private void registerAudioCallback() {
        try {
            android.media.AudioManager am =
                (android.media.AudioManager) getSystemService(android.media.AudioManager.class);
            if (am == null) return;
            audioPlaybackCallback = new android.media.AudioManager.AudioPlaybackCallback() {
                @Override
                public void onPlaybackConfigChanged(
                        java.util.List<android.media.AudioPlaybackConfiguration> configs) {
                    if (configs == null) return;
                    for (android.media.AudioPlaybackConfiguration cfg : configs) {
                        if (cfg == null || !cfg.isActive()) continue;
                        try {
                            android.media.AudioAttributes attrs = cfg.getAudioAttributes();
                            int usage = attrs != null ? attrs.getUsage()
                                : android.media.AudioAttributes.USAGE_UNKNOWN;
                            boolean abusive = usage == android.media.AudioAttributes.USAGE_ALARM
                                || usage == android.media.AudioAttributes.USAGE_EMERGENCY
                                || usage == android.media.AudioAttributes.USAGE_NOTIFICATION_RINGTONE;
                            if (!abusive) continue;
                            String pkg = null;
                            try {
                                pkg = cfg.getClientPid() > 0
                                    ? android.app.ActivityManager.getRunningAppProcesses() == null
                                        ? null : null // resolved below via getPackageNameFromPid
                                    : cfg.getClientPackageName();
                            } catch (Throwable ignored) {}
                            if (pkg == null || pkg.isEmpty()) {
                                pkg = getPackageNameFromPid(cfg.getClientPid());
                            }
                            if (pkg == null || pkg.isEmpty()) continue;
                            if (com.hydradragon.antivirus.engine.HipsMonitor.isSelfPackage(pkg)) continue;
                            if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(GuardService.this, pkg)) continue;
                            if (com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(GuardService.this, pkg)) continue;
                            String usageName = usageName(usage);
                            com.hydradragon.antivirus.engine.HipsMonitor.reportAudioAbuse(
                                pkg, usage, usageName,
                                attrs != null ? attrs.getContentType()
                                    : android.media.AudioAttributes.CONTENT_TYPE_UNKNOWN,
                                true);
                            Log.e(TAG, "AUDIO ABUSE: " + pkg + " playing with usage " + usageName
                                + " — scareware/ransomware signature");
                            ThreatLogger.logThreat(GuardService.this, pkg, "Audio Abuse",
                                "App is playing audio with " + usageName + " usage — scareware attention tactic");
                        } catch (Throwable t) {
                            Log.e(TAG, "onPlaybackConfigChanged entry failed", t);
                        }
                    }
                }
            };
            am.registerAudioPlaybackCallback(audioPlaybackCallback, null);
            Log.i(TAG, "AudioPlaybackCallback registered (USAGE_ALARM/EMERGENCY monitoring)");
        } catch (Throwable t) {
            Log.e(TAG, "registerAudioCallback failed", t);
        }
    }

    /** Best-effort package-name lookup for a client PID — falls back to the
     *  running-process list when AudioPlaybackConfiguration#getClientPackageName
     *  isn't populated (rare on OEM builds). */
    private String getPackageNameFromPid(int pid) {
        if (pid <= 0) return null;
        try {
            java.util.List<android.app.ActivityManager.RunningAppProcessInfo> procs =
                ((android.app.ActivityManager) getSystemService(ACTIVITY_SERVICE))
                    .getRunningAppProcesses();
            if (procs == null) return null;
            for (android.app.ActivityManager.RunningAppProcessInfo p : procs) {
                if (p.pid == pid && p.pkgList != null && p.pkgList.length > 0) {
                    return p.pkgList[0];
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static String usageName(int usage) {
        switch (usage) {
            case android.media.AudioAttributes.USAGE_ALARM: return "USAGE_ALARM";
            case android.media.AudioAttributes.USAGE_EMERGENCY: return "USAGE_EMERGENCY";
            case android.media.AudioAttributes.USAGE_NOTIFICATION_RINGTONE: return "USAGE_NOTIFICATION_RINGTONE";
            case android.media.AudioAttributes.USAGE_MEDIA: return "USAGE_MEDIA";
            case android.media.AudioAttributes.USAGE_ASSISTANCE_NAVIGATION_GUIDANCE: return "USAGE_NAVIGATION_GUIDANCE";
            default: return "USAGE_" + usage;
        }
    }

    private void initializeEngines() {
        com.hydradragon.antivirus.engine.ScanEngine.setBackgroundPriority(
            !com.hydradragon.antivirus.engine.ScanSchedule.isScanWakeLockEnabled(this));
        aiEngine = new AIEngine(this);
        scanEngine = new ScanEngine(this, aiEngine);
        backgroundScanEngine = new ScanEngine(this, aiEngine);
        backgroundScanEngine.setBackgroundScan(true);
        backgroundScanEngine.setCallback(new ScanEngine.ScanCallback() {
            @Override public void onProgress(int c, int t, String p) {
                // A background scan adopted by the user's ScanFragment
                // (see ScanEngine.scanAllApps's adopt path) runs on THIS engine —
                // forward its progress so the scan page keeps updating.
                if (backgroundScanEngine.isBackgroundScan()) return;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onProgress(c, t, p);
            }
            @Override public void onThreatFound(ThreatResult threat) {
                try {
                    ThreatLogger.logThreat(GuardService.this, threat, "BACKGROUND SCAN");
                } catch (Throwable t) {
                    Log.e(TAG, "ThreatLogger.logThreat failed", t);
                }
                String pkg = threat.getPackageName();
                if (pkg != null && !pkg.isEmpty()) {
                    com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(pkg, "SCAN_MALWARE");
                }
                if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) {
                    try {
                        if (com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(GuardService.this)) {
                            com.hydradragon.antivirus.engine.BehaviorResponse.autoDeleteThreat(
                                GuardService.this, threat);
                        } else {
                            // Never throw up the full-screen "malware found" page
                            // mid-scan (isFromScan=true): the threat is shown in the
                            // scan result once the scan completes instead.
                            com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                                GuardService.this, threat, true);
                        }
                    } catch (Throwable t) {
                        Log.e(TAG, "background auto-kill failed", t);
                    }
                }
                boolean adopted = !backgroundScanEngine.isBackgroundScan();
                if (adopted) {
                    // This background scan was adopted by the user (ScanFragment
                    // started a scan of the same type) — forward its threats to
                    // the attached UI so they appear in the scan result list.
                    ScanEngine.ScanCallback ui = uiScanCallback;
                    synchronized (pendingUiThreats) {
                        pendingUiThreats.add(threat);
                    }
                    if (ui != null && backgroundScanEngine.isScanRunning()) {
                        java.util.List<ThreatResult> batch = consumePendingUiThreats();
                        for (ThreatResult t : batch) ui.onThreatFound(t);
                    }
                } else {
                    // Purely background scan: no full-screen popup, but the user
                    // is still informed via a notification (non-intrusive).
                    try {
                        sendThreatNotification(threat);
                    } catch (Throwable t) {
                        Log.e(TAG, "sendThreatNotification failed", t);
                    }
                }
            }
            @Override public void onScanComplete(com.hydradragon.antivirus.model.ScanResult r) {
                if (backgroundScanEngine.isBackgroundScan()) return;
                pendingUiScanResult = r;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) {
                    ui.onScanComplete(r);
                    pendingUiScanResult = null;
                }
            }
            @Override public void onError(String e) {
                if (backgroundScanEngine.isBackgroundScan()) return;
                pendingUiScanResult = null;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onError(e);
            }
        });
        networkMonitor = new NetworkMonitor(this);
        processDetector = new ProcessDetector(this);
        minerDetector = new com.hydradragon.antivirus.engine.MinerDetector(this);

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
                String scanPkg = threat.getPackageName();
                if (scanPkg != null && !scanPkg.isEmpty()) {
                    com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(scanPkg, "SCAN_MALWARE");
                }
                // Isolated in its own try/catch: this whole onThreatFound() call
                // runs INSIDE ScanEngine's per-app loop, itself wrapped in a
                // silent catch(Exception) — any exception thrown here (bad
                // PendingIntent, null NotificationManager, etc.) used to abort
                // the rest of this method too, which meant the UI forwarding
                // below NEVER ran either: the scan looked like it found nothing,
                // both in the system tray AND in the app's own threat list.
                if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) {
                    try {
                        com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                            GuardService.this, threat, true);
                    } catch (Throwable t) {
                        Log.e(TAG, "foreground scan auto-kill failed", t);
                    }
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
                // Always queue — survives UI detachment mid-scan.
                synchronized (pendingUiThreats) {
                    pendingUiThreats.add(threat);
                }
                if (ui != null && scanEngine.isScanRunning()) {
                    // Drain queued threats into UI (including this one) so the
                    // fragment receives any threats found while it was away.
                    java.util.List<ThreatResult> batch = consumePendingUiThreats();
                    for (ThreatResult t : batch) {
                        ui.onThreatFound(t);
                    }
                }
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
                pendingUiScanResult = result;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) {
                    ui.onScanComplete(result);
                    pendingUiScanResult = null;
                }
            }

            @Override
            public void onError(String error) {
                if (scanEngine.isBackgroundScan()) return;
                Log.e(TAG, "Scan error: " + error);
                pendingUiScanResult = null;
                ScanEngine.ScanCallback ui = uiScanCallback;
                if (ui != null) ui.onError(error);
            }
        });

        networkMonitor.setCallback(new NetworkMonitor.NetworkCallback() {
            @Override
            public void onSuspiciousActivity(NetworkMonitor.NetworkEvent event) {
                ThreatLogger.logThreat(GuardService.this, event.destIp, "Network", event.reason);
                if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) return;
                String netPkg = resolvePackageForPid(event.pid);
                if (netPkg != null && !netPkg.isEmpty()) {
                    com.hydradragon.antivirus.engine.HipsMonitor.reportNetwork(netPkg, 1, 1, 0);
                }
                sendNetworkAlert(event);
                if (callback != null) callback.onNetworkAlert(event);
            }

            @Override
            public void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed) {
                String fgPkg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
                if (fgPkg != null && !fgPkg.isEmpty() && blocked + allowed > 0) {
                    com.hydradragon.antivirus.engine.HipsMonitor.reportNetwork(fgPkg, 1, 1, 0);
                }
            }

            @Override
            public void onNetworkChange(boolean isConnected, String networkType) {
                Log.d(TAG, "Network changed: " + networkType);
            }
        });

        processDetector.setCallback(new ProcessDetector.ProcessCallback() {
            @Override
            public void onSuspiciousProcess(ProcessInfo processInfo) {
                String procPkg = processInfo.getPackageName();
                boolean isTrusted = procPkg != null
                    && com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(GuardService.this, procPkg);
                if (procPkg != null && !procPkg.isEmpty() && !isTrusted) {
                    com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(procPkg, "PROCESS_ANOMALY");
                    try {
                        android.content.pm.ApplicationInfo ai = getPackageManager()
                            .getApplicationInfo(procPkg, 0);
                        String apkPath = ai.sourceDir;
                        if (apkPath != null) {
                            com.hydradragon.antivirus.engine.NativeScanner.Verdict v =
                                com.hydradragon.antivirus.engine.NativeScanner.scan(apkPath, procPkg);
                            if (v != null && v.malicious) {
                                com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(
                                    procPkg, "SCAN_MALWARE");
                                com.hydradragon.antivirus.service.ThreatLogger.logThreat(
                                    GuardService.this, procPkg, "RUNTIME SCAN",
                                    "NativeScanner flagged running process APK");
                            }
                        }
                    } catch (Throwable t) {
                        Log.w(TAG, "runtime scan failed for " + procPkg, t);
                    }
                }
                boolean hasScanFlag = procPkg != null && (
                    com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(procPkg, "SCAN_MALWARE")
                    || com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(procPkg, "DOWNLOAD_MALWARE"));
                boolean shouldKill = processInfo.isCritical()
                    || (processInfo.isSuspicious()
                        && processInfo.getFlags() != null
                        && processInfo.getFlags().size() >= 2)
                    || hasScanFlag;
                if (shouldKill) {
                    sendProcessAlert(processInfo);
                    if (callback != null) callback.onSuspiciousProcess(processInfo);
                    handleProcessKill(procPkg, hasScanFlag);
                }
            }

            @Override
            public void onProcessListUpdated(List<ProcessInfo> processes) {
                for (ProcessInfo pi : processes) {
                    String pkg = pi.getPackageName();
                    if (pkg != null && !pkg.isEmpty() && com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) {
                        boolean hasFlag = com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(pkg, "SCAN_MALWARE")
                            || com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(pkg, "DOWNLOAD_MALWARE");
                        if (hasFlag) {
                            handleProcessKill(pkg, true);
                        }
                    }
                }
            }
        });

        networkMonitor.startMonitoring();
    }

    private void checkForegroundViaUsageStats() {
        try {
            if (Build.VERSION.SDK_INT < 22) return;
            if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(this)) return;
            android.app.AppOpsManager appOps = getSystemService(android.app.AppOpsManager.class);
            if (appOps == null) return;
            int mode = appOps.checkOpNoThrow(android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(), getPackageName());
            if (mode != android.app.AppOpsManager.MODE_ALLOWED) {
                Log.w(TAG, "Usage access not granted — foreground scan disabled");
                return;
            }
            android.app.usage.UsageStatsManager usm = getSystemService(android.app.usage.UsageStatsManager.class);
            if (usm == null) return;
            long now = System.currentTimeMillis();
            java.util.List<android.app.usage.UsageStats> stats =
                usm.queryUsageStats(android.app.usage.UsageStatsManager.INTERVAL_BEST, now - 5000, now);
            if (stats == null) return;
            String fgPkg = null;
            long lastTime = 0;
            for (android.app.usage.UsageStats s : stats) {
                long t = s.getLastTimeUsed();
                if (t > lastTime) {
                    lastTime = t;
                    fgPkg = s.getPackageName();
                }
            }
            if (fgPkg == null || fgPkg.isEmpty()) return;
            com.hydradragon.antivirus.engine.HipsMonitor.setForegroundPackage(fgPkg);
            if (fgPkg.equals(getPackageName())
                || fgPkg.equals("com.hydradragon.antivirus")
                || fgPkg.equals("com.hydradragon.antivirus.debug")) return;

            boolean hasFlag = com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(fgPkg, "SCAN_MALWARE")
                || com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(fgPkg, "DOWNLOAD_MALWARE");

            if (!hasFlag
                    && !com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, fgPkg)) {
                try {
                    android.content.pm.ApplicationInfo ai = getPackageManager().getApplicationInfo(fgPkg, 0);
                    String apkPath = ai.sourceDir;
                    if (apkPath != null) {
                        com.hydradragon.antivirus.engine.NativeScanner.Verdict v =
                            com.hydradragon.antivirus.engine.NativeScanner.scan(apkPath, fgPkg);
                        if (v != null && v.malicious) {
                            com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(fgPkg, "SCAN_MALWARE");
                            hasFlag = true;
                            com.hydradragon.antivirus.service.ThreatLogger.logThreat(
                                this, fgPkg, "FOREGROUND SCAN",
                                "NativeScanner flagged foreground app APK");
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "foreground scan failed for " + fgPkg, t);
                }
            }

            if (hasFlag) {
                Log.i(TAG, "Foreground flagged app " + fgPkg + " -> killing");
                String appName = fgPkg;
                try {
                    android.content.pm.ApplicationInfo ai = getPackageManager().getApplicationInfo(fgPkg, 0);
                    appName = getPackageManager().getApplicationLabel(ai).toString();
                } catch (Throwable ignored) {}
                com.hydradragon.antivirus.model.ThreatResult threat =
                    new com.hydradragon.antivirus.model.ThreatResult.Builder(fgPkg)
                        .setAppName(appName)
                        .setRiskScore(100)
                        .setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE)
                        .setReasons(java.util.Collections.singletonList(getString(R.string.reason_scan_detected_malware)))
                        .build();
                com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(this, threat);
            }
        } catch (Throwable t) {
            Log.w(TAG, "checkForegroundViaUsageStats failed", t);
        }
    }

    private void handleProcessKill(String procPkg, boolean hasScanFlag) {
        if (procPkg == null || procPkg.isEmpty()) return;
        if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(GuardService.this)) return;
        try {
            if (hasScanFlag) {
                String appName = procPkg;
                try {
                    android.content.pm.ApplicationInfo ai = getPackageManager()
                        .getApplicationInfo(procPkg, 0);
                    appName = getPackageManager().getApplicationLabel(ai).toString();
                } catch (Throwable ignored) {}
                com.hydradragon.antivirus.model.ThreatResult threat =
                    new com.hydradragon.antivirus.model.ThreatResult.Builder(procPkg)
                        .setAppName(appName)
                        .setRiskScore(75)
                        .setThreatType(com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE)
                        .setReasons(java.util.Collections.singletonList(
                            getString(R.string.reason_previously_detected_running)))
                        .build();
                com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                    GuardService.this, threat, false);
            } else if (!com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, procPkg)) {
                com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(
                    GuardService.this, procPkg);
            }
        } catch (Throwable t) {
            Log.e(TAG, "process auto-kill failed", t);
        }
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
        registerPackageChangeReceiver();
        registerAudioCallback();

        scheduler.scheduleAtFixedRate(() -> {
            processDetector.scanRunningProcesses();
        }, 0, 10, TimeUnit.MILLISECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            checkForegroundViaUsageStats();
        }, 0, 1, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { com.hydradragon.antivirus.engine.LaunchMonitor.poll(GuardService.this); }
            catch (Throwable t) { Log.e(TAG, "LaunchMonitor poll failed", t); }
        }, 0, 5, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { checkWallpaperChange(); }
            catch (Throwable t) { Log.e(TAG, "Wallpaper monitor failed", t); }
        }, 3, 5, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { checkAudioScareware(); }
            catch (Throwable t) { Log.e(TAG, "Audio-scareware monitor failed", t); }
        }, 3, 2, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { checkClipboardStealer(); }
            catch (Throwable t) { Log.e(TAG, "Clipboard stealer monitor failed", t); }
        }, 3, 2, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { checkHiddenApps(); }
            catch (Throwable t) { Log.e(TAG, "Hidden-app monitor failed", t); }
        }, 10, 60, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(this::checkRootTransition, 15, 60, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { minerDetector.scan(); } catch (Throwable t) { Log.e(TAG, "MinerDetector failed", t); }
        }, 30, 15, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { com.hydradragon.antivirus.engine.FileReadEstimator.scan(GuardService.this); }
            catch (Throwable t) { Log.e(TAG, "FileReadEstimator failed", t); }
        }, 60, 30, TimeUnit.SECONDS);

        scheduler.scheduleAtFixedRate(() -> {
            try { com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.checkDeletions(GuardService.this); }
            catch (Throwable t) { Log.e(TAG, "Wiper check failed", t); }
        }, 90, 30, TimeUnit.SECONDS);
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

    /** Detects the scareware audio tactic: an app slamming media volume to max
     *  within a short window (usually from near-silence). Works even on
     *  Android 10+ where 3rd-party setStreamVolume is blocked, because we
     *  observe the RESULTING volume delta and attribute it to whichever app is
     *  foreground — the same attribution used for wallpaper changes. */
    private void checkAudioScareware() {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCAREWARE)) return;        try {
            android.media.AudioManager am =
                (android.media.AudioManager) getSystemService(android.media.AudioManager.class);
            if (am == null) return;
            int max = am.getStreamMaxVolume(android.media.AudioManager.STREAM_MUSIC);
            int level = am.getStreamVolume(android.media.AudioManager.STREAM_MUSIC);
            if (max <= 0) return;
            long now = System.currentTimeMillis();
            if (lastVolumeLevel == -1) {
                lastVolumeLevel = level;
                lastVolumeSampleMs = now;
                return;
            }
            boolean jumped = level >= (int) Math.ceil(max * 0.9)
                && lastVolumeLevel <= (int) Math.floor(max * 0.25)
                && (now - lastVolumeSampleMs) < 4000;
            int from = lastVolumeLevel;
            lastVolumeLevel = level;
            lastVolumeSampleMs = now;
            if (!jumped) return;

            // USER-initiated volume rise (physical rocker): the user pressing
            // the volume key is captured by the AccessibilityService, so a rise
            // that coincides with a key press is the user's own doing, not
            // scareware. Only attribute programmatic slams to the foreground app.
            long nowRealtime = android.os.SystemClock.elapsedRealtime();
            if (com.hydradragon.antivirus.service.DynamicAnalysisService
                    .userPressedVolumeKeyWithin(nowRealtime, 4000)) {
                Log.d(TAG, "Volume rise coincides with a physical volume key — user-initiated, not scareware");
                return;
            }

            String suspect = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
            if (suspect == null || suspect.isEmpty()) return;
            if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, suspect)) return;
            com.hydradragon.antivirus.engine.HipsMonitor.reportAudioSpike(
                suspect, from, level, max, true);
            Log.e(TAG, "AUDIO SPIKE: media volume " + from + "→" + level
                + "/" + max + " by foreground app: " + suspect);
            ThreatLogger.logThreat(this, suspect, "Volume Spike",
                "Media volume jumped from " + from + " to " + level + " of " + max
                    + " while this app was foreground — scareware signature");
        } catch (Throwable ignore) { }
    }

    /** Info-stealer clipboard watch. Android 10+ restricts clipboard reads to the
     *  foreground app, so a sensitive item placed on the clipboard (crypto
     *  address, token, seed phrase) that is still there when a DIFFERENT app
     *  comes to the foreground is a read that app can make. We can't see the
     *  actual getPrimaryClip() call, so we attribute conservatively: only flag
     *  when a suspicious/unknown app takes the foreground while the sensitive
     *  clipboard item is still present. */
    private void checkClipboardStealer() {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.STEALER)) return;
        try {
            android.content.ClipboardManager cm =
                (android.content.ClipboardManager) getSystemService(android.content.ClipboardManager.class);
            if (cm == null) return;
            android.content.ClipData clip = cm.getPrimaryClip();
            String text = null;
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence cs = clip.getItemAt(0).coerceToText(this);
                if (cs != null) text = cs.toString();
            }
            if (text == null || text.isEmpty()) {
                lastSensitiveClipboardText = null;
                lastSensitiveClipboardPkg = null;
                return;
            }

            String current = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
            boolean sensitive = isSensitiveClipboard(text);
            if (sensitive) {
                if (lastSensitiveClipboardText == null
                        || !lastSensitiveClipboardText.equals(text)) {
                    lastSensitiveClipboardText = text;
                    lastSensitiveClipboardPkg = current;
                    lastSensitiveClipboardMs = System.currentTimeMillis();
                    Log.d(TAG, "Sensitive clipboard item seen; placed-by=" + current);
                    return;
                }
                // Same item still on the clipboard but a new app is foreground.
                if (current != null && lastSensitiveClipboardPkg != null
                        && !current.equals(lastSensitiveClipboardPkg)) {
                    if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, current)) {
                        return;
                    }
                    com.hydradragon.antivirus.engine.HipsMonitor.reportClipboardRead(
                        current, true, clipboardHint(text), true);
                    Log.e(TAG, "CLIPBOARD STEAL: sensitive item on clipboard, foreground switched to " + current);
                    ThreatLogger.logThreat(this, current, "Clipboard Stealer",
                        "Sensitive data on the clipboard was readable while " + current
                            + " took the foreground (info-stealer pattern)");
                    lastSensitiveClipboardPkg = current; // don't re-fire for this app
                }
            } else {
                lastSensitiveClipboardText = null;
                lastSensitiveClipboardPkg = null;
            }
        } catch (Throwable ignore) { }
    }

    /** Heuristic: is this clipboard text worth guarding? We only mark strings
     *  that clearly look like credentials/secrets — long random-ish strings,
     *  crypto addresses, JWT-like tokens, key-like hex — to keep false alarms
     *  near zero on ordinary copied text. */
    private static boolean isSensitiveClipboard(String text) {
        if (text == null) return false;
        String t = text.trim();
        int len = t.length();
        if (len < 20) return false;
        // Crypto addresses: BTC/ETH/TRON/other.
        if (t.matches("(?i)^(1|3|bc1|0x)[A-Za-z0-9]{25,}$")) return true;
        // Long tokens / keys / seed phrases.
        if (len >= 32 && t.matches("(?i)^[A-Za-z0-9+/=_.-]{32,}$") && containsDigitsAndLetters(t)) return true;
        // Multi-word seed phrase (>=6 words).
        if (t.matches("(?i)^([a-z]+\\s+){5,}[a-z]+$")) return true;
        return false;
    }

    private static boolean containsDigitsAndLetters(String s) {
        boolean d = false, l = false;
        for (char c : s.toCharArray()) {
            if (Character.isDigit(c)) d = true;
            else if (Character.isLetter(c)) l = true;
            if (d && l) return true;
        }
        return false;
    }

    private static String clipboardHint(String text) {
        if (text == null) return "unknown";
        String t = text.trim();
        if (t.matches("(?i)^0x[0-9a-f]{40}$")) return "eth_address";
        if (t.matches("(?i)^(1|3)[1-9A-HJ-NP-Za-km-z]{25,34}$")) return "btc_address";
        if (t.matches("(?i)^T[1-9A-HJ-NP-Za-km-z]{25,34}$")) return "tron_address";
        if (t.matches("(?i)^[A-Za-z0-9+/=_-]{32,}$") && t.split("[.-]").length > 1) return "token_or_key";
        if (t.matches("(?i)^([a-z]+\\s+){5,}[a-z]+$")) return "seed_phrase";
        return "credential_like";
    }

    /** Polls WallpaperManager.getWallpaperId() — on Android 10+ the
     *  ACTION_WALLPAPER_CHANGED broadcast is no longer delivered to 3rd-party
     *  apps, so a wallpaper-ID delta is the only reliable way to catch
     *  ransomware/scareware silently calling setWallpaper(). The change is
     *  attributed to the foreground app (see the com.user.ad sample:
     *  IWallpaperManager.setWallpaper). */
    private void checkWallpaperChange() {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCAREWARE)) return;
        try {
            android.app.WallpaperManager wm =
                (android.app.WallpaperManager) getSystemService(android.app.WallpaperManager.class);
            if (wm == null) return;
            int id;
            try {
                id = wm.getWallpaperId(android.app.WallpaperManager.FLAG_SYSTEM);
            } catch (Throwable t) {
                return;
            }
            if (lastWallpaperId == -1) {
                lastWallpaperId = id;
                return;
            }
            if (id != lastWallpaperId) {
                lastWallpaperId = id;
                String suspect = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
                if (suspect == null || suspect.isEmpty()) return;
                if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, suspect)) return;
                com.hydradragon.antivirus.engine.HipsMonitor.reportWallpaperChange(suspect, id);
                Log.e(TAG, "WALLPAPER CHANGED by foreground app: " + suspect + " (id=" + id + ")");
                ThreatLogger.logThreat(this, suspect, "Wallpaper Change",
                    "Wallpaper was replaced while this app was foreground — ransomware/scareware signature");
            }
        } catch (Throwable ignore) { }
    }

    /** Smart hidden-app monitor.
     *  <p>Fast path: {@link #packageChangeReceiver} catches the exact moment an
     *  app disables its own launcher activity (ACTION_PACKAGE_CHANGED) and calls
     *  {@link #checkPackageForHiddenIcon(String)} instantly — no polling latency.
     *  <p>Slow path: this periodic sweep exists only as a safety net for cases
     *  that don't deliver PACKAGE_CHANGED (e.g. icon hidden via a device-admin
     *  component or OEM launcher quirk). It also re-learns newly-installed apps
     *  into {@link #pkgsSeenWithLauncher} so a future suppression is caught.
     *  Because of the event-driven fast path, the sweep runs rarely. */
    private void checkHiddenApps() {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCAREWARE)) return;
        try {
            android.content.pm.PackageManager pm = getPackageManager();
            java.util.List<android.content.pm.ApplicationInfo> installed =
                pm.getInstalledApplications(0);
            if (installed == null) return;
            java.util.Set<String> currentlyVisible = new java.util.HashSet<>();
            for (android.content.pm.ApplicationInfo ai : installed) {
                if (com.hydradragon.antivirus.engine.HipsMonitor.isSelfPackage(ai.packageName)) continue;
                boolean hasIcon = hasLauncherIcon(pm, ai);
                if (hasIcon) {
                    currentlyVisible.add(ai.packageName);
                    pkgsSeenWithLauncher.add(ai.packageName);
                }
            }
            if (pkgsSeenWithLauncher.isEmpty()) {
                pkgsSeenWithLauncher.addAll(currentlyVisible);
                return;
            }
            for (String pkg : new java.util.ArrayList<>(pkgsSeenWithLauncher)) {
                if (currentlyVisible.contains(pkg)) continue;
                // Re-verify the icon truly vanished (not a stale first-sweep
                // baseline race) before flagging.
                android.content.pm.ApplicationInfo ai;
                try {
                    ai = pm.getApplicationInfo(pkg, 0);
                } catch (Throwable t) {
                    // Package uninstalled — drop from the watch set, not a threat.
                    pkgsSeenWithLauncher.remove(pkg);
                    continue;
                }
                if (hasLauncherIcon(pm, ai)) {
                    currentlyVisible.add(pkg);
                    continue;
                }
                if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, pkg)) continue;
                if (com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, pkg)) continue;
                com.hydradragon.antivirus.engine.HipsMonitor.reportHiddenApp(pkg, true);
                Log.e(TAG, "HIDDEN APP: launcher icon suppressed for " + pkg);
                ThreatLogger.logThreat(this, pkg, "Hidden App",
                    "App is no longer visible in the launcher — stealth/rootkit signature (T1628.001)");
            }
        } catch (Throwable ignore) { }
    }

    private boolean hasLauncherIcon(android.content.pm.PackageManager pm,
                                    android.content.pm.ApplicationInfo ai) {
        try {
            return pm.getLaunchIntentForPackage(ai.packageName) != null
                || (ai.enabled
                    && (ai.flags & android.content.pm.ApplicationInfo.FLAG_SUSPENDED) == 0
                    && pm.getApplicationEnabledSetting(ai.packageName)
                        != android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED);
        } catch (Throwable t) {
            return false;
        }
    }

    /** Event-driven check triggered the instant an app reports a package
     *  change (typically disabling its own launcher activity). Cheaper and
     *  faster than the periodic sweep because it inspects ONE package. */
    private void checkPackageForHiddenIcon(String pkg) {
        if (!com.hydradragon.antivirus.engine.BehaviorDetectionSettings.isEnabled(this,
                com.hydradragon.antivirus.engine.BehaviorDetectionSettings.SCAREWARE)) return;
        try {
            android.content.pm.PackageManager pm = getPackageManager();
            android.content.pm.ApplicationInfo ai;
            try {
                ai = pm.getApplicationInfo(pkg, 0);
            } catch (Throwable t) {
                pkgsSeenWithLauncher.remove(pkg);
                return;
            }
            if (hasLauncherIcon(pm, ai)) {
                pkgsSeenWithLauncher.add(pkg);
                return;
            }
            // Icon is gone. Only flag if we previously saw this app WITH an
            // icon (otherwise it was simply installed icon-less — legitimate).
            if (!pkgsSeenWithLauncher.contains(pkg)) {
                pkgsSeenWithLauncher.add(pkg);
                return;
            }
            if (com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(this, pkg)) return;
            if (com.hydradragon.antivirus.engine.UserDecisions.isThreatAllowed(this, pkg)) return;
            com.hydradragon.antivirus.engine.HipsMonitor.reportHiddenApp(pkg, true);
            Log.e(TAG, "HIDDEN APP (instant): launcher icon suppressed for " + pkg);
            ThreatLogger.logThreat(this, pkg, "Hidden App",
                "App disabled its own launcher icon — stealth/rootkit signature (T1628.001)");
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
            .setContentText(getString(R.string.notif_threat_risk_text, threat.getAppName(), threat.getRiskScore()))
            .setStyle(new NotificationCompat.BigTextStyle()
                .bigText(threat.getAppName() + "\n"
                    + getString(R.string.notif_threat_risk_big, threat.getThreatLevel(),
                        threat.getReasons().isEmpty() ? "-" : threat.getReasons().get(0))))
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
                   .addAction(R.drawable.ic_threat, getString(R.string.notif_action_remove), pi);
        }

        nm.notify(alertNotificationId++, builder.build());
    }

    private void sendNetworkAlert(NetworkMonitor.NetworkEvent event) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_network_alert)
            .setContentTitle(getString(R.string.notif_suspicious_network_title))
            .setContentText(getString(R.string.notif_network_alert_text, event.destIp, event.destPort, event.reason))
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
            .setContentText(getString(R.string.notif_process_alert_text, process.getPid(), process.getProcessName()))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(0xFF0040)
            .build();
        nm.notify(alertNotificationId++, notification);
    }

    private Notification buildNotification(String text, boolean secure) {
        // Content tap → open the main activity.
        Intent openIntent = new Intent(this, MainActivity.class);
        PendingIntent openPI = PendingIntent.getActivity(
            this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(secure ? R.drawable.ic_shield_secure : R.drawable.ic_shield_alert)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(openPI)
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

    public boolean isEngineLoading() {
        // engineLoading only tracks the Java-side ScanEngine construction.
        // The heavy native engine (ClamAV/YARA, ~70s on a background Rust
        // thread) can still be loading after that, and scanning before it's
        // ready silently skips the native pass. Treat "still loading" as true
        // until BOTH the Java engines are built AND the native scanner reports
        // ready — otherwise a scan can start against a not-yet-initialised
        // native engine.
        return engineLoading
            || !com.hydradragon.antivirus.engine.NativeScanner.isReady();
    }
    public void setCallback(GuardCallback cb) { this.callback = cb; }
    public ScanEngine getScanEngine() { return scanEngine; }
    public AIEngine getAiEngine() { return aiEngine; }
    public NetworkMonitor getNetworkMonitor() { return networkMonitor; }
    public ProcessDetector getProcessDetector() { return processDetector; }

    private String resolvePackageForPid(int pid) {
        android.app.ActivityManager am = (android.app.ActivityManager) getSystemService(ACTIVITY_SERVICE);
        if (am == null) return null;
        for (android.app.ActivityManager.RunningAppProcessInfo p : am.getRunningAppProcesses()) {
            if (p.pid == pid && p.pkgList != null && p.pkgList.length > 0) return p.pkgList[0];
        }
        return null;
    }

    /** Scan a single installed package (triggered by ACTION_PACKAGE_ADDED/REPLACED). */
    private void scanInstalledPackage(android.content.Context ctx, String packageName) {
        ScanEngine.runOrchestrated(() -> {
            try {
                android.content.pm.PackageManager pm = ctx.getPackageManager();
                android.content.pm.ApplicationInfo appInfo = null;
                int attempt = 0;
                while (appInfo == null && attempt < 5) {
                    try {
                        appInfo = pm.getApplicationInfo(packageName, android.content.pm.PackageManager.GET_META_DATA);
                    } catch (android.content.pm.PackageManager.NameNotFoundException e) {
                        attempt++;
                        if (attempt >= 5) {
                            for (android.content.pm.ApplicationInfo ai : pm.getInstalledApplications(android.content.pm.PackageManager.GET_META_DATA)) {
                                if (packageName.equals(ai.packageName)) {
                                    appInfo = ai;
                                    break;
                                }
                            }
                            if (appInfo == null) {
                                Log.e(TAG, "Package not found after retries: " + packageName);
                                return;
                            }
                        } else {
                            try { Thread.sleep(500L * attempt); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                        }
                    }
                }

                ThreatResult result = scanEngine.analyzeSingleApp(appInfo, pm, false);
                
                if (result != null && result.isThreat()) {
                    Log.e(TAG, "ON-INSTALL THREAT DETECTED: " + packageName);
                    String ownerPkg = com.hydradragon.antivirus.engine.HipsMonitor.getDownloadOwner(packageName);
                    if (ownerPkg != null
                            && com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(ownerPkg, "DOWNLOAD_MALWARE")) {
                        com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(ownerPkg, "DROPPER:installed=" + packageName);
                        com.hydradragon.antivirus.service.ThreatLogger.logThreat(
                            ctx, ownerPkg, packageName,
                            "Andr.Dropper.Susp: downloaded and installed malicious package " + packageName);
                    }
                    if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(ctx)) {
                        if (com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(ctx)) {
                            com.hydradragon.antivirus.engine.BehaviorResponse.autoDeleteThreat(ctx, result);
                        } else {
                            com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(ctx, result);
                        }
                    }
                    android.app.NotificationManager nm = (android.app.NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
                    android.content.Intent del = new android.content.Intent(android.content.Intent.ACTION_DELETE,
                            android.net.Uri.parse("package:" + packageName));
                    del.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                    android.app.PendingIntent pi = android.app.PendingIntent.getActivity(
                            ctx, packageName.hashCode(), del,
                            android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT);

                    androidx.core.app.NotificationCompat.Builder builder = new androidx.core.app.NotificationCompat.Builder(ctx, "hydradragon_dynamic_alert")
                            .setSmallIcon(R.drawable.ic_threat)
                            .setContentTitle(getString(R.string.notif_critical_threat_blocked))
                            .setContentText(getString(R.string.notif_threat_detected_text, result.getThreatType(), packageName))
                            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_MAX)
                            .setAutoCancel(true)
                            .setColor(0xFF0000)
                            .setContentIntent(pi)
                            .addAction(R.drawable.ic_threat, getString(R.string.notif_action_remove), pi);
                    if (nm != null) nm.notify((int)System.currentTimeMillis(), builder.build());
                }
            } catch (Exception e) {
                Log.e(TAG, "scanInstalledPackage Error", e);
            }
        });
    }

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
        try { unregisterReceiver(packageChangeReceiver); } catch (Throwable t) { Log.e(TAG, "unregister packageChangeReceiver failed", t); }
        if (audioPlaybackCallback != null) {
            try {
                android.media.AudioManager am =
                    (android.media.AudioManager) getSystemService(android.media.AudioManager.class);
                if (am != null) am.unregisterAudioPlaybackCallback(audioPlaybackCallback);
            } catch (Throwable t) { Log.e(TAG, "unregister audio callback failed", t); }
            audioPlaybackCallback = null;
        }
        if (networkMonitor != null) networkMonitor.stopMonitoring();
        if (aiEngine != null) aiEngine.close();
        if (downloadObserver != null) {
            try { getContentResolver().unregisterContentObserver(downloadObserver); }
            catch (Throwable t) { Log.e(TAG, "unregister download observer failed", t); }
        }
        if (fullStorageObserver != null) {
            try { getContentResolver().unregisterContentObserver(fullStorageObserver); }
            catch (Throwable t) { Log.e(TAG, "unregister full-storage observer failed", t); }
        }
        Log.i(TAG, "Guard Service destroyed");
    }
}
