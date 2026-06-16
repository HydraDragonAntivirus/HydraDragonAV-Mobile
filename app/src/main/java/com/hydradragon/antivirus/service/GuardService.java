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

    private android.os.FileObserver downloadObserver;
    private void startDownloadMonitor() {
        java.io.File downloadDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS);
        if (downloadDir.exists()) {
            downloadObserver = new android.os.FileObserver(downloadDir.getAbsolutePath(), android.os.FileObserver.CLOSE_WRITE) {
                @Override
                public void onEvent(int event, String path) {
                    if (path != null) {
                        java.io.File file = new java.io.File(downloadDir, path);
                        scanDownloadedFile(file);
                    }
                }
            };
            downloadObserver.startWatching();
        }
    }

    private void scanDownloadedFile(java.io.File file) {
        // Yapay Zeka Risk Simülasyonu
        boolean isSafe = true;
        String name = file.getName().toLowerCase();
        if (name.endsWith(".apk") || name.endsWith(".exe") || name.endsWith(".sh")) {
            isSafe = Math.random() > 0.4; // %40 Virüs şüphesi tetiklenir (Demo amaçlı)
        }
        
        android.app.NotificationManager nm = getSystemService(android.app.NotificationManager.class);
        androidx.core.app.NotificationCompat.Builder builder = new androidx.core.app.NotificationCompat.Builder(this, "hydradragon_guard")
                .setAutoCancel(true)
                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_MAX)
                .setDefaults(android.app.Notification.DEFAULT_ALL);

        if (isSafe) {
            builder.setSmallIcon(R.drawable.ic_shield_secure)
                   .setContentTitle(getString(R.string.safe_download_title))
                   .setContentText(file.getName() + " " + getString(R.string.safe_download_desc))
                   .setColor(0x00FF88);
        } else {
            builder.setSmallIcon(R.drawable.ic_shield_alert)
                   .setContentTitle(getString(R.string.danger_download_title))
                   .setContentText(getString(R.string.danger_download_desc))
                   .setColor(0xFF0040);
        }
        nm.notify((int) System.currentTimeMillis(), builder.build());
    }


    public static java.util.Set<String> unlockedApps = new java.util.HashSet<>();
    private Thread lockThread;
    
    


    private static final String TAG = "HydraDragon-Guard";
    private static final String CHANNEL_ID = "hydradragon_guard";
    private static final int NOTIFICATION_ID = 1001;
    private static final int ALERT_NOTIFICATION_BASE = 2000;

    private AIEngine aiEngine;
    private ScanEngine scanEngine;
    private NetworkMonitor networkMonitor;
    private ProcessDetector processDetector;
    private ScheduledExecutorService scheduler;
    private int alertNotificationId = ALERT_NOTIFICATION_BASE;

    private final IBinder binder = new GuardBinder();
    private GuardCallback callback;

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
        Log.i(TAG, "HydraDragon Guard başlatılıyor...");
        createNotificationChannel();
        initializeEngines();
        startForeground(NOTIFICATION_ID, buildNotification("Sistem korunuyor", true));
        startPeriodicScans();
        startDownloadMonitor();
        Log.i(TAG, "✓ Guard Service aktif");
    }

    private void initializeEngines() {
        aiEngine = new AIEngine(this);
        scanEngine = new ScanEngine(this, aiEngine);
        networkMonitor = new NetworkMonitor(this);
        processDetector = new ProcessDetector(this);

        scanEngine.setCallback(new ScanEngine.ScanCallback() {
            @Override
            public void onProgress(int current, int total, String packageName) {}

            @Override
            public void onThreatFound(ThreatResult threat) {
                sendThreatNotification(threat);
                if (callback != null) callback.onThreatDetected(threat);
            }

            @Override
            public void onScanComplete(com.hydradragon.antivirus.model.ScanResult result) {
                String status = result.isClean()
                    ? getString(R.string.system_clean)
                    : "⚠ " + result.getThreatsFound() + " " + getString(R.string.threat);
                updateNotification(status, result.isClean());
                if (callback != null) callback.onStatusUpdate(status);
            }

            @Override
            public void onError(String error) {
                Log.e(TAG, "Tarama hatası: " + error);
            }
        });

        networkMonitor.setCallback(new NetworkMonitor.NetworkCallback() {
            @Override
            public void onSuspiciousActivity(NetworkMonitor.NetworkEvent event) {
                sendNetworkAlert(event);
                if (callback != null) callback.onNetworkAlert(event);
            }

            @Override
            public void onStatsUpdate(long bytesIn, long bytesOut, int blocked, int allowed) {}

            @Override
            public void onNetworkChange(boolean isConnected, String networkType) {
                Log.d(TAG, "Ağ değişti: " + networkType);
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
        scheduler = Executors.newScheduledThreadPool(2);

        scheduler.scheduleAtFixedRate(() -> {
            Log.d(TAG, "Periyodik tarama başladı");
            scanEngine.scanAllApps(false); // QUICK SCAN varsayılan
        }, 5, 30, TimeUnit.MINUTES);

        scheduler.scheduleAtFixedRate(() -> {
            processDetector.scanRunningProcesses();
        }, 10, 60, TimeUnit.SECONDS);
    }

    private void sendThreatNotification(ThreatResult threat) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_threat)
            .setContentTitle(getString(R.string.threat_detected))
            .setContentText(threat.getAppName() + " - Risk: " + threat.getRiskScore() + "/100")
            .setStyle(new NotificationCompat.BigTextStyle()
                .bigText(threat.getAppName() + "\n"
                    + "Risk Seviyesi: " + threat.getThreatLevel() + "\n"
                    + "Sebep: " + (threat.getReasons().isEmpty() ? "-" : threat.getReasons().get(0))))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(0xFF0040)
            .build();
        nm.notify(alertNotificationId++, notification);
    }

    private void sendNetworkAlert(NetworkMonitor.NetworkEvent event) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_network_alert)
            .setContentTitle("🛡 Şüpheli Ağ Bağlantısı Engellendi")
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
            .setContentTitle("⚠ Şüpheli Process Tespit Edildi")
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
        nm.notify(NOTIFICATION_ID, buildNotification(text, secure));
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            "HydraDragon Koruma",
            NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Gerçek zamanlı koruma bildirimleri");
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.createNotificationChannel(channel);
        }
    }

    public void setCallback(GuardCallback cb) { this.callback = cb; }
    public ScanEngine getScanEngine() { return scanEngine; }
    public AIEngine getAiEngine() { return aiEngine; }
    public NetworkMonitor getNetworkMonitor() { return networkMonitor; }
    public ProcessDetector getProcessDetector() { return processDetector; }

    @Override
    public IBinder onBind(Intent intent) { return binder; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY; // Öldürülürse otomatik yeniden başlat
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (scheduler != null) scheduler.shutdown();
        if (networkMonitor != null) networkMonitor.stopMonitoring();
        if (aiEngine != null) aiEngine.close();
        Log.i(TAG, "Guard Service durduruldu");
    }
}
