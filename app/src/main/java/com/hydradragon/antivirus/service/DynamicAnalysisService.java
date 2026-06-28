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

public class DynamicAnalysisService extends AccessibilityService {
    private static final String TAG = "HydraDragon-Dynamic";
    private static final String CHANNEL_ID = "hydradragon_dynamic_alert";
    
    private long lastClickTime = 0;
    private int rapidClickCount = 0;

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

        int eventType = event.getEventType();

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
                Log.e(TAG, "RANSOMWARE LOCK SCREEN DETECTED!");
                sendAlert("RANSOMWARE BLOCKED", "Ransomware locked screen detected. Device locked down to home screen!");
                performGlobalAction(GLOBAL_ACTION_HOME);
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
                        Log.e(TAG, "MALICIOUS URL (" + cat + "): " + url);
                        sendAlert("MALICIOUS WEBSITE BLOCKED",
                            cat + ": " + url);
                        performGlobalAction(GLOBAL_ACTION_HOME);
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

    @Override
    public void onInterrupt() {}

    private void sendAlert(String title, String message) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_threat)
                .setContentTitle(title)
                .setContentText(message)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setColor(0xFF0000)
                .setAutoCancel(true);

        nm.notify((int) System.currentTimeMillis(), builder.build());
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