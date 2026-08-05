package com.hydradragon.antivirus.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import android.app.NotificationManager;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.AIEngine;
import com.hydradragon.antivirus.engine.ScanEngine;
import com.hydradragon.antivirus.model.ThreatResult;

public class InstallReceiver extends BroadcastReceiver {
    private static final String TAG = "HydraDragon-InstallRecv";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_PACKAGE_ADDED.equals(action) || Intent.ACTION_PACKAGE_REPLACED.equals(action)) {
            android.net.Uri data = intent.getData();
            if (data == null) return;
            String packageName = data.getEncodedSchemeSpecificPart();
            if (packageName == null || packageName.isEmpty()) return;
            Log.i(TAG, "On-Install scan triggered for: " + packageName);

            // New install / update -> drop any stale cached result so this exact
            // (possibly changed) APK is scanned fresh, not served from cache.
            ScanEngine.invalidateCache(packageName);

            ScanEngine.runOrchestrated(() -> {
                try {
                    PackageManager pm = context.getPackageManager();

                    // Retry getApplicationInfo with backoff — on some devices/Android
                    // versions the package may not be fully visible yet when the
                    // broadcast arrives (especially for ADB-installed packages).
                    ApplicationInfo appInfo = null;
                    int attempt = 0;
                    while (appInfo == null && attempt < 5) {
                        try {
                            appInfo = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA);
                        } catch (PackageManager.NameNotFoundException e) {
                            attempt++;
                            if (attempt >= 5) {
                                // Last resort: scan through all installed apps
                                for (ApplicationInfo ai : pm.getInstalledApplications(PackageManager.GET_META_DATA)) {
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

                    AIEngine ai = new AIEngine(context);
                    ScanEngine engine = new ScanEngine(context, ai);
                    ThreatResult result = engine.analyzeSingleApp(appInfo, pm, false);
                    
                    if (result != null && result.isThreat()) {
                        Log.e(TAG, "ON-INSTALL THREAT DETECTED: " + packageName);
                        // Dropper attribution: if this package was a previously
                        // downloaded malicious APK whose downloader was an
                        // untrusted app, that downloader just INSTALLED its own
                        // payload -> it is a dropper (Andr.Dropper.Susp).
                        String ownerPkg = com.hydradragon.antivirus.engine.HipsMonitor.getDownloadOwner(packageName);
                        if (ownerPkg != null
                                && com.hydradragon.antivirus.engine.HipsMonitor.hasBehaviorFlag(ownerPkg, "DOWNLOAD_MALWARE")) {
                            com.hydradragon.antivirus.engine.HipsMonitor.addBehaviorFlag(ownerPkg, "DROPPER:installed=" + packageName);
                            com.hydradragon.antivirus.service.ThreatLogger.logThreat(
                                context, ownerPkg, packageName,
                                "Andr.Dropper.Susp: downloaded and installed malicious package " + packageName);
                        }
                        if (com.hydradragon.antivirus.engine.ProtectionState.isEnabled(context)) {
                            if (com.hydradragon.antivirus.engine.AutoDeleteMalware.isEnabled(context)) {
                                com.hydradragon.antivirus.engine.BehaviorResponse.autoDeleteThreat(context, result);
                            } else {
                                com.hydradragon.antivirus.engine.BehaviorResponse.killAndPromptUninstall(context, result);
                            }
                        }
                        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

                        // Tapping the notification / "Remove" opens the SYSTEM
                        // uninstall dialog for THIS exact malicious package. We
                        // can't silently remove it (Android needs user consent);
                        // this targets the related app, nothing else.
                        Intent del = new Intent(Intent.ACTION_DELETE,
                                android.net.Uri.parse("package:" + packageName));
                        del.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        android.app.PendingIntent pi = android.app.PendingIntent.getActivity(
                                context, packageName.hashCode(), del,
                                android.app.PendingIntent.FLAG_IMMUTABLE
                                        | android.app.PendingIntent.FLAG_UPDATE_CURRENT);

                        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, "hydradragon_dynamic_alert")
                                .setSmallIcon(R.drawable.ic_threat)
                                .setContentTitle(context.getString(R.string.notif_critical_threat_blocked))
                                .setContentText(context.getString(R.string.notif_threat_detected_text, result.getThreatType(), packageName))
                                .setPriority(NotificationCompat.PRIORITY_MAX)
                                .setAutoCancel(true)
                                .setColor(0xFF0000)
                                .setContentIntent(pi)
                                .addAction(R.drawable.ic_threat, context.getString(R.string.notif_action_remove), pi);
                        if (nm != null) nm.notify((int)System.currentTimeMillis(), builder.build());
                    }
                } catch (Exception e) {
                    Log.e(TAG, "On-Install Error", e);
                }
            });
        }
    }
}
