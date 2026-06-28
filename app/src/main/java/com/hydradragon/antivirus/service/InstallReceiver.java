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
            Log.i(TAG, "On-Install scan triggered for: " + packageName);

            // New install / update -> drop any stale cached result so this exact
            // (possibly changed) APK is scanned fresh, not served from cache.
            ScanEngine.invalidateCache(packageName);

            new Thread(() -> {
                try {
                    PackageManager pm = context.getPackageManager();
                    ApplicationInfo appInfo = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA);
                    AIEngine ai = new AIEngine(context);
                    ScanEngine engine = new ScanEngine(context, ai);
                    ThreatResult result = engine.analyzeSingleApp(appInfo, pm, false);
                    
                    if (result != null && result.isThreat()) {
                        Log.e(TAG, "ON-INSTALL THREAT DETECTED: " + packageName);
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
                                .setContentTitle("CRITICAL THREAT BLOCKED")
                                .setContentText(result.getThreatType() + " detected: " + packageName + " — tap to remove")
                                .setPriority(NotificationCompat.PRIORITY_MAX)
                                .setAutoCancel(true)
                                .setColor(0xFF0000)
                                .setContentIntent(pi)
                                .addAction(R.drawable.ic_threat, "Remove", pi);
                        if (nm != null) nm.notify((int)System.currentTimeMillis(), builder.build());
                    }
                } catch (Exception e) {
                    Log.e(TAG, "On-Install Error", e);
                }
            }).start();
        }
    }
}
