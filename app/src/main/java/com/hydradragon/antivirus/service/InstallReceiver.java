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
                        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, "hydradragon_dynamic_alert")
                                .setSmallIcon(R.drawable.ic_threat)
                                .setContentTitle("CRITICAL THREAT BLOCKED")
                                .setContentText(result.getThreatType() + " detected during installation!")
                                .setPriority(NotificationCompat.PRIORITY_MAX)
                                .setColor(0xFF0000);
                        if (nm != null) nm.notify((int)System.currentTimeMillis(), builder.build());
                    }
                } catch (Exception e) {
                    Log.e(TAG, "On-Install Error", e);
                }
            }).start();
        }
    }
}
