package com.hydradragon.antivirus.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.hydradragon.antivirus.engine.BehaviorFlags;
import com.hydradragon.antivirus.engine.ScanEngine;
import com.hydradragon.antivirus.engine.UserDecisions;

public class UninstallReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
            boolean replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
            if (!replacing) {
                String packageName = intent.getData().getSchemeSpecificPart();
                Log.d("HydraDragon", "Uygulama silindi: " + packageName);

                // Purge ALL remembered state for this package so a removed virus
                // doesn't "come back": cached scan result, behaviour flag, and any
                // user allowlist (so a different app later reusing the name isn't
                // silently trusted).
                ScanEngine.invalidateCache(packageName);
                BehaviorFlags.clear(context, packageName);
                UserDecisions.revokeThreatAllowance(context, packageName);

                ThreatLogger.logThreat(context, packageName, "Bilinmeyen Uygulama", "TEHDİT SİLİNDİ (GÜVENLİ)");
            }
        }
    }
}
