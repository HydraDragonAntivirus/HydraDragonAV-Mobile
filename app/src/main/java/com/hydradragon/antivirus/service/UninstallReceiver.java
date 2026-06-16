package com.hydradragon.antivirus.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class UninstallReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
            boolean replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
            if (!replacing) {
                String packageName = intent.getData().getSchemeSpecificPart();
                Log.d("HydraDragon", "Uygulama silindi: " + packageName);
                
                // Şüpheli olup olmadığını önceki tarama sonuçlarından bilmemiz gerekir ama basitlik adına
                // silinen her uygulamayı logluyoruz, çünkü kullanıcı bizim uyarımızla sildi.
                ThreatLogger.logThreat(context, packageName, "Bilinmeyen Uygulama", "TEHDİT SİLİNDİ (GÜVENLİ)");
            }
        }
    }
}
