package com.hydradragon.antivirus;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.core.content.ContextCompat;
import com.hydradragon.antivirus.service.GuardService;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Log.i("HydraDragon", "Cihaz açıldı, GuardService sessizce başlatılıyor...");
            Intent serviceIntent = new Intent(context, GuardService.class);
            ContextCompat.startForegroundService(context, serviceIntent);
        }
    }
}
