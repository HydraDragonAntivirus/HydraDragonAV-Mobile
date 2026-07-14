package com.hydradragon.antivirus;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import com.hydradragon.antivirus.service.GuardService;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            if (!com.hydradragon.antivirus.engine.BootAutoStart.isEnabled(context)) {
                Log.i("HydraDragon", "Device booted, but auto-start was disabled by the user.");
                return;
            }
            Log.i("HydraDragon", "Device booted, starting GuardService silently...");
            // Pre-warm the native engine now — the 70s init runs on a background
            // thread before the user even opens the app.
            com.hydradragon.antivirus.engine.NativeScanner.init(context);
            Intent serviceIntent = new Intent(context, GuardService.class);
            context.startService(serviceIntent);
        }
    }
}
