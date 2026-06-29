package com.hydradragon.antivirus.service;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Device-administrator receiver for legitimate self-protection.
 *
 * <p>While this admin is active, Android won't let the app be uninstalled until
 * the user explicitly deactivates the admin first — a transparent speed bump,
 * not a hard block. No lock/wipe/password powers are requested (see
 * {@code res/xml/device_admin.xml}).
 */
public class AdminReceiver extends DeviceAdminReceiver {

    private static final String TAG = "HydraDragon-Admin";

    @Override
    public void onEnabled(Context context, Intent intent) {
        Log.i(TAG, "Self-protection (device admin) enabled");
    }

    @Override
    public CharSequence onDisableRequested(Context context, Intent intent) {
        // Shown on the system "deactivate admin?" screen.
        return "HydraDragon korumasını kapatmak üzeresiniz. Kapatırsanız uygulama "
                + "kaldırmaya karşı korumasız kalır.";
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        Log.w(TAG, "Self-protection (device admin) disabled");
    }
}
