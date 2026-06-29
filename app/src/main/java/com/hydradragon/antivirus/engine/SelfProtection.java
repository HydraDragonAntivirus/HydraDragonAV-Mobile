package com.hydradragon.antivirus.engine;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

import com.hydradragon.antivirus.service.AdminReceiver;

/**
 * Legitimate self-protection via the Device Admin API: while active, the app
 * can't be uninstalled until the user deactivates the admin. No intrusive
 * powers are used — only the uninstall speed bump.
 *
 * <p>Usage from an Activity:
 * <pre>
 *   if (!SelfProtection.isActive(this)) {
 *       startActivity(SelfProtection.activationIntent(this)); // user confirms
 *   }
 *   // To turn it off again: SelfProtection.deactivate(this);
 * </pre>
 */
public final class SelfProtection {

    private SelfProtection() {}

    private static DevicePolicyManager dpm(Context c) {
        return (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
    }

    public static ComponentName admin(Context c) {
        return new ComponentName(c.getApplicationContext(), AdminReceiver.class);
    }

    /** True if self-protection (device admin) is currently active. */
    public static boolean isActive(Context c) {
        DevicePolicyManager d = dpm(c);
        return d != null && d.isAdminActive(admin(c));
    }

    /**
     * Intent that opens the system "activate device admin?" consent screen.
     * Launch it from an Activity ({@code startActivity}).
     */
    public static Intent activationIntent(Context c) {
        Intent i = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        i.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin(c));
        i.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "HydraDragon'un kaldırılmaya karşı korunması için cihaz yöneticisi "
                + "izni gerekir. Hiçbir kilitleme/silme yetkisi kullanılmaz; "
                + "istediğiniz zaman Ayarlar'dan kapatabilirsiniz.");
        return i;
    }

    /** Turn self-protection off (lets the app be uninstalled normally again). */
    public static void deactivate(Context c) {
        DevicePolicyManager d = dpm(c);
        if (d != null && d.isAdminActive(admin(c))) {
            d.removeActiveAdmin(admin(c));
        }
    }
}
