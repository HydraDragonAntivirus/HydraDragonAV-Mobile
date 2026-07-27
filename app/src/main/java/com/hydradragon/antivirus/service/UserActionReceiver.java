package com.hydradragon.antivirus.service;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import androidx.core.content.ContextCompat;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.ProtectionState;
import com.hydradragon.antivirus.engine.UserDecisions;

/**
 * Handles the user's actions on threat alerts and foreground-notification controls:
 *   - ACTION_IGNORE           : mark this package/URL safe (allowlist) — never flag again.
 *   - ACTION_DISMISS          : the redirect/popup was dismissed — don't redirect again.
 *   - ACTION_REMOVE_FILE      : delete a malicious file the user explicitly chose to remove
 *                               (real-time watcher hits ask first, they never auto-delete).
 *   - ACTION_PAUSE_PROTECTION : disable real-time protection and stop GuardService
 *                               (fired from the foreground notification's Pause button).
 *   - ACTION_RESUME_PROTECTION: re-enable real-time protection and restart GuardService
 *                               (fired from the foreground notification's Resume button).
 */
public class UserActionReceiver extends BroadcastReceiver {

    public static final String ACTION_IGNORE      = "com.hydradragon.antivirus.IGNORE_THREAT";
    public static final String ACTION_DISMISS     = "com.hydradragon.antivirus.DISMISS_REDIRECT";
    public static final String ACTION_REMOVE_FILE = "com.hydradragon.antivirus.REMOVE_FILE";
    /** Pause real-time protection from the foreground notification. */
    public static final String ACTION_PAUSE_PROTECTION  = "com.hydradragon.antivirus.PAUSE_PROTECTION";
    /** Resume real-time protection from the foreground notification. */
    public static final String ACTION_RESUME_PROTECTION = "com.hydradragon.antivirus.RESUME_PROTECTION";
    /** Action to notify GuardService to refresh its foreground notification. */
    public static final String ACTION_UPDATE_NOTIFICATION = "com.hydradragon.antivirus.ACTION_UPDATE_NOTIFICATION";

    public static final String EXTRA_ID    = "threat_id";
    public static final String EXTRA_NOTIF = "notif_id";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String id = intent.getStringExtra(EXTRA_ID);
        String action = intent.getAction();

        // Protection toggle actions don't need a threat id — handle them first.
        if (ACTION_PAUSE_PROTECTION.equals(action)) {
            ProtectionState.setEnabled(context, false);
            // Do NOT stop GuardService — keep it alive so the persistent
            // "Protection Paused" warning notification stays visible.
            // Just tell GuardService to refresh its foreground notification.
            context.sendBroadcast(
                new Intent(ACTION_UPDATE_NOTIFICATION).setPackage(context.getPackageName()));
            Toast.makeText(context,
                context.getString(R.string.protection_paused), Toast.LENGTH_LONG).show();
            Log.i("UserActionReceiver", "protection paused from notification (service kept alive)");
            return;
        } else if (ACTION_RESUME_PROTECTION.equals(action)) {
            ProtectionState.setEnabled(context, true);
            // GuardService is still running — just tell it to refresh its notification.
            context.sendBroadcast(
                new Intent(ACTION_UPDATE_NOTIFICATION).setPackage(context.getPackageName()));
            // Also start the service in case it was killed by the OS.
            ContextCompat.startForegroundService(
                context, new Intent(context, GuardService.class));
            Toast.makeText(context,
                context.getString(R.string.protection_enabled), Toast.LENGTH_SHORT).show();
            Log.i("UserActionReceiver", "protection resumed from notification");
            return;
        }

        if (id == null) return;

        if (ACTION_IGNORE.equals(action)) {
            UserDecisions.allowThreat(context, id);
            Toast.makeText(context, context.getString(R.string.marked_safe_format, id), Toast.LENGTH_SHORT).show();
            Log.i("UserActionReceiver", "allowlisted " + id);
        } else if (ACTION_DISMISS.equals(action)) {
            UserDecisions.dismissRedirect(context, id);
        } else if (ACTION_REMOVE_FILE.equals(action)) {
            java.io.File file = new java.io.File(id);
            boolean removed = file.exists() && file.delete();
            Toast.makeText(context, context.getString(
                removed ? R.string.threat_destroyed : R.string.file_delete_failed), Toast.LENGTH_LONG).show();
            Log.i("UserActionReceiver", (removed ? "removed " : "FAILED to remove ") + id);
        }

        int notifId = intent.getIntExtra(EXTRA_NOTIF, -1);
        if (notifId != -1) {
            NotificationManager nm =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) nm.cancel(notifId);
        }
    }
}
