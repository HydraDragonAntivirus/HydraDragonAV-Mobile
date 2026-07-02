package com.hydradragon.antivirus.service;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.UserDecisions;

/**
 * Handles the user's actions on threat alerts:
 *   - ACTION_IGNORE      : mark this package/URL safe (allowlist) — never flag again.
 *   - ACTION_DISMISS     : the redirect/popup was dismissed — don't redirect again.
 *   - ACTION_REMOVE_FILE : delete a malicious file the user explicitly chose to remove
 *                          (real-time watcher hits ask first, they never auto-delete).
 */
public class UserActionReceiver extends BroadcastReceiver {

    public static final String ACTION_IGNORE = "com.hydradragon.antivirus.IGNORE_THREAT";
    public static final String ACTION_DISMISS = "com.hydradragon.antivirus.DISMISS_REDIRECT";
    public static final String ACTION_REMOVE_FILE = "com.hydradragon.antivirus.REMOVE_FILE";
    public static final String EXTRA_ID = "threat_id";
    public static final String EXTRA_NOTIF = "notif_id";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String id = intent.getStringExtra(EXTRA_ID);
        if (id == null) return;
        String action = intent.getAction();

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
