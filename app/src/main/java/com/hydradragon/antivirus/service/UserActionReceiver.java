package com.hydradragon.antivirus.service;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import com.hydradragon.antivirus.engine.UserDecisions;

/**
 * Handles the user's "no" actions on threat alerts:
 *   - ACTION_IGNORE  : mark this package/URL safe (allowlist) — never flag again.
 *   - ACTION_DISMISS : the redirect/popup was dismissed — don't redirect again.
 */
public class UserActionReceiver extends BroadcastReceiver {

    public static final String ACTION_IGNORE = "com.hydradragon.antivirus.IGNORE_THREAT";
    public static final String ACTION_DISMISS = "com.hydradragon.antivirus.DISMISS_REDIRECT";
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
            Toast.makeText(context, "Marked safe: " + id, Toast.LENGTH_SHORT).show();
            Log.i("UserActionReceiver", "allowlisted " + id);
        } else if (ACTION_DISMISS.equals(action)) {
            UserDecisions.dismissRedirect(context, id);
        }

        int notifId = intent.getIntExtra(EXTRA_NOTIF, -1);
        if (notifId != -1) {
            NotificationManager nm =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) nm.cancel(notifId);
        }
    }
}
