package com.hydradragon.antivirus.service;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.ScreenThreatKeywords;
import com.hydradragon.antivirus.engine.UrlThreatScanner;
import com.hydradragon.antivirus.engine.UserDecisions;

import java.util.Locale;

/**
 * Real-time SMS scanning: every incoming text message is checked for a
 * malicious link (native URL threat scanner) and scam/phishing/fake-antivirus
 * wording (the same 20-language keyword lists {@link ScreenThreatKeywords}
 * uses for on-screen text). Never aborts the broadcast — the Messages app
 * still receives the SMS normally; this only raises an alert.
 */
public class SmsReceiver extends BroadcastReceiver {
    private static final String TAG = "HydraDragon-Sms";
    private static final String CHANNEL_ID = "hydradragon_sms_alert";
    private static final int ALERT_NOTIF_ID = 0xA1E8;

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        if (!com.hydradragon.antivirus.engine.ProtectionState.isEnabled(context)) return;

        try {
            SmsMessage[] messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
            if (messages == null || messages.length == 0) return;

            StringBuilder body = new StringBuilder();
            String sender = null;
            for (SmsMessage m : messages) {
                if (m == null) continue;
                if (sender == null) sender = m.getOriginatingAddress();
                CharSequence part = m.getMessageBody();
                if (part != null) body.append(part);
            }
            if (body.length() == 0) return;
            String text = body.toString();
            String from = sender != null ? sender : "unknown";

            boolean malicious = false;

            // Malicious link inside the SMS (native URL threat scanner).
            UrlThreatScanner scanner = UrlThreatScanner.get(context);
            for (String url : UrlThreatScanner.extractUrls(text)) {
                if (scanner.scanUrl(url) != null) { malicious = true; break; }
            }

            // Scam/phishing/fake-antivirus/ransomware wording, same multi-language
            // lists used for on-screen text (smishing lures, tech-support scams,
            // ransom notes sent/linked via SMS).
            if (!malicious) {
                String lower = text.toLowerCase(Locale.ROOT);
                // SMS_PHISHING/FAKE_VIRUS_WARNING require 2+ distinct lures (most
                // individual phrases also appear in genuine texts); RANSOMWARE
                // phrases are unambiguous enough on their own for a single hit.
                malicious = ScreenThreatKeywords.containsAtLeast(lower, ScreenThreatKeywords.SMS_PHISHING, 2)
                    || ScreenThreatKeywords.containsAtLeast(lower, ScreenThreatKeywords.FAKE_VIRUS_WARNING, 2)
                    || ScreenThreatKeywords.containsAny(lower, ScreenThreatKeywords.RANSOMWARE);
            }

            if (!malicious) return;

            String id = "smsvirus:" + from;
            if (UserDecisions.isThreatAllowed(context, id)) return;

            Log.w(TAG, "MALICIOUS SMS from " + from);
            sendAlert(context, from, id);
        } catch (Throwable t) {
            Log.w(TAG, "SMS scan failed", t);
        }
    }

    private void sendAlert(Context context, String from, String id) {
        createChannel(context);
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        Intent open = new Intent(context, com.hydradragon.antivirus.MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(context, (int) System.currentTimeMillis(), open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        String title = context.getString(R.string.sms_virus_title);
        String msg = context.getString(R.string.sms_virus_msg, from);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_threat)
                .setContentTitle(title)
                .setContentText(msg)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setColor(0xFFFF0000)
                .setAutoCancel(true)
                .setContentIntent(pi);

        nm.notify(ALERT_NOTIF_ID, builder.build());

        try {
            ThreatLogger.logThreat(context, id, title, msg);
        } catch (Throwable ignore) { }
    }

    private void createChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "SMS Threat Alerts", NotificationManager.IMPORTANCE_HIGH);
            channel.setDescription("Alerts for malicious SMS messages");
            NotificationManager nm = context.getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }
}
