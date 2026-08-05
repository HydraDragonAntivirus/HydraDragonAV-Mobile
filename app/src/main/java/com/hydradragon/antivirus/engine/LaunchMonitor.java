package com.hydradragon.antivirus.engine;

import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Launch monitor: detects which package launched (brought to the foreground)
 * which other package via {@link UsageStatsManager#queryEvents}
 * (ACTIVITY_RESUMED transitions).
 *
 * Each transition where the source package is already behavior-flagged
 * (e.g. {@code SCAN_MALWARE}) is recorded as an
 * {@code APP_LAUNCH:from=<source>:to=<target>[:class=<ActivityClass>]}
 * behavior flag on the source, so the YARA-X
 * {@code hydradragon.behavior_flagged} check can match the "malware opened
 * Chrome" pattern without shipping static rules. Ordinary app switching stays
 * silent because the source is only inspected once it has been flagged.
 *
 * {@code UsageEvents.Event.getClassName()} (Android 10+) gives the launched
 * activity class best-effort; the reliable class name path is
 * {@link com.hydradragon.antivirus.service.DynamicAnalysisService}'s
 * accessibility window-switch tracking.
 */
public final class LaunchMonitor {

    private static final String TAG = "HydraDragon-Launch";

    private static final int MAX_LAUNCHES = 256;

    /** Launch records older than this are dropped (keeps memory bounded). */
    private static final long MAX_RECALL_MS = 24L * 60 * 60 * 1000;

    public static final class LaunchRecord {
        public final String fromPackage;
        public final String toPackage;
        public final String className;
        public final long timestamp;

        LaunchRecord(String fromPackage, String toPackage, String className, long timestamp) {
            this.fromPackage = fromPackage;
            this.toPackage = toPackage;
            this.className = className;
            this.timestamp = timestamp;
        }
    }

    private static final List<LaunchRecord> launches = new ArrayList<>();

    /** Timestamp of the newest processed event; used as the next query start. */
    private static volatile long lastEventTimeMs = 0;

    /** The most recently activated package across polls. */
    private static volatile String lastActive = "";

    private LaunchMonitor() {}

    /**
     * Pulls the activity-events window since the previous poll and records the
     * launch transitions (flagging the source when it is already suspicious).
     * Cheap enough for a periodic (seconds) tick; no-op without usage-access
     * permission.
     */
    public static synchronized void poll(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT < 22) return;
            if (!ProtectionState.isEnabled(ctx)) return;
            if (!hasUsageAccess(ctx)) return;

            UsageStatsManager usm = (UsageStatsManager) ctx.getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm == null) return;

            long now = System.currentTimeMillis();
            long from = lastEventTimeMs > 0 ? lastEventTimeMs : now - 60_000;
            UsageEvents events = usm.queryEvents(from, now);
            if (events == null) return;

            long newest = lastEventTimeMs;
            String last = lastActive;
            while (events.hasNextEvent()) {
                UsageEvents.Event e = new UsageEvents.Event();
                if (!events.getNextEvent(e)) continue;
                if (e.getEventType() != UsageEvents.Event.ACTIVITY_RESUMED) continue;
                if (e.getTimeStamp() <= lastEventTimeMs) continue;

                String pkg = e.getPackageName();
                if (pkg == null || pkg.isEmpty() || isSelfPackage(pkg)) continue;

                long t = e.getTimeStamp();
                if (t > newest) newest = t;

                String cls = null;
                if (Build.VERSION.SDK_INT >= 29) {
                    try { cls = e.getClassName(); } catch (Throwable ignored) {}
                }

                if (!last.isEmpty() && !last.equals(pkg)) {
                    recordLaunch(last, pkg, cls, t);
                }
                last = pkg;
            }
            lastActive = last;
            if (newest > lastEventTimeMs) lastEventTimeMs = newest;

            trim();
        } catch (Throwable t) {
            Log.w(TAG, "poll failed", t);
        }
    }

    /** Latest N launch transitions, most recent first. */
    public static synchronized List<LaunchRecord> getLaunchEvents(int max) {
        List<LaunchRecord> out = new ArrayList<>(launches);
        out.sort(Comparator.comparingLong(e -> -e.timestamp));
        if (out.size() > max) return out.subList(0, max);
        return out;
    }

    /** JSON array merged into the HIPS report behavior_state. */
    public static synchronized JSONArray buildLaunchesJson() {
        JSONArray arr = new JSONArray();
        for (LaunchRecord e : getLaunchEvents(MAX_LAUNCHES)) {
            try {
                JSONObject o = new JSONObject();
                o.put("from_package", e.fromPackage);
                o.put("to_package", e.toPackage);
                if (e.className != null) o.put("class_name", e.className);
                o.put("timestamp", e.timestamp);
                arr.put(o);
            } catch (Exception ignored) {}
        }
        return arr;
    }

    private static void recordLaunch(String fromPkg, String toPkg, String className, long time) {
        launches.add(new LaunchRecord(fromPkg, toPkg, className, time));
        if (launches.size() > MAX_LAUNCHES) launches.remove(0);

        // Only flag when the source is already suspicious; otherwise ordinary
        // app switching (home screen, "share to", etc.) would generate noise.
        if (HipsMonitor.hasAnyBehaviorFlag(fromPkg)) {
            String flag = "APP_LAUNCH:from=" + fromPkg + ":to=" + toPkg;
            if (className != null && !className.isEmpty()) {
                flag += ":class=" + className;
            }
            HipsMonitor.addBehaviorFlag(fromPkg, flag);
        }
    }

    private static void trim() {
        long cutoff = System.currentTimeMillis() - MAX_RECALL_MS;
        launches.removeIf(e -> e.timestamp < cutoff);
    }

    private static boolean isSelfPackage(String pkg) {
        return pkg == null || pkg.isEmpty() || pkg.startsWith("com.hydradragon.antivirus");
    }

    private static boolean hasUsageAccess(Context ctx) {
        try {
            AppOpsManager appOps = ctx.getSystemService(AppOpsManager.class);
            if (appOps == null) return false;
            int mode = appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(), ctx.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Throwable t) {
            Log.w(TAG, "hasUsageAccess failed", t);
            return false;
        }
    }
}
