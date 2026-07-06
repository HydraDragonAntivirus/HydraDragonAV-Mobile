package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HIPS (Host Intrusion Prevention System) behavioral metadata collector.
 *
 * Continuously gathers behavioral signals from all detection components
 * (DynamicAnalysisService, RansomwareBehaviorGuard, FileCanaryGuard,
 * NetworkMonitor, StrandHoggGuard, SelfProtection, RootCheck, DebugModeCheck)
 * and exposes a JSON report (merged into the YARA-X {@code hydradragon} module
 * metadata) so HIPS rules can match behavioral patterns.
 *
 * JSON shape expected by the hydradragon module (merged into its metadata):
 * <pre>{@code
 * {
 *   "ui_spam_events": [{"package_name":"...","click_count":30,"window_count":5,"time_window_seconds":8,"is_malicious":true}],
 *   "notification_spam_events": [{"package_name":"...","notification_count":20,"time_window_seconds":10,"is_malicious":true}],
 *   "clickjack_events": [{"package_name":"...","rapid_clicks":3,"target_package":"com.android.packageinstaller","time_window_seconds":2,"is_malicious":true}],
 *   "ransomware_events": [{"package_name":"...","rename_count":5,"appended_suffix":".locked","access_granted":true,"is_all_files":true,"time_window_seconds":60,"is_malicious":true}],
 *   "canary_events": [{"package_name":"...","canary_triggered":true}],
 *   "network_events": [{"package_name":"...","connection_count":50,"unique_hosts":10,"dns_queries":100}],
 *   "strandhogg_events": [{"package_name":"...","activity_count":5,"is_suspicious":true}],
 *   "removal_resistance_events": [{"package_name":"...","kick_count":3,"screen_kind":"uninstall","time_window_seconds":300,"is_malicious":true}],
 *   "system": {"is_rooted":false,"is_debug_mode":false,"is_self_protection_triggered":false,"package_name":""},
 *   "behavior_flags": [{"package_name":"...","flags":["UI_SPAM","RANSOMWARE"]}],
 *   "behavior_state": {"foreground_package":"...","observed_packages":["..."]}
 * }
 * }</pre>
 */
public final class HipsMonitor {

    private static final String TAG = "HydraDragon-Hips";

    private static final int MAX_EVENTS_PER_TYPE = 256;
    private static final int MAX_PACKAGES = 1024;

    private static final class UiSpamEvent {
        String packageName;
        int clickCount;
        int windowCount;
        long timeWindowMs;
        boolean malicious;
        long timestamp;
    }

    private static final class NotificationSpamEvent {
        String packageName;
        int notificationCount;
        long timeWindowMs;
        boolean malicious;
        long timestamp;
    }

    private static final class ClickjackEvent {
        String packageName;
        int rapidClicks;
        String targetPackage;
        long timeWindowMs;
        boolean malicious;
        long timestamp;
    }

    private static final class RansomwareEvent {
        String packageName;
        int renameCount;
        String appendedSuffix;
        boolean accessGranted;
        boolean isAllFiles;
        long timeWindowMs;
        boolean malicious;
        long timestamp;
    }

    private static final class CanaryEvent {
        String packageName;
        boolean triggered;
    }

    private static final class NetworkEvent {
        String packageName;
        int connectionCount;
        int uniqueHosts;
        int dnsQueries;
    }

    private static final class StrandHoggEvent {
        String packageName;
        int activityCount;
        boolean suspicious;
    }

    private static final class RemovalResistanceEvent {
        String packageName;
        int kickCount;
        String screenKind;
        long timeWindowMs;
        boolean malicious;
        long timestamp;
    }

    private static final class BehaviorFlagEntry {
        String packageName;
        final List<String> flags = new ArrayList<>();
    }

    private static final List<UiSpamEvent> uiSpamEvents = new ArrayList<>();
    private static final List<NotificationSpamEvent> notificationSpamEvents = new ArrayList<>();
    private static final List<ClickjackEvent> clickjackEvents = new ArrayList<>();
    private static final List<RansomwareEvent> ransomwareEvents = new ArrayList<>();
    private static final List<CanaryEvent> canaryEvents = new ArrayList<>();
    private static final List<NetworkEvent> networkEvents = new ArrayList<>();
    private static final List<StrandHoggEvent> strandhoggEvents = new ArrayList<>();
    private static final List<RemovalResistanceEvent> removalResistanceEvents = new ArrayList<>();
    private static final Map<String, BehaviorFlagEntry> behaviorFlags = new HashMap<>();

    private static boolean isRooted = false;
    private static boolean isDebugMode = false;
    private static boolean selfProtectionTriggered = false;
    private static String selfProtectionPackage = "";
    private static String foregroundPackage = "";
    private static final List<String> observedPackages = new ArrayList<>();

    private HipsMonitor() {}

    public static synchronized void reportUiSpam(String pkg, int clicks, int windows, long windowMs, boolean malicious) {
        if (pkg == null) return;
        UiSpamEvent e = new UiSpamEvent();
        e.packageName = pkg; e.clickCount = clicks; e.windowCount = windows;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        uiSpamEvents.add(e);
        if (uiSpamEvents.size() > MAX_EVENTS_PER_TYPE) uiSpamEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportNotificationSpam(String pkg, int count, long windowMs, boolean malicious) {
        if (pkg == null) return;
        NotificationSpamEvent e = new NotificationSpamEvent();
        e.packageName = pkg; e.notificationCount = count; e.timeWindowMs = windowMs;
        e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        notificationSpamEvents.add(e);
        if (notificationSpamEvents.size() > MAX_EVENTS_PER_TYPE) notificationSpamEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportClickjack(String pkg, int clicks, String target, long windowMs, boolean malicious) {
        if (pkg == null) return;
        ClickjackEvent e = new ClickjackEvent();
        e.packageName = pkg; e.rapidClicks = clicks; e.targetPackage = target;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        clickjackEvents.add(e);
        if (clickjackEvents.size() > MAX_EVENTS_PER_TYPE) clickjackEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportRansomware(String pkg, int renames, String suffix,
                                                      boolean accessGranted, boolean isAllFiles,
                                                      long windowMs, boolean malicious) {
        if (pkg == null) return;
        RansomwareEvent e = new RansomwareEvent();
        e.packageName = pkg; e.renameCount = renames; e.appendedSuffix = suffix;
        e.accessGranted = accessGranted; e.isAllFiles = isAllFiles;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        ransomwareEvents.add(e);
        if (ransomwareEvents.size() > MAX_EVENTS_PER_TYPE) ransomwareEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportCanary(String pkg, boolean triggered) {
        if (pkg == null) return;
        CanaryEvent e = new CanaryEvent();
        e.packageName = pkg; e.triggered = triggered;
        canaryEvents.add(e);
        if (canaryEvents.size() > MAX_EVENTS_PER_TYPE) canaryEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportNetwork(String pkg, int connections, int hosts, int queries) {
        if (pkg == null) return;
        NetworkEvent e = new NetworkEvent();
        e.packageName = pkg; e.connectionCount = connections;
        e.uniqueHosts = hosts; e.dnsQueries = queries;
        networkEvents.add(e);
        if (networkEvents.size() > MAX_EVENTS_PER_TYPE) networkEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportStrandHogg(String pkg, int activities, boolean suspicious) {
        if (pkg == null) return;
        StrandHoggEvent e = new StrandHoggEvent();
        e.packageName = pkg; e.activityCount = activities; e.suspicious = suspicious;
        strandhoggEvents.add(e);
        if (strandhoggEvents.size() > MAX_EVENTS_PER_TYPE) strandhoggEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportRemovalResistance(String pkg, int kicks, String screenKind,
                                                              long windowMs, boolean malicious) {
        if (pkg == null) return;
        RemovalResistanceEvent e = new RemovalResistanceEvent();
        e.packageName = pkg; e.kickCount = kicks; e.screenKind = screenKind;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        removalResistanceEvents.add(e);
        if (removalResistanceEvents.size() > MAX_EVENTS_PER_TYPE) removalResistanceEvents.remove(0);
        addBehaviorFlag(pkg, "REMOVAL_RESISTANCE");
        observePackage(pkg);
    }

    public static synchronized void setRooted(boolean rooted) { isRooted = rooted; }

    public static synchronized void setDebugMode(boolean debug) { isDebugMode = debug; }

    public static synchronized void setSelfProtectionTriggered(boolean triggered, String pkg) {
        selfProtectionTriggered = triggered;
        selfProtectionPackage = pkg != null ? pkg : "";
    }

    public static synchronized void setForegroundPackage(String pkg) {
        foregroundPackage = pkg != null ? pkg : "";
        if (!foregroundPackage.isEmpty()) observePackage(foregroundPackage);
    }

    public static synchronized void addBehaviorFlag(String pkg, String flag) {
        if (pkg == null || flag == null) return;
        BehaviorFlagEntry entry = behaviorFlags.get(pkg);
        if (entry == null) {
            entry = new BehaviorFlagEntry();
            entry.packageName = pkg;
            behaviorFlags.put(pkg, entry);
        }
        if (!entry.flags.contains(flag)) entry.flags.add(flag);
        observePackage(pkg);
    }

    public static synchronized boolean hasBehaviorFlag(String pkg, String flag) {
        BehaviorFlagEntry entry = behaviorFlags.get(pkg);
        return entry != null && entry.flags.contains(flag);
    }

    private static void observePackage(String pkg) {
        if (pkg == null || pkg.isEmpty()) return;
        if (!observedPackages.contains(pkg)) {
            observedPackages.add(pkg);
            if (observedPackages.size() > MAX_PACKAGES) observedPackages.remove(0);
        }
    }

    /**
     * Build the complete HIPS JSON report for the YARA-X hydradragon module.
     * Clears accumulated events after building (one-shot evaluation).
     */
    public static synchronized String buildReportJson() {
        try {
            JSONObject root = new JSONObject();

            // UI spam events
            JSONArray uiArr = new JSONArray();
            for (UiSpamEvent e : uiSpamEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("click_count", e.clickCount);
                o.put("window_count", e.windowCount);
                o.put("time_window_seconds", e.timeWindowMs / 1000);
                o.put("is_malicious", e.malicious);
                uiArr.put(o);
            }
            root.put("ui_spam_events", uiArr);
            uiSpamEvents.clear();

            // Notification spam events
            JSONArray notifArr = new JSONArray();
            for (NotificationSpamEvent e : notificationSpamEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("notification_count", e.notificationCount);
                o.put("time_window_seconds", e.timeWindowMs / 1000);
                o.put("is_malicious", e.malicious);
                notifArr.put(o);
            }
            root.put("notification_spam_events", notifArr);
            notificationSpamEvents.clear();

            // Clickjack events
            JSONArray cjArr = new JSONArray();
            for (ClickjackEvent e : clickjackEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("rapid_clicks", e.rapidClicks);
                o.put("target_package", e.targetPackage != null ? e.targetPackage : "");
                o.put("time_window_seconds", e.timeWindowMs / 1000);
                o.put("is_malicious", e.malicious);
                cjArr.put(o);
            }
            root.put("clickjack_events", cjArr);
            clickjackEvents.clear();

            // Ransomware events
            JSONArray rwArr = new JSONArray();
            for (RansomwareEvent e : ransomwareEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("rename_count", e.renameCount);
                o.put("appended_suffix", e.appendedSuffix != null ? e.appendedSuffix : "");
                o.put("access_granted", e.accessGranted);
                o.put("is_all_files", e.isAllFiles);
                o.put("time_window_seconds", e.timeWindowMs / 1000);
                o.put("is_malicious", e.malicious);
                rwArr.put(o);
            }
            root.put("ransomware_events", rwArr);
            ransomwareEvents.clear();

            // Canary events
            JSONArray canArr = new JSONArray();
            for (CanaryEvent e : canaryEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("canary_triggered", e.triggered);
                canArr.put(o);
            }
            root.put("canary_events", canArr);
            canaryEvents.clear();

            // Network events
            JSONArray netArr = new JSONArray();
            for (NetworkEvent e : networkEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("connection_count", e.connectionCount);
                o.put("unique_hosts", e.uniqueHosts);
                o.put("dns_queries", e.dnsQueries);
                netArr.put(o);
            }
            root.put("network_events", netArr);
            networkEvents.clear();

            // Captured packets (VpnService full-tunnel mode) for Suricata
            // payload matching via hydradragon.network.payload_hex.
            String pktsJson = com.hydradragon.antivirus.service.DnsVpnService.getCapturedPacketsJson();
            if (!pktsJson.isEmpty() && !pktsJson.equals("[]")) {
                JSONObject netObj = root.optJSONObject("network");
                if (netObj == null) netObj = new JSONObject();
                netObj.put("packets", new JSONArray(pktsJson));
                root.put("network", netObj);
            }

            // StrandHogg events
            JSONArray shArr = new JSONArray();
            for (StrandHoggEvent e : strandhoggEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("activity_count", e.activityCount);
                o.put("is_suspicious", e.suspicious);
                shArr.put(o);
            }
            root.put("strandhogg_events", shArr);
            strandhoggEvents.clear();

            // Removal-resistance events (device-admin/uninstall screen "kick")
            JSONArray rrArr = new JSONArray();
            for (RemovalResistanceEvent e : removalResistanceEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("kick_count", e.kickCount);
                o.put("screen_kind", e.screenKind != null ? e.screenKind : "");
                o.put("time_window_seconds", e.timeWindowMs / 1000);
                o.put("is_malicious", e.malicious);
                rrArr.put(o);
            }
            root.put("removal_resistance_events", rrArr);
            removalResistanceEvents.clear();

            // System state
            JSONObject sys = new JSONObject();
            sys.put("is_rooted", isRooted);
            sys.put("is_debug_mode", isDebugMode);
            sys.put("is_self_protection_triggered", selfProtectionTriggered);
            sys.put("package_name", selfProtectionPackage);
            root.put("system", sys);

            // Behavior flags
            JSONArray bfArr = new JSONArray();
            for (BehaviorFlagEntry entry : behaviorFlags.values()) {
                JSONObject o = new JSONObject();
                o.put("package_name", entry.packageName);
                JSONArray flagsArr = new JSONArray();
                for (String f : entry.flags) flagsArr.put(f);
                o.put("flags", flagsArr);
                bfArr.put(o);
            }
            root.put("behavior_flags", bfArr);

            // Behavior state
            JSONObject state = new JSONObject();
            state.put("foreground_package", foregroundPackage);
            JSONArray obsArr = new JSONArray();
            for (String p : observedPackages) obsArr.put(p);
            state.put("observed_packages", obsArr);
            root.put("behavior_state", state);

            return root.toString();
        } catch (Exception e) {
            Log.e(TAG, "buildReportJson failed", e);
            return "";
        }
    }
}
