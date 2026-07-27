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
 *   "behavior_state": {"foreground_package":"...","observed_packages":["..."]},
 *   "device_admin_packages": [{"package_name":"...","value":true}],
 *   "hidden_app_packages": [{"package_name":"...","value":true}]
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

    private static final class LauncherChangeEvent {
        String packageName;
        boolean changed;
        String method;
        boolean suspicious;
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
    private static final List<LauncherChangeEvent> launcherChangeEvents = new ArrayList<>();

    private static final class MinerEvent {
        String packageName;
        double cpuUsage;
        long memoryMb;
        boolean knownName;
        boolean malicious;
    }

    private static final List<MinerEvent> minerEvents = new ArrayList<>();

    private static final Map<String, BehaviorFlagEntry> behaviorFlags = new HashMap<>();

    private static boolean isRooted = false;
    private static boolean isDebugMode = false;
    private static boolean selfProtectionTriggered = false;
    private static String selfProtectionPackage = "";
    private static String foregroundPackage = "";
    private static final List<String> observedPackages = new ArrayList<>();

    private HipsMonitor() {}

    private static JSONArray buildDeviceAdminJson(android.content.Context ctx) {
        JSONArray arr = new JSONArray();
        if (ctx == null) return arr;
        android.app.admin.DevicePolicyManager dpm =
            (android.app.admin.DevicePolicyManager)
                ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) return arr;
        java.util.List<android.content.ComponentName> admins = dpm.getActiveAdmins();
        if (admins == null) return arr;
        for (android.content.ComponentName cn : admins) {
            try {
                JSONObject o = new JSONObject();
                o.put("package_name", cn.getPackageName());
                o.put("value", true);
                arr.put(o);
            } catch (Exception ignored) {}
        }
        return arr;
    }

    private static JSONArray buildHiddenAppJson(android.content.Context ctx) {
        JSONArray arr = new JSONArray();
        if (ctx == null) return arr;
        android.content.pm.PackageManager pm = ctx.getPackageManager();
        for (String pkg : observedPackages) {
            try {
                android.content.Intent launchIntent =
                    pm.getLaunchIntentForPackage(pkg);
                if (launchIntent != null) continue;
                JSONObject o = new JSONObject();
                o.put("package_name", pkg);
                o.put("value", true);
                arr.put(o);
            } catch (Exception ignored) {}
        }
        return arr;
    }

    private static boolean isSelfPackage(String pkg) {
        return pkg == null || pkg.isEmpty() || pkg.startsWith("com.hydradragon.antivirus");
    }

    public static synchronized void reportUiSpam(String pkg, int clicks, int windows, long windowMs, boolean malicious) {
        if (isSelfPackage(pkg)) return;
        UiSpamEvent e = new UiSpamEvent();
        e.packageName = pkg; e.clickCount = clicks; e.windowCount = windows;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        uiSpamEvents.add(e);
        if (uiSpamEvents.size() > MAX_EVENTS_PER_TYPE) uiSpamEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportNotificationSpam(String pkg, int count, long windowMs, boolean malicious) {
        if (isSelfPackage(pkg)) return;
        NotificationSpamEvent e = new NotificationSpamEvent();
        e.packageName = pkg; e.notificationCount = count; e.timeWindowMs = windowMs;
        e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        notificationSpamEvents.add(e);
        if (notificationSpamEvents.size() > MAX_EVENTS_PER_TYPE) notificationSpamEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportClickjack(String pkg, int clicks, String target, long windowMs, boolean malicious) {
        if (isSelfPackage(pkg)) return;
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
        if (isSelfPackage(pkg)) return;
        RansomwareEvent e = new RansomwareEvent();
        e.packageName = pkg; e.renameCount = renames; e.appendedSuffix = suffix;
        e.accessGranted = accessGranted; e.isAllFiles = isAllFiles;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        ransomwareEvents.add(e);
        if (ransomwareEvents.size() > MAX_EVENTS_PER_TYPE) ransomwareEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportCanary(String pkg, boolean triggered) {
        if (isSelfPackage(pkg)) return;
        CanaryEvent e = new CanaryEvent();
        e.packageName = pkg; e.triggered = triggered;
        canaryEvents.add(e);
        if (canaryEvents.size() > MAX_EVENTS_PER_TYPE) canaryEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportNetwork(String pkg, int connections, int hosts, int queries) {
        if (isSelfPackage(pkg)) return;
        NetworkEvent e = new NetworkEvent();
        e.packageName = pkg; e.connectionCount = connections;
        e.uniqueHosts = hosts; e.dnsQueries = queries;
        networkEvents.add(e);
        if (networkEvents.size() > MAX_EVENTS_PER_TYPE) networkEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportStrandHogg(String pkg, int activities, boolean suspicious) {
        if (isSelfPackage(pkg)) return;
        StrandHoggEvent e = new StrandHoggEvent();
        e.packageName = pkg; e.activityCount = activities; e.suspicious = suspicious;
        strandhoggEvents.add(e);
        if (strandhoggEvents.size() > MAX_EVENTS_PER_TYPE) strandhoggEvents.remove(0);
        observePackage(pkg);
    }

    public static synchronized void reportRemovalResistance(String pkg, int kicks, String screenKind,
                                                             long windowMs, boolean malicious) {
        if (isSelfPackage(pkg)) return;
        RemovalResistanceEvent e = new RemovalResistanceEvent();
        e.packageName = pkg; e.kickCount = kicks; e.screenKind = screenKind;
        e.timeWindowMs = windowMs; e.malicious = malicious; e.timestamp = System.currentTimeMillis();
        removalResistanceEvents.add(e);
        if (removalResistanceEvents.size() > MAX_EVENTS_PER_TYPE) removalResistanceEvents.remove(0);
        addBehaviorFlag(pkg, "REMOVAL_RESISTANCE");
        observePackage(pkg);
    }

    public static synchronized void reportLauncherChange(String pkg, boolean changed, String method, boolean suspicious) {
        if (isSelfPackage(pkg)) return;
        LauncherChangeEvent e = new LauncherChangeEvent();
        e.packageName = pkg; e.changed = changed; e.method = method; e.suspicious = suspicious;
        launcherChangeEvents.add(e);
        if (launcherChangeEvents.size() > MAX_EVENTS_PER_TYPE) launcherChangeEvents.remove(0);
        addBehaviorFlag(pkg, "LAUNCHER_CHANGE");
        observePackage(pkg);
    }

    public static synchronized void addMinerEvent(String pkg, double cpuUsage, long memoryMb,
                                                   boolean knownName, boolean malicious) {
        if (isSelfPackage(pkg)) return;
        MinerEvent e = new MinerEvent();
        e.packageName = pkg; e.cpuUsage = cpuUsage; e.memoryMb = memoryMb;
        e.knownName = knownName; e.malicious = malicious;
        minerEvents.add(e);
        if (minerEvents.size() > MAX_EVENTS_PER_TYPE) minerEvents.remove(0);
        addBehaviorFlag(pkg, "MINER");
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
        if (!isSelfPackage(foregroundPackage)) observePackage(foregroundPackage);
    }

    public static synchronized void addBehaviorFlag(String pkg, String flag) {
        if (isSelfPackage(pkg) || flag == null) return;
        BehaviorFlagEntry entry = behaviorFlags.get(pkg);
        if (entry == null) {
            entry = new BehaviorFlagEntry();
            entry.packageName = pkg;
            behaviorFlags.put(pkg, entry);
        }
        if (!entry.flags.contains(flag)) entry.flags.add(flag);
        observePackage(pkg);
    }

    public static synchronized boolean packageHasMinerMemory(String pkg, long minMemoryMb) {
        if (pkg == null) return false;
        for (MinerEvent e : minerEvents) {
            if (pkg.equals(e.packageName) && e.memoryMb >= minMemoryMb && e.malicious) {
                return true;
            }
        }
        return false;
    }

    static synchronized BehaviorGraphData collectBehaviorData(String pkg, android.content.Context ctx) {
        if (pkg == null) pkg = "";
        final boolean isGeneral = pkg.isEmpty();

        if (isGeneral) {
            // General Device Behavior: use per-package MAX (not sum) for count
            // metrics so the graph reflects the worst single offender rather
            // than an inflated aggregate that grows with the number of apps.
            return collectGeneralBehaviorData(ctx);
        }

        // --- Per-package path ---
        int ui = 0, notif = 0, cj = 0, rw = 0, net = 0, minerMem = 0, flags = 0;
        int fileRead = 0, fileReadHigh = 0;
        int fileCreated = 0, fileCopy = 0;
        boolean sh = false, rr = false, lc = false, canary = false;

        for (UiSpamEvent e : uiSpamEvents) {
            if (pkg.equals(e.packageName)) ui += e.clickCount;
        }
        for (NotificationSpamEvent e : notificationSpamEvents) {
            if (pkg.equals(e.packageName)) notif += e.notificationCount;
        }
        for (ClickjackEvent e : clickjackEvents) {
            if (pkg.equals(e.packageName)) cj += e.rapidClicks;
        }
        for (RansomwareEvent e : ransomwareEvents) {
            if (pkg.equals(e.packageName)) rw += e.renameCount;
        }
        for (NetworkEvent e : networkEvents) {
            if (pkg.equals(e.packageName)) net += e.connectionCount;
        }
        for (MinerEvent e : minerEvents) {
            if (pkg.equals(e.packageName)) minerMem = Math.max(minerMem, (int) e.memoryMb);
        }
        for (StrandHoggEvent e : strandhoggEvents)      { if (pkg.equals(e.packageName)) sh = true; }
        for (RemovalResistanceEvent e : removalResistanceEvents) { if (pkg.equals(e.packageName)) rr = true; }
        for (LauncherChangeEvent e : launcherChangeEvents) { if (pkg.equals(e.packageName)) lc = true; }
        for (CanaryEvent e : canaryEvents)              { if (pkg.equals(e.packageName)) canary = true; }

        int created = com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.countTotalObservedFiles();
        int deleted = com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.countRecentDeletions();
        boolean hasWiper = false, hasScanMalware = false;
        BehaviorFlagEntry flagEntry = behaviorFlags.get(pkg);
        if (flagEntry != null) {
            flags = flagEntry.flags.size();
            for (String f : flagEntry.flags) {
                if (f.startsWith("FILE_READ")) {
                    fileRead++;
                    if (f.contains("conf=8") || f.contains("conf=9") || f.contains("conf=100")) fileReadHigh++;
                } else if (f.startsWith("FILE_CREATED")) { fileCreated++;
                } else if (f.startsWith("FILE_COPY"))    { fileCopy++;
                } else if (f.startsWith("WIPER"))        { hasWiper = true;
                } else if (f.equals("SCAN_MALWARE") || f.equals("DOWNLOAD_MALWARE") || f.equals("PROCESS_ANOMALY")) {
                    hasScanMalware = true;
                }
            }
        }

        boolean da = false, ha = false;
        if (ctx != null) {
            try {
                android.app.admin.DevicePolicyManager dpm =
                    (android.app.admin.DevicePolicyManager) ctx.getSystemService(android.content.Context.DEVICE_POLICY_SERVICE);
                if (dpm != null) {
                    for (android.content.ComponentName cn : dpm.getActiveAdmins()) {
                        if (pkg.equals(cn.getPackageName())) { da = true; break; }
                    }
                }
                try { ha = ctx.getPackageManager().getLaunchIntentForPackage(pkg) == null; }
                catch (Throwable ignored) {}
            } catch (Throwable ignored) {}
        }
        return new BehaviorGraphData(pkg, ui, notif, cj, rw, net, minerMem,
            fileRead, fileReadHigh, fileCreated, fileCopy, flags,
            sh, rr, lc, canary, da, ha, isRooted, isDebugMode,
            created, deleted, hasWiper, hasScanMalware);
    }

    /**
     * Aggregates all packages using MAX per metric so that "General Device
     * Behavior" shows the peak threat level of the single worst-behaving app,
     * not an inflated sum that grows with the number of monitored packages.
     */
    private static BehaviorGraphData collectGeneralBehaviorData(android.content.Context ctx) {
        int maxUi = 0, maxNotif = 0, maxCj = 0, maxRw = 0, maxNet = 0, maxMiner = 0, maxFlags = 0;
        int maxFileRead = 0, maxFileReadHigh = 0, maxFileCreated = 0, maxFileCopy = 0;
        boolean sh = false, rr = false, lc = false, canary = false;
        boolean hasWiper = false, hasScanMalware = false;

        // Aggregate per-package and take the max for count fields
        java.util.Set<String> allPkgs = new java.util.HashSet<>();
        for (UiSpamEvent e : uiSpamEvents)           if (e.packageName != null) allPkgs.add(e.packageName);
        for (NotificationSpamEvent e : notificationSpamEvents) if (e.packageName != null) allPkgs.add(e.packageName);
        for (ClickjackEvent e : clickjackEvents)      if (e.packageName != null) allPkgs.add(e.packageName);
        for (RansomwareEvent e : ransomwareEvents)    if (e.packageName != null) allPkgs.add(e.packageName);
        for (NetworkEvent e : networkEvents)          if (e.packageName != null) allPkgs.add(e.packageName);
        for (StrandHoggEvent e : strandhoggEvents)   { if (e.packageName != null) allPkgs.add(e.packageName); sh = true; }
        for (RemovalResistanceEvent e : removalResistanceEvents) { if (e.packageName != null) allPkgs.add(e.packageName); rr = true; }
        for (LauncherChangeEvent e : launcherChangeEvents) { if (e.packageName != null) allPkgs.add(e.packageName); lc = true; }
        allPkgs.addAll(behaviorFlags.keySet());
        allPkgs.removeIf(HipsMonitor::isSelfPackage);

        for (String p : allPkgs) {
            int pUi = 0, pNotif = 0, pCj = 0, pRw = 0, pNet = 0, pMiner = 0, pFlags = 0;
            int pFr = 0, pFrHigh = 0, pFc = 0, pCopy = 0;
            for (UiSpamEvent e : uiSpamEvents)           if (p.equals(e.packageName)) pUi += e.clickCount;
            for (NotificationSpamEvent e : notificationSpamEvents) if (p.equals(e.packageName)) pNotif += e.notificationCount;
            for (ClickjackEvent e : clickjackEvents)      if (p.equals(e.packageName)) pCj += e.rapidClicks;
            for (RansomwareEvent e : ransomwareEvents)    if (p.equals(e.packageName)) pRw += e.renameCount;
            for (NetworkEvent e : networkEvents)          if (p.equals(e.packageName)) pNet += e.connectionCount;
            for (MinerEvent e : minerEvents)              if (p.equals(e.packageName)) pMiner = Math.max(pMiner, (int) e.memoryMb);
            BehaviorFlagEntry fe = behaviorFlags.get(p);
            if (fe != null) {
                pFlags = fe.flags.size();
                for (String f : fe.flags) {
                    if (f.startsWith("FILE_READ")) {
                        pFr++;
                        if (f.contains("conf=8") || f.contains("conf=9") || f.contains("conf=100")) pFrHigh++;
                    } else if (f.startsWith("FILE_CREATED")) { pFc++;
                    } else if (f.startsWith("FILE_COPY"))    { pCopy++;
                    } else if (f.startsWith("WIPER"))        { hasWiper = true;
                    } else if (f.equals("SCAN_MALWARE") || f.equals("DOWNLOAD_MALWARE") || f.equals("PROCESS_ANOMALY")) {
                        hasScanMalware = true;
                    }
                }
            }
            maxUi       = Math.max(maxUi, pUi);
            maxNotif    = Math.max(maxNotif, pNotif);
            maxCj       = Math.max(maxCj, pCj);
            maxRw       = Math.max(maxRw, pRw);
            maxNet      = Math.max(maxNet, pNet);
            maxMiner    = Math.max(maxMiner, pMiner);
            maxFlags    = Math.max(maxFlags, pFlags);
            maxFileRead = Math.max(maxFileRead, pFr);
            maxFileReadHigh = Math.max(maxFileReadHigh, pFrHigh);
            maxFileCreated  = Math.max(maxFileCreated, pFc);
            maxFileCopy     = Math.max(maxFileCopy, pCopy);
        }

        int created = com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.countTotalObservedFiles();
        int deleted = com.hydradragon.antivirus.engine.RansomwareBehaviorGuard.countRecentDeletions();

        return new BehaviorGraphData("", maxUi, maxNotif, maxCj, maxRw, maxNet, maxMiner,
            maxFileRead, maxFileReadHigh, maxFileCreated, maxFileCopy, maxFlags,
            sh, rr, lc, canary, false, false, isRooted, isDebugMode,
            created, deleted, hasWiper, hasScanMalware);
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
     */
    public static synchronized String buildReportJson(android.content.Context ctx) {
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

            // Canary events
            JSONArray canArr = new JSONArray();
            for (CanaryEvent e : canaryEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("canary_triggered", e.triggered);
                canArr.put(o);
            }
            root.put("canary_events", canArr);

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

            // Launcher-change events (homepage/app default launcher hijacking)
            JSONArray lcArr = new JSONArray();
            for (LauncherChangeEvent e : launcherChangeEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("changed", e.changed);
                o.put("method", e.method != null ? e.method : "");
                o.put("is_suspicious", e.suspicious);
                lcArr.put(o);
            }
            root.put("launcher_change_events", lcArr);

            // Crypto-miner events (CPU + memory profiling)
            JSONArray minArr = new JSONArray();
            for (MinerEvent e : minerEvents) {
                JSONObject o = new JSONObject();
                o.put("package_name", e.packageName);
                o.put("cpu_usage", e.cpuUsage);
                o.put("memory_mb", e.memoryMb);
                o.put("known_name", e.knownName);
                o.put("is_malicious", e.malicious);
                minArr.put(o);
            }
            root.put("miner_events", minArr);

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

            JSONArray daArr = buildDeviceAdminJson(ctx);
            if (daArr.length() > 0) root.put("device_admin_packages", daArr);
            JSONArray haArr = buildHiddenAppJson(ctx);
            if (haArr.length() > 0) root.put("hidden_app_packages", haArr);

            return root.toString();
        } catch (Exception e) {
            Log.e(TAG, "buildReportJson failed", e);
            return "";
        }
    }

    public static synchronized List<String> getAllObservedPackages() {
        java.util.Set<String> set = new java.util.LinkedHashSet<>();
        for (UiSpamEvent e : uiSpamEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (NotificationSpamEvent e : notificationSpamEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (ClickjackEvent e : clickjackEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (RansomwareEvent e : ransomwareEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (NetworkEvent e : networkEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (MinerEvent e : minerEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (StrandHoggEvent e : strandhoggEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (RemovalResistanceEvent e : removalResistanceEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (LauncherChangeEvent e : launcherChangeEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        for (CanaryEvent e : canaryEvents) if (e.packageName != null && !e.packageName.isEmpty()) set.add(e.packageName);
        set.addAll(behaviorFlags.keySet());
        set.addAll(observedPackages);
        set.remove("");
        // Never expose the antivirus app itself in the behavior graph.
        set.removeIf(pkg -> pkg.startsWith("com.hydradragon.antivirus"));
        return new ArrayList<>(set);
    }
}
