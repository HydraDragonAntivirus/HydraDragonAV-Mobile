package com.hydradragon.antivirus.engine;

import java.util.ArrayList;
import java.util.List;

public final class BehaviorGraphData {

    public final String packageName;
    public final int uiSpamCount;
    public final int notificationSpamCount;
    public final int clickjackCount;
    public final int ransomwareCount;
    public final int networkConnectionCount;
    public final int minerMemoryMb;
    public final int fileReadCount;
    public final int fileReadHighConfCount;
    public final int flagCount;
    public final boolean hasStrandHogg;
    public final boolean hasRemovalResistance;
    public final boolean hasLauncherChange;
    public final boolean hasCanaryTrigger;
    public final boolean isDeviceAdmin;
    public final boolean isHiddenApp;
    public final boolean isRooted;
    public final boolean isDebug;
    public final int createdFiles;
    public final int deletedFiles;
    public final boolean hasWiper;

    BehaviorGraphData(String packageName, int uiSpamCount, int notificationSpamCount,
                      int clickjackCount, int ransomwareCount, int networkConnectionCount,
                      int minerMemoryMb, int fileReadCount, int fileReadHighConfCount,
                      int flagCount, boolean hasStrandHogg, boolean hasRemovalResistance,
                      boolean hasLauncherChange, boolean hasCanaryTrigger,
                      boolean isDeviceAdmin, boolean isHiddenApp,
                      boolean isRooted, boolean isDebug,
                      int createdFiles, int deletedFiles, boolean hasWiper) {
        this.packageName = packageName;
        this.uiSpamCount = uiSpamCount;
        this.notificationSpamCount = notificationSpamCount;
        this.clickjackCount = clickjackCount;
        this.ransomwareCount = ransomwareCount;
        this.networkConnectionCount = networkConnectionCount;
        this.minerMemoryMb = minerMemoryMb;
        this.fileReadCount = fileReadCount;
        this.fileReadHighConfCount = fileReadHighConfCount;
        this.flagCount = flagCount;
        this.hasStrandHogg = hasStrandHogg;
        this.hasRemovalResistance = hasRemovalResistance;
        this.hasLauncherChange = hasLauncherChange;
        this.hasCanaryTrigger = hasCanaryTrigger;
        this.isDeviceAdmin = isDeviceAdmin;
        this.isHiddenApp = isHiddenApp;
        this.isRooted = isRooted;
        this.isDebug = isDebug;
        this.createdFiles = createdFiles;
        this.deletedFiles = deletedFiles;
        this.hasWiper = hasWiper;
    }

    public static BehaviorGraphData forPackage(String pkg, android.content.Context ctx) {
        return HipsMonitor.collectBehaviorData(pkg, ctx);
    }

    public List<AxisValue> computeAxisValues() {
        List<AxisValue> axes = new ArrayList<>();

        axes.add(new AxisValue("Network", normalize(networkConnectionCount, 0, 50)));
        axes.add(new AxisValue("File Ops", normalize(ransomwareCount + fileReadCount, 0, 20)));
        axes.add(new AxisValue("Permissions", normalize(
            (isDeviceAdmin ? 30 : 0) + (isHiddenApp ? 30 : 0), 0, 100)));
        axes.add(new AxisValue("Malware", normalize(
            (hasStrandHogg ? 25 : 0) + (hasRemovalResistance ? 25 : 0)
            + (hasLauncherChange ? 15 : 0) + (hasCanaryTrigger ? 35 : 0), 0, 100)));
        axes.add(new AxisValue("Wiper", normalize(
            (hasWiper ? 80 : 0) + deletedFiles, 0, 50)));
        axes.add(new AxisValue("System", normalize(
            (isRooted ? 50 : 0) + (isDebug ? 25 : 0), 0, 100)));
        axes.add(new AxisValue("Behavior", normalize(flagCount, 0, 8)));
        axes.add(new AxisValue("Miner", normalize(minerMemoryMb, 0, 128)));
        axes.add(new AxisValue("Spam", normalize(uiSpamCount + notificationSpamCount, 0, 50)));

        return axes;
    }

    private static int normalize(int value, int min, int max) {
        if (max <= min) return 0;
        int clamped = Math.max(min, Math.min(max, value));
        return (clamped - min) * 100 / (max - min);
    }

    public static final class AxisValue {
        public final String label;
        public final int level;

        AxisValue(String label, int level) {
            this.label = label;
            this.level = level;
        }
    }
}
