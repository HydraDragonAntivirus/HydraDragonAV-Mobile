package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import com.hydradragon.antivirus.model.ThreatResult;
import com.hydradragon.antivirus.service.ThreatLogger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class MinerDetector {

    private static final String TAG = "HydraDragon-Miner";
    private static final long SAMPLE_INTERVAL_MS = 15_000;
    private static final long SUSTAINED_THRESHOLD_MS = 45_000;
    private static final float CPU_THRESHOLD = 0.20f;
    private static final long MEMORY_THRESHOLD_BYTES = 20L * 1024 * 1024;
    private static final int MAX_SAMPLES = (int) (SUSTAINED_THRESHOLD_MS / SAMPLE_INTERVAL_MS);

    private static final Set<String> KNOWN_MINER_NAMES = new HashSet<>(Arrays.asList(
        "cryptominer", "xmrig", "xmr-stak", "minerd", "ccminer", "cpuminer",
        "sgminer", "bfgminer", "cgminer", "ethminer", "claymore", "excavator",
        "t-rex", "phoenixminer", "lolminer", "nbminer", "gminer", "teamredminer",
        "bminer", "ewbf", "zm", "nanominer", "wildrig", "srbmminer", "comitari",
        "stratum", "crypto", "miner"
    ));

    private final Context context;
    private final Map<Integer, ProcessSample> lastSamples = new HashMap<>();
    private final Map<Integer, SustainedState> sustainedStates = new HashMap<>();
    private long lastSampleTime = 0;

    private static final class ProcessSample {
        final long cpuTicks;
        final long timestamp;

        ProcessSample(long cpuTicks, long timestamp) {
            this.cpuTicks = cpuTicks;
            this.timestamp = timestamp;
        }
    }

    private static final class SustainedState {
        int aboveThresholdCount = 0;
        boolean flagged = false;
    }

    public MinerDetector(Context context) {
        this.context = context;
    }

    public void scan() {
        if (!BehaviorDetectionSettings.isEnabled(context, BehaviorDetectionSettings.CRYPTO_MINER)) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastSampleTime < SAMPLE_INTERVAL_MS) {
            return;
        }
        lastSampleTime = now;

        try {
            File proc = new File("/proc");
            File[] entries = proc.listFiles((dir, name) -> name.matches("\\d+"));
            if (entries == null) return;

            long totalCpuTicks = readTotalCpuTicks();
            if (totalCpuTicks < 0) return;

            for (File pidDir : entries) {
                int pid;
                try {
                    pid = Integer.parseInt(pidDir.getName());
                } catch (NumberFormatException e) {
                    continue;
                }
                try {
                    checkProcess(pid, pidDir, totalCpuTicks, now);
                } catch (Throwable ignored) {
                }
            }

            // Clean up stale entries for PIDs that no longer exist
            lastSamples.keySet().removeIf(p -> !new File("/proc/" + p).exists());
            sustainedStates.keySet().removeIf(p -> !new File("/proc/" + p).exists());
        } catch (Throwable t) {
            Log.e(TAG, "scan failed", t);
        }
    }

    private void checkProcess(int pid, File pidDir, long totalCpuTicks, long now) {
        String name = readProcessName(pidDir);
        if (name == null || name.isEmpty()) return;

        long memBytes = readVmRss(pidDir);
        long processCpuTicks = readProcessCpuTicks(pidDir);
        if (processCpuTicks < 0) return;

        ProcessSample prev = lastSamples.get(pid);
        lastSamples.put(pid, new ProcessSample(processCpuTicks, now));

        if (prev == null) return;

        long dtTicks = processCpuTicks - prev.cpuTicks;
        long dtWall = now - prev.timestamp;
        if (dtWall <= 0) return;

        float cpuFraction = (float) dtTicks / (float) totalCpuTicks;

        boolean nameMatch = isKnownMinerName(name);

        if (cpuFraction >= CPU_THRESHOLD && memBytes >= MEMORY_THRESHOLD_BYTES && dtWall >= SAMPLE_INTERVAL_MS - 2000) {
            SustainedState state = sustainedStates.get(pid);
            if (state == null) {
                state = new SustainedState();
                sustainedStates.put(pid, state);
            }
            state.aboveThresholdCount++;
            Log.d(TAG, "pid=" + pid + " name=" + name + " cpu=" + String.format("%.1f", cpuFraction * 100) + "% mem=" + (memBytes / 1024 / 1024) + "MB sustained=" + state.aboveThresholdCount + "/" + MAX_SAMPLES);

            if (state.aboveThresholdCount >= MAX_SAMPLES && !state.flagged || nameMatch) {
                state.flagged = true;
                reportMiner(pid, name, cpuFraction, memBytes, nameMatch);
            }
        } else if (nameMatch) {
            SustainedState state = sustainedStates.get(pid);
            if (state != null && state.flagged) return;
            if (state == null) {
                state = new SustainedState();
                sustainedStates.put(pid, state);
            }
            if (!state.flagged) {
                state.flagged = true;
                reportMiner(pid, name, cpuFraction, memBytes, true);
            }
        } else {
            // Reset if below threshold
            SustainedState state = sustainedStates.get(pid);
            if (state != null && state.aboveThresholdCount > 0) {
                state.aboveThresholdCount = Math.max(0, state.aboveThresholdCount - 1);
            }
        }
    }

    private void reportMiner(int pid, String name, float cpuFraction, long memBytes, boolean nameMatch) {
        String pkg = resolvePackageName(pid, name);
        String appName = pkg != null ? pkg : name;
        boolean isInstalled = pkg != null;

        List<String> reasons = new java.util.ArrayList<>();
        if (nameMatch) {
            reasons.add("Known miner process: " + name);
        }
        reasons.add("Sustained CPU: " + String.format("%.0f", cpuFraction * 100) + "%");
        reasons.add("Memory: " + (memBytes / 1024 / 1024) + "MB");

        int riskScore = nameMatch ? 85 : 70;

        if (isInstalled) {
            com.hydradragon.antivirus.engine.HipsMonitor.addMinerEvent(
                pkg, cpuFraction, memBytes / 1024 / 1024, nameMatch, true);
        }

        ThreatResult threat = new ThreatResult.Builder(isInstalled ? pkg : name)
            .setAppName(appName)
            .setRiskScore(riskScore)
            .setThreatType(ThreatResult.ThreatType.PUA)
            .setReasons(reasons)
            .setStandaloneFile(!isInstalled)
            .build();

        ThreatLogger.logThreat(context, threat, "MINER DETECTED");

        BehaviorFlags.flag(context, isInstalled ? pkg : name,
            "Crypto miner: CPU " + String.format("%.0f", cpuFraction * 100)
            + "% mem " + (memBytes / 1024 / 1024) + "MB");

        BehaviorResponse.killAndPromptUninstall(context, threat);
    }

    private boolean isKnownMinerName(String name) {
        String lower = name.toLowerCase();
        for (String m : KNOWN_MINER_NAMES) {
            if (lower.contains(m)) return true;
        }
        return false;
    }

    private String readProcessName(File pidDir) {
        try {
            File comm = new File(pidDir, "comm");
            if (!comm.canRead()) return null;
            try (BufferedReader r = new BufferedReader(new FileReader(comm))) {
                return r.readLine();
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private long readVmRss(File pidDir) {
        try {
            File status = new File(pidDir, "status");
            if (!status.canRead()) return 0;
            try (BufferedReader r = new BufferedReader(new FileReader(status))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.startsWith("VmRSS:")) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 2) {
                            long kb = Long.parseLong(parts[1]);
                            return kb * 1024;
                        }
                    }
                }
            }
        } catch (Throwable t) {
        }
        return 0;
    }

    private long readProcessCpuTicks(File pidDir) {
        try {
            File stat = new File(pidDir, "stat");
            if (!stat.canRead()) return -1;
            try (BufferedReader r = new BufferedReader(new FileReader(stat))) {
                String line = r.readLine();
                if (line == null) return -1;
                // /proc/pid/stat fields: pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
                String[] parts = line.split("\\s+");
                if (parts.length < 15) return -1;
                long utime = Long.parseLong(parts[13]);
                long stime = Long.parseLong(parts[14]);
                return utime + stime;
            }
        } catch (Throwable t) {
            return -1;
        }
    }

    private long readTotalCpuTicks() {
        try {
            try (BufferedReader r = new BufferedReader(new FileReader("/proc/stat"))) {
                String line = r.readLine();
                if (line == null || !line.startsWith("cpu ")) return -1;
                String[] parts = line.trim().split("\\s+");
                long total = 0;
                for (int i = 1; i < parts.length; i++) {
                    total += Long.parseLong(parts[i]);
                }
                return total;
            }
        } catch (Throwable t) {
            return -1;
        }
    }

    private String resolvePackageName(int pid, String processName) {
        try {
            android.app.ActivityManager am = (android.app.ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) return null;
            for (android.app.ActivityManager.RunningAppProcessInfo info : am.getRunningAppProcesses()) {
                if (info.pid == pid && info.processName != null) {
                    return info.processName;
                }
            }
        } catch (Throwable t) {
        }
        // Fallback: check if processName looks like a package name
        if (processName != null && processName.contains(".")) {
            try {
                context.getPackageManager().getPackageInfo(processName, 0);
                return processName;
            } catch (PackageManager.NameNotFoundException e) {
            }
        }
        return null;
    }
}
