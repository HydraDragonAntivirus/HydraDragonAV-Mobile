package com.hydradragon.antivirus.engine;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class FileReadEstimator {

    private static final String TAG = "HydraDragon-FileRead";

    private static final long MAX_FILE_AGE_MS = 10 * 60 * 1000;
    private static final double SIZE_TOLERANCE = 0.10;
    private static final int MIN_BYTES_FOR_ESTIMATE = 4096;
    private static final float CONFIDENCE_REPORT_THRESHOLD = 0.60f;
    private static final long COPY_CORRELATION_WINDOW_MS = 30_000;
    private static final int MAX_RECENT_READS = 256;

    private static final Map<String, FileEntry> knownFiles = new HashMap<>();
    private static final Map<Integer, ProcIoBaseline> procBaselines = new HashMap<>();

    private static final List<RecentRead> recentReads = new ArrayList<>();

    private FileReadEstimator() {}

    /** Recent read estimate (for FILE_COPY correlation). */
    public static final class RecentRead {
        public final String packageName;
        public final long sizeBytes;
        public final String filePath;
        public final float confidence;
        public final long timestamp;

        RecentRead(String packageName, long sizeBytes, String filePath, float confidence) {
            this.packageName = packageName;
            this.sizeBytes = sizeBytes;
            this.filePath = filePath;
            this.confidence = confidence;
            this.timestamp = System.currentTimeMillis();
        }
    }

    /** Returns recent reads by the given package within the correlation window. */
    public static synchronized java.util.List<RecentRead> getRecentReadsByPackage(String pkg) {
        if (pkg == null) return java.util.Collections.emptyList();
        long now = System.currentTimeMillis();
        java.util.List<RecentRead> result = new ArrayList<>();
        for (RecentRead r : recentReads) {
            if (pkg.equals(r.packageName) && now - r.timestamp <= COPY_CORRELATION_WINDOW_MS) {
                result.add(r);
            }
        }
        return result;
    }

    /** Returns the total number of recent reads stored. */
    public static synchronized int getRecentReadCount() {
        return recentReads.size();
    }

    public static synchronized void observeFile(android.content.Context ctx, String path, long sizeBytes) {
        if (ctx != null && !BehaviorDetectionSettings.isEnabled(ctx, BehaviorDetectionSettings.FILE_READ_ESTIMATOR)) {
            knownFiles.clear();
            procBaselines.clear();
            return;
        }
        if (path == null || sizeBytes <= 0) return;
        knownFiles.put(path, new FileEntry(path, sizeBytes, System.currentTimeMillis()));
        if (knownFiles.size() > 2048) {
            removeStale();
        }
    }

    public static synchronized void scan(android.content.Context ctx) {
        if (ctx != null && !BehaviorDetectionSettings.isEnabled(ctx, BehaviorDetectionSettings.FILE_READ_ESTIMATOR)) {
            knownFiles.clear();
            procBaselines.clear();
            return;
        }
        try {
            removeStale();

            File proc = new File("/proc");
            File[] entries = proc.listFiles((dir, name) -> name.matches("\\d+"));
            if (entries == null) return;

            for (File pidDir : entries) {
                int pid;
                try {
                    pid = Integer.parseInt(pidDir.getName());
                } catch (NumberFormatException e) {
                    continue;
                }
                try {
                    checkProcess(pid, pidDir);
                } catch (Throwable ignored) {
                }
            }

            procBaselines.keySet().removeIf(p -> !new File("/proc/" + p).exists());
        } catch (Throwable t) {
            Log.e(TAG, "scan failed", t);
        }
    }

    private static void checkProcess(int pid, File pidDir) {
        File ioFile = new File(pidDir, "io");
        if (!ioFile.canRead()) return;

        long readBytes = readProcIoField(ioFile, "read_bytes:");
        long rchar = readProcIoField(ioFile, "rchar:");
        if (readBytes < 0 || rchar < 0) return;

        ProcIoBaseline prev = procBaselines.get(pid);
        long now = System.currentTimeMillis();
        procBaselines.put(pid, new ProcIoBaseline(readBytes, rchar, now));

        if (prev == null) return;

        long deltaRead = readBytes - prev.readBytes;
        long deltaRchar = rchar - prev.rchar;
        if (deltaRead < MIN_BYTES_FOR_ESTIMATE) return;

        long dtWall = now - prev.timestamp;
        if (dtWall <= 0) return;

        long cachedBytes = deltaRchar - deltaRead;
        float cacheRatio = deltaRchar > 0 ? (float) cachedBytes / (float) deltaRchar : 0f;

        estimateFile(pid, deltaRead, cachedBytes, cacheRatio, dtWall);
    }

    private static void estimateFile(int pid, long deltaRead, long cachedBytes,
                                      float cacheRatio, long dtWallMs) {
        String pkg = resolvePackageName(pid);
        if (pkg == null) return;

        List<Candidate> candidates = new ArrayList<>();
        for (Map.Entry<String, FileEntry> entry : knownFiles.entrySet()) {
            FileEntry fe = entry.getValue();
            if (fe.sizeBytes <= 0) continue;

            long diff = Math.abs(fe.sizeBytes - deltaRead);
            double ratio = (double) diff / (double) fe.sizeBytes;
            if (ratio > SIZE_TOLERANCE) continue;

            float sizeScore = (float) Math.max(0.0, 1.0 - (ratio / SIZE_TOLERANCE));

            long age = System.currentTimeMillis() - fe.timestamp;
            float recencyScore = (float) Math.max(0.0, 1.0 - ((double) age / (double) MAX_FILE_AGE_MS));

            float cacheScore = 0f;
            if (cacheRatio > 0.5f && dtWallMs < 5000) {
                cacheScore = Math.min(1f, cacheRatio * 2f);
            }

            float memoryScore = 0f;
            if (HipsMonitor.packageHasMinerMemory(pkg, fe.sizeBytes / (1024 * 1024))) {
                memoryScore = 0.3f;
            }

            float confidence = (sizeScore * 0.50f) + (recencyScore * 0.30f)
                             + (cacheScore * 0.15f) + (memoryScore * 0.05f);

            if (confidence >= CONFIDENCE_REPORT_THRESHOLD) {
                candidates.add(new Candidate(fe.path, fe.sizeBytes, confidence, cacheRatio));
            }
        }

        if (candidates.isEmpty()) {
            candidates.add(new Candidate(
                String.format("unknown~%dB", deltaRead), deltaRead, 0.3f, cacheRatio));
        }

        candidates.sort((a, b) -> Float.compare(b.confidence, a.confidence));
        Candidate best = candidates.get(0);

        String flag = String.format("FILE_READ:pid=%d:size=%d:file=%s:conf=%.0f:cache=%.0f",
            pid, deltaRead, best.path, best.confidence * 100, cacheRatio * 100);
        HipsMonitor.addBehaviorFlag(pkg, flag);

        recentReads.add(new RecentRead(pkg, deltaRead, best.path, best.confidence));
        if (recentReads.size() > MAX_RECENT_READS) recentReads.remove(0);

        Log.d(TAG, "estimated read pid=" + pid + " pkg=" + pkg
            + " delta=" + deltaRead + "B file=" + best.path
            + " conf=" + String.format("%.0f%%", best.confidence * 100)
            + " cache=" + String.format("%.0f%%", cacheRatio * 100)
            + (candidates.size() > 1 ? " alt=" + candidates.get(1).path : ""));
    }

    private static long readProcIoField(File ioFile, String prefix) {
        try (BufferedReader r = new BufferedReader(new FileReader(ioFile))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith(prefix)) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 2) return Long.parseLong(parts[1]);
                }
            }
        } catch (Throwable t) {
        }
        return -1;
    }

    private static String resolvePackageName(int pid) {
        try {
            File cmdline = new File("/proc/" + pid + "/cmdline");
            if (!cmdline.canRead()) return null;
            try (BufferedReader r = new BufferedReader(new FileReader(cmdline))) {
                String line = r.readLine();
                if (line != null) {
                    String clean = line.replace('\0', ' ').trim();
                    if (!clean.isEmpty() && clean.contains(".")) {
                        return clean.split("\\s+")[0];
                    }
                }
            }
        } catch (Throwable t) {
        }
        return null;
    }

    private static void removeStale() {
        long cutoff = System.currentTimeMillis() - MAX_FILE_AGE_MS;
        knownFiles.values().removeIf(f -> f.timestamp < cutoff);
    }

    private static final class FileEntry {
        final String path;
        final long sizeBytes;
        final long timestamp;

        FileEntry(String path, long sizeBytes, long timestamp) {
            this.path = path;
            this.sizeBytes = sizeBytes;
            this.timestamp = timestamp;
        }
    }

    private static final class ProcIoBaseline {
        final long readBytes;
        final long rchar;
        final long timestamp;

        ProcIoBaseline(long readBytes, long rchar, long timestamp) {
            this.readBytes = readBytes;
            this.rchar = rchar;
            this.timestamp = timestamp;
        }
    }

    private static final class Candidate {
        final String path;
        final long sizeBytes;
        final float confidence;
        final float cacheRatio;

        Candidate(String path, long sizeBytes, float confidence, float cacheRatio) {
            this.path = path;
            this.sizeBytes = sizeBytes;
            this.confidence = confidence;
            this.cacheRatio = cacheRatio;
        }
    }
}
