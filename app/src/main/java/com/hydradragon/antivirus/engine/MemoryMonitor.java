package com.hydradragon.antivirus.engine;

import android.util.Log;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Reads system memory pressure from {@code /proc/meminfo} to detect conditions
 * consistent with mass in-place file encryption.
 *
 * <p>Ransomware typically reads each target file into memory, encrypts it
 * there, and writes the encrypted blob back — a pattern that drives
 * {@code MemAvailable} down measurably compared to the device's idle
 * baseline.  Combining memory pressure with the existing rename-burst and
 * canary-file heuristics makes each sensor a check on the other: a rename
 * burst without memory pressure is more likely a legitimate file manager
 * operation, while pressure without file changes could be a game or camera.
 *
 * <p>All values are read from {@code /proc/meminfo} (available to every app,
 * no special permission needed) and cached for {@link #CACHE_MS} to avoid
 * thrashing the procfs on back-to-back queries.
 */
public final class MemoryMonitor {

    private static final String TAG = "HydraDragon-Memory";
    private static final String MEMINFO_PATH = "/proc/meminfo";

    /** How long a meminfo snapshot stays fresh (milliseconds). */
    private static final long CACHE_MS = 5_000L;

    /** Minimum available memory (as fraction of total) below which the device
     *  is considered under "high" memory pressure.  When available drops under
     *  this threshold AND file operations are detected, ransomware becomes
     *  significantly more likely. */
    private static final double HIGH_PRESSURE_THRESHOLD = 0.15;

    /** Moderate pressure threshold — above HIGH but below this, memory alone
     *  merely raises suspicion rather than confirming it. */
    private static final double MODERATE_PRESSURE_THRESHOLD = 0.30;

    // ── Cached snapshot ────────────────────────────────────────────────
    private static long lastReadMs = 0L;
    private static long cachedTotalKb = 0L;
    private static long cachedAvailableKb = 0L;
    private static Integer cachedPressureScore = null; // 0–100

    private MemoryMonitor() {}

    // ── Public API ─────────────────────────────────────────────────────

    /** Returns a memory-pressure score between 0 (plenty of RAM) and 100
     *  (critically low, device is thrashing).  0 means {@code /proc/meminfo}
     *  could not be read. */
    public static synchronized int pressureScore() {
        refreshIfStale();
        return cachedPressureScore != null ? cachedPressureScore : 0;
    }

    /** Returns {@code true} when the device's available memory has dropped
     *  below {@link #HIGH_PRESSURE_THRESHOLD} of total — the range where
     *  mass file encryption by a foreground process becomes the leading
     *  hypothesis for ongoing file activity. */
    public static synchronized boolean isUnderHighPressure() {
        refreshIfStale();
        return cachedAvailableKb > 0 && cachedTotalKb > 0
            && (double) cachedAvailableKb / cachedTotalKb < HIGH_PRESSURE_THRESHOLD;
    }

    /** Returns {@code true} when available memory is below
     *  {@link #MODERATE_PRESSURE_THRESHOLD} — used as a milder co-factor. */
    public static synchronized boolean isUnderModeratePressure() {
        refreshIfStale();
        return cachedAvailableKb > 0 && cachedTotalKb > 0
            && (double) cachedAvailableKb / cachedTotalKb < MODERATE_PRESSURE_THRESHOLD;
    }

    /** Human-readable summary for logging / HIPS metadata. */
    public static synchronized String summary() {
        refreshIfStale();
        if (cachedTotalKb <= 0) return "meminfo=unavailable";
        double pct = 100.0 * cachedAvailableKb / cachedTotalKb;
        return String.format("mem_avail=%.0f%% total=%dMB avail=%dMB score=%d",
            pct, cachedTotalKb / 1024, cachedAvailableKb / 1024,
            cachedPressureScore != null ? cachedPressureScore : 0);
    }

    /** Force-refresh the cache on the next call. */
    public static synchronized void invalidate() {
        lastReadMs = 0L;
    }

    // ── Internal ───────────────────────────────────────────────────────

    private static void refreshIfStale() {
        long now = System.currentTimeMillis();
        if (now - lastReadMs < CACHE_MS && cachedPressureScore != null) return;
        lastReadMs = now;

        Map<String, Long> meminfo = readMeminfo();
        long total = meminfo.getOrDefault("MemTotal", 0L);
        long free = meminfo.getOrDefault("MemFree", 0L);
        long cached = meminfo.getOrDefault("Cached", 0L);
        long buffers = meminfo.getOrDefault("Buffers", 0L);
        long sReclaimable = meminfo.getOrDefault("SReclaimable", 0L);

        // MemAvailable is the most realistic "how much can apps use" metric.
        // Many kernels provide it directly; when absent, approximate it.
        long available = meminfo.getOrDefault("MemAvailable", 0L);
        if (available == 0L) {
            available = free + cached + buffers + sReclaimable;
        }

        cachedTotalKb = total;
        cachedAvailableKb = available;

        if (total <= 0) {
            cachedPressureScore = null;
            return;
        }

        double ratio = (double) available / total; // 0.0 – 1.0
        // Invert: low available → high pressure.  Clamp to 0–100.
        int score = (int) Math.round((1.0 - Math.min(ratio, 1.0)) * 100.0);
        cachedPressureScore = Math.max(0, Math.min(100, score));
    }

    /** Parse {@code /proc/meminfo} lines of the form {@code Key:    value kB}. */
    private static Map<String, Long> readMeminfo() {
        Map<String, Long> result = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new FileReader(MEMINFO_PATH))) {
            String line;
            while ((line = r.readLine()) != null) {
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String key = line.substring(0, colon).trim();
                String rest = line.substring(colon + 1).trim();
                // Value may have trailing " kB" — strip everything after the
                // first space to get the numeric part.
                int space = rest.indexOf(' ');
                String numStr = space > 0 ? rest.substring(0, space) : rest;
                try {
                    result.put(key, Long.parseLong(numStr));
                } catch (NumberFormatException ignored) { }
            }
        } catch (IOException e) {
            Log.w(TAG, "cannot read /proc/meminfo", e);
        } catch (Throwable t) {
            Log.w(TAG, "unexpected error reading meminfo", t);
        }
        return result;
    }
}
