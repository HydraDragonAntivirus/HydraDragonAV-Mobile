package com.hydradragon.antivirus.engine;

import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Computes Shannon entropy of file content to detect encryption.
 *
 * <p>Encrypted data is indistinguishable from random — its per-byte Shannon
 * entropy approaches 8 (the theoretical maximum for 8-bit bytes).  By
 * contrast, plaintext documents, source code, and structured binary formats
 * (ELF, DEX) typically score between 4.0 and 6.5.  Compressed formats (ZIP,
 * JPEG, PNG, MP4) naturally score 7.5–7.9, so this check is only meaningful
 * when a file of a KNOWN low-entropy type (text, PDF, doc, APK, DEX, ELF)
 * is replaced by something with entropy above the threshold — precisely the
 * shape of in-place encryption.
 *
 * <p>Thresholds (byte-level Shannon entropy):
 * <ul>
 *   <li>{@code > 7.5} — almost certainly compressed or encrypted.</li>
 *   <li>{@code > 7.0} — suspicious; may be lightly compressed or obfuscated.</li>
 *   <li>{@code <= 7.0} — typical for most plaintext / structured binary.</li>
 * </ul>
 *
 * <p>Very small files ({@code < 48 bytes}) are skipped because their entropy
 * estimate is noisy and unreliable.
 */
public final class FileEntropy {

    private static final String TAG = "HydraDragon-Entropy";

    /** Minimum file size for a reliable entropy estimate (bytes). */
    private static final int MIN_FILE_SIZE = 48;

    /** Entropy above this threshold is treated as "encrypted / compressed"
     *  — strong evidence of in-place encryption when combined with a
     *  rename-suffix pattern and/or memory pressure. */
    private static final double ENCRYPTED_THRESHOLD = 7.5;

    private FileEntropy() {}

    /**
     * Returns the Shannon entropy (0.0 – 8.0) of the file's content,
     * or -1 if the file cannot be read or is too small.
     */
    public static double entropyOf(File file) {
        if (file == null || !file.exists() || !file.isFile()) return -1.0;
        long len = file.length();
        if (len < MIN_FILE_SIZE) return -1.0;

        // Read up to 64 KB for the estimate — enough for a stable Shannon
        // calculation on any file type, and avoids thrashing on huge files.
        int sampleSize = (int) Math.min(len, 64L * 1024L);
        byte[] buf = new byte[sampleSize];

        try (FileInputStream fis = new FileInputStream(file)) {
            int read = 0;
            while (read < sampleSize) {
                int n = fis.read(buf, read, sampleSize - read);
                if (n < 0) break;
                read += n;
            }
            if (read < MIN_FILE_SIZE) return -1.0;
            return shannonEntropy(buf, read);
        } catch (IOException e) {
            Log.w(TAG, "cannot read " + file, e);
            return -1.0;
        } catch (Throwable t) {
            Log.w(TAG, "unexpected error reading " + file, t);
            return -1.0;
        }
    }

    /**
     * Returns {@code true} when the file's entropy exceeds
     * {@link #ENCRYPTED_THRESHOLD}, indicating the content is almost
     * certainly compressed or encrypted.
     */
    public static boolean isEncrypted(File file) {
        double e = entropyOf(file);
        return e >= ENCRYPTED_THRESHOLD;
    }

    /**
     * Returns a human-readable label for the given entropy value.
     */
    public static String label(double entropy) {
        if (entropy < 0) return "unavailable";
        if (entropy >= ENCRYPTED_THRESHOLD) return "encrypted";
        if (entropy >= 7.0) return "suspicious";
        if (entropy >= 5.5) return "mixed";
        return "plaintext";
    }

    // ── Shannon entropy ───────────────────────────────────────────────

    /**
     * Computes byte-level Shannon entropy of the first {@code len} bytes
     * of {@code data}.  Returns a value between 0.0 (all bytes identical)
     * and 8.0 (perfectly uniform).
     */
    public static double shannonEntropy(byte[] data, int len) {
        if (data == null || len <= 0) return 0.0;

        int[] freq = new int[256];
        for (int i = 0; i < len; i++) {
            freq[data[i] & 0xff]++;
        }

        double entropy = 0.0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / len;
            entropy -= p * (Math.log(p) / Math.log(256)); // log base 256 → 0..8 range
        }
        return entropy;
    }
}
