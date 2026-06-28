package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/**
 * Persistent store of packages flagged by runtime BEHAVIOUR (e.g. event/overlay
 * spam) rather than by static signatures. The dynamic-analysis service writes
 * here; {@link ScanEngine} reads it so a behaviourally-flagged app is reported
 * as malware on the next scan.
 */
public final class BehaviorFlags {

    private static final String PREFS = "hydra_behavior_flags";
    private static final String KEY = "flagged";
    /** Delimiter between "pkg" and "reason" — control char, never in a pkg name. */
    private static final String SEP = String.valueOf((char) 1);

    private BehaviorFlags() {}

    private static SharedPreferences prefs(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** Flag a package with a reason (e.g. "Spam: repeated overlay x40"). */
    public static synchronized void flag(Context c, String pkg, String reason) {
        if (pkg == null || pkg.isEmpty()) return;
        SharedPreferences p = prefs(c);
        Set<String> set = new HashSet<>(p.getStringSet(KEY, new HashSet<>()));
        set.removeIf(e -> entryPkg(e).equals(pkg));
        set.add(pkg + SEP + (reason == null ? "Malicious behaviour" : reason));
        p.edit().putStringSet(KEY, set).apply();
    }

    /** @return the stored reason if this package was behaviour-flagged, else null. */
    public static String reasonFor(Context c, String pkg) {
        if (pkg == null) return null;
        for (String e : prefs(c).getStringSet(KEY, new HashSet<>())) {
            if (entryPkg(e).equals(pkg)) {
                int i = e.indexOf(SEP);
                return i >= 0 ? e.substring(i + SEP.length()) : "Malicious behaviour";
            }
        }
        return null;
    }

    public static boolean isFlagged(Context c, String pkg) {
        return reasonFor(c, pkg) != null;
    }

    public static synchronized void clear(Context c, String pkg) {
        SharedPreferences p = prefs(c);
        Set<String> set = new HashSet<>(p.getStringSet(KEY, new HashSet<>()));
        set.removeIf(e -> entryPkg(e).equals(pkg));
        p.edit().putStringSet(KEY, set).apply();
    }

    private static String entryPkg(String entry) {
        int i = entry.indexOf(SEP);
        return i >= 0 ? entry.substring(0, i) : entry;
    }
}
