package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * User-maintained list of detection/signature NAMES (e.g. "PUA.SomeAdware",
 * "YARA-X.auto_2b891fca...", "ML") to suppress engine-
 * wide — not just for one app (that's {@link UserDecisions#allowThreat}), but
 * for every future scan hit carrying that exact signature name, on any app.
 * Editable from Settings (type a name directly) as well as from the "ignore
 * this signature" action on a completed scan's threat dialog.
 */
public final class IgnoredSignatures {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "ignored_signatures";

    private IgnoredSignatures() {}

    private static SharedPreferences p(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static boolean isIgnored(Context c, String signatureName) {
        if (signatureName == null || signatureName.isEmpty()) return false;
        return p(c).getStringSet(KEY, new HashSet<>()).contains(signatureName.toLowerCase(Locale.US));
    }

    public static synchronized void add(Context c, String signatureName) {
        if (signatureName == null) return;
        String norm = signatureName.trim().toLowerCase(Locale.US);
        if (norm.isEmpty()) return;
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(KEY, new HashSet<>()));
        s.add(norm);
        pr.edit().putStringSet(KEY, s).apply();
    }

    public static synchronized void remove(Context c, String signatureName) {
        if (signatureName == null) return;
        String norm = signatureName.trim().toLowerCase(Locale.US);
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(KEY, new HashSet<>()));
        if (s.remove(norm)) pr.edit().putStringSet(KEY, s).apply();
    }

    /** Sorted snapshot for display in Settings. */
    public static java.util.List<String> getAll(Context c) {
        return new java.util.ArrayList<>(new TreeSet<>(p(c).getStringSet(KEY, new HashSet<>())));
    }
}
