package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/**
 * Remembers the user's "no" answers so the app never nags twice:
 *
 *   - denied permissions / consents (e.g. VPN) -> don't auto-prompt again;
 *   - threats marked safe (package or URL)      -> never flag / pop up again;
 *   - dismissed redirects (threat id)           -> don't redirect again.
 *
 * Backed by SharedPreferences so decisions survive restarts.
 */
public final class UserDecisions {

    private static final String PREFS = "hydra_user_decisions";
    private static final String K_PERM = "denied_perms";
    private static final String K_SAFE = "allowed_threats";
    private static final String K_DISMISS = "dismissed_redirects";

    private UserDecisions() {}

    private static SharedPreferences p(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static boolean has(Context c, String key, String id) {
        return id != null && p(c).getStringSet(key, new HashSet<>()).contains(id);
    }

    private static synchronized void add(Context c, String key, String id) {
        if (id == null || id.isEmpty()) return;
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(key, new HashSet<>()));
        s.add(id);
        pr.edit().putStringSet(key, s).apply();
    }

    private static synchronized void remove(Context c, String key, String id) {
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(key, new HashSet<>()));
        if (s.remove(id)) pr.edit().putStringSet(key, s).apply();
    }

    // ── Permissions / consents ──────────────────────────────────────────────
    public static void denyPermission(Context c, String key) { add(c, K_PERM, key); }
    public static boolean isPermissionDenied(Context c, String key) { return has(c, K_PERM, key); }
    public static void clearPermissionDenial(Context c, String key) { remove(c, K_PERM, key); }

    // ── Threats marked safe (package or URL) ────────────────────────────────
    public static void allowThreat(Context c, String id) {
        add(c, K_SAFE, id);
        // An allowlisted item also clears any prior behaviour flag for it.
        BehaviorFlags.clear(c, id);
    }
    public static boolean isThreatAllowed(Context c, String id) { return has(c, K_SAFE, id); }
    public static void revokeThreatAllowance(Context c, String id) { remove(c, K_SAFE, id); }

    // ── Dismissed redirects ─────────────────────────────────────────────────
    public static void dismissRedirect(Context c, String id) { add(c, K_DISMISS, id); }
    public static boolean isRedirectDismissed(Context c, String id) { return has(c, K_DISMISS, id); }
}
