package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/** PIN-based App Lock: protects HydraDragon's own UI from being opened by
 *  someone other than the owner (shoulder-surfing, a borrowed/stolen phone,
 *  a kid picking up the device, etc.) — see AppLockActivity for the actual
 *  lock screen + secure pinpad. PIN is stored as a salted SHA-256 hash, never
 *  in plaintext. Includes an exponential wrong-attempt backoff so the PIN
 *  can't be brute-forced by repeated guessing. */
public final class AppLockManager {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_ENABLED = "app_lock_enabled";
    private static final String KEY_HASH = "app_lock_pin_hash";
    private static final String KEY_SALT = "app_lock_pin_salt";
    private static final String KEY_FAIL_COUNT = "app_lock_fail_count";
    private static final String KEY_LOCKOUT_UNTIL = "app_lock_lockout_until";

    /** True once the correct PIN has been entered for the CURRENT process
     *  lifetime — reset to false whenever the process restarts (a fresh
     *  process is exactly when re-authentication should be required). Not
     *  persisted on purpose. */
    private static volatile boolean unlockedThisSession = false;

    private AppLockManager() {}

    private static SharedPreferences p(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static boolean isEnabled(Context c) {
        return p(c).getBoolean(KEY_ENABLED, false);
    }

    public static boolean hasPin(Context c) {
        return p(c).contains(KEY_HASH);
    }

    /** Whether the lock screen needs to be shown right now. */
    public static boolean isLockRequired(Context c) {
        return isEnabled(c) && hasPin(c) && !unlockedThisSession;
    }

    public static void markUnlocked() {
        unlockedThisSession = true;
    }

    /** Called when App Lock is turned off, or the app process is known to be
     *  going to background for good (defensive — the static flag already
     *  resets on process death on its own). */
    public static void markLocked() {
        unlockedThisSession = false;
    }

    public static void setEnabled(Context c, boolean on) {
        p(c).edit().putBoolean(KEY_ENABLED, on).apply();
        if (!on) markLocked();
    }

    public static void setPin(Context c, String pin) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String saltHex = toHex(salt);
        String hash = hashPin(pin, saltHex);
        p(c).edit()
            .putString(KEY_SALT, saltHex)
            .putString(KEY_HASH, hash)
            .putInt(KEY_FAIL_COUNT, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0)
            .apply();
    }

    public static boolean verifyPin(Context c, String pin) {
        SharedPreferences pr = p(c);
        String salt = pr.getString(KEY_SALT, null);
        String storedHash = pr.getString(KEY_HASH, null);
        if (salt == null || storedHash == null) return false;
        boolean ok = storedHash.equals(hashPin(pin, salt));
        if (ok) {
            pr.edit().putInt(KEY_FAIL_COUNT, 0).putLong(KEY_LOCKOUT_UNTIL, 0).apply();
            unlockedThisSession = true;
        } else {
            recordFailure(c);
        }
        return ok;
    }

    /** Seconds remaining in the current lockout, or 0 if none. Exponential:
     *  3rd+ wrong attempt starts a backoff that doubles each additional miss
     *  (30s, 60s, 120s, ... capped at 30 minutes) — slows brute-forcing to a
     *  crawl without permanently locking the legitimate owner out. */
    public static long lockoutSecondsRemaining(Context c) {
        long until = p(c).getLong(KEY_LOCKOUT_UNTIL, 0);
        long remaining = (until - System.currentTimeMillis()) / 1000;
        return Math.max(0, remaining);
    }

    private static void recordFailure(Context c) {
        SharedPreferences pr = p(c);
        int fails = pr.getInt(KEY_FAIL_COUNT, 0) + 1;
        SharedPreferences.Editor e = pr.edit().putInt(KEY_FAIL_COUNT, fails);
        if (fails >= 3) {
            long backoffSec = Math.min(30L << Math.min(fails - 3, 6), 30 * 60L); // 30s .. 30min
            e.putLong(KEY_LOCKOUT_UNTIL, System.currentTimeMillis() + backoffSec * 1000);
        }
        e.apply();
    }

    private static String hashPin(String pin, String saltHex) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(hexToBytes(saltHex));
            byte[] digest = md.digest(pin.getBytes("UTF-8"));
            return toHex(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format(Locale.US, "%02x", x));
        return sb.toString();
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }
}
