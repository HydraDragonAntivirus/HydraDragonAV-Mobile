package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Direct CIDR blacklist matcher (no bloom) for resolved/contacted IPs, loaded
 * from the plain {@code CIDRBlackListIPv4.txt} / {@code CIDRBlackListIPv6.txt}
 * asset lists (sourced from https://github.com/T145/black-mirror).
 *
 * <p>Matching is exact, not probabilistic: each CIDR is grouped by prefix length
 * and its masked network stored in a hash set, so testing an address is a few
 * hash-set lookups (one per distinct prefix length present), not a scan of all
 * ~11k entries.
 */
public final class CidrBlacklist {

    private static final String TAG = "CidrBlacklist";

    // prefixLen -> set of masked network ints (IPv4).
    private final Map<Integer, Set<Integer>> v4 = new HashMap<>();
    // prefixLen -> set of masked network keys (IPv6, 16-byte hex of masked addr).
    private final Map<Integer, Set<String>> v6 = new HashMap<>();

    private static volatile CidrBlacklist instance;

    public static CidrBlacklist get(Context ctx) {
        CidrBlacklist local = instance;
        if (local == null) {
            synchronized (CidrBlacklist.class) {
                local = instance;
                if (local == null) {
                    local = new CidrBlacklist(ctx.getApplicationContext());
                    instance = local;
                }
            }
        }
        return local;
    }

    private CidrBlacklist(Context ctx) {
        load(ctx, "CIDRBlackListIPv4.txt");
        load(ctx, "CIDRBlackListIPv6.txt");
        Log.i(TAG, "loaded v4 lens=" + v4.size() + " v6 lens=" + v6.size());
    }

    private void load(Context ctx, String asset) {
        try (InputStream is = ctx.getAssets().open(asset);
             BufferedReader r = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                int slash = line.indexOf('/');
                if (slash < 0) continue;
                String addr = line.substring(0, slash);
                int prefix;
                try { prefix = Integer.parseInt(line.substring(slash + 1)); }
                catch (NumberFormatException e) { continue; }
                InetAddress ip;
                try { ip = InetAddress.getByName(addr); }
                catch (Exception e) { continue; }
                if (ip instanceof Inet4Address) {
                    if (prefix < 0 || prefix > 32) continue;
                    int net = ipv4ToInt(ip.getAddress()) & maskV4(prefix);
                    v4.computeIfAbsent(prefix, k -> new HashSet<>()).add(net);
                } else {
                    if (prefix < 0 || prefix > 128) continue;
                    String key = maskedKeyV6(ip.getAddress(), prefix);
                    v6.computeIfAbsent(prefix, k -> new HashSet<>()).add(key);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "missing/invalid " + asset + ": " + e.getMessage());
        }
    }

    /** True if {@code ip} falls inside any blacklisted CIDR. */
    public boolean contains(InetAddress ip) {
        if (ip == null) return false;
        byte[] b = ip.getAddress();
        if (b.length == 4) {
            int x = ipv4ToInt(b);
            for (Map.Entry<Integer, Set<Integer>> e : v4.entrySet()) {
                if (e.getValue().contains(x & maskV4(e.getKey()))) return true;
            }
            return false;
        } else if (b.length == 16) {
            for (Map.Entry<Integer, Set<String>> e : v6.entrySet()) {
                if (e.getValue().contains(maskedKeyV6(b, e.getKey()))) return true;
            }
            return false;
        }
        return false;
    }

    /** Convenience: parse a textual IP and test it. */
    public boolean contains(String ip) {
        try { return contains(InetAddress.getByName(ip)); }
        catch (Exception e) { return false; }
    }

    private static int ipv4ToInt(byte[] b) {
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }

    private static int maskV4(int prefix) {
        return prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
    }

    /** Hex of the address with all bits beyond {@code prefix} zeroed. */
    private static String maskedKeyV6(byte[] addr, int prefix) {
        byte[] m = new byte[16];
        for (int i = 0; i < 16; i++) {
            int bitStart = i * 8;
            if (bitStart + 8 <= prefix) {
                m[i] = addr[i];
            } else if (bitStart >= prefix) {
                m[i] = 0;
            } else {
                int keep = prefix - bitStart;                 // 1..7 high bits kept
                int mask = (0xFF << (8 - keep)) & 0xFF;
                m[i] = (byte) (addr[i] & mask);
            }
        }
        StringBuilder sb = new StringBuilder(33);
        sb.append(prefix).append(':');
        for (byte x : m) sb.append(Character.forDigit((x >> 4) & 0xF, 16))
                           .append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }
}
