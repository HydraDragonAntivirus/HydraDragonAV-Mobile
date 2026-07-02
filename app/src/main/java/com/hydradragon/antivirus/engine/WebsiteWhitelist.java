package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.SharedPreferences;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * User-maintained allowlist for Web Shield (DnsVpnService): a domain, bare IP,
 * or CIDR range the user has explicitly said to never block, even if it later
 * matches the malicious-domain/IP lists. Small, user-edited list — checked
 * linearly (no bloom filter needed, unlike the ~thousands-of-entries
 * CidrBlacklist/UrlThreatScanner data sets).
 */
public final class WebsiteWhitelist {
    private static final String PREFS = "hydra_prefs";
    private static final String KEY = "website_whitelist";

    private WebsiteWhitelist() {}

    private static SharedPreferences p(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static java.util.List<String> getAll(Context c) {
        return new java.util.ArrayList<>(new TreeSet<>(p(c).getStringSet(KEY, new HashSet<>())));
    }

    public static synchronized void add(Context c, String entry) {
        if (entry == null) return;
        String norm = entry.trim().toLowerCase(Locale.US);
        if (norm.isEmpty()) return;
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(KEY, new HashSet<>()));
        s.add(norm);
        pr.edit().putStringSet(KEY, s).apply();
    }

    public static synchronized void remove(Context c, String entry) {
        if (entry == null) return;
        String norm = entry.trim().toLowerCase(Locale.US);
        SharedPreferences pr = p(c);
        Set<String> s = new HashSet<>(pr.getStringSet(KEY, new HashSet<>()));
        if (s.remove(norm)) pr.edit().putStringSet(KEY, s).apply();
    }

    /** True if {@code host} (a DNS query name, e.g. "www.example.com") is
     *  covered by a whitelisted domain — exact match or a subdomain of one
     *  (whitelisting "example.com" also covers "static.example.com"). */
    public static boolean isDomainWhitelisted(Context c, String host) {
        if (host == null || host.isEmpty()) return false;
        String h = host.toLowerCase(Locale.US);
        for (String entry : p(c).getStringSet(KEY, new HashSet<>())) {
            if (looksLikeIpOrCidr(entry)) continue;
            if (h.equals(entry) || h.endsWith("." + entry)) return true;
        }
        return false;
    }

    /** True if {@code ip} is covered by a whitelisted bare IP or CIDR range. */
    public static boolean isIpWhitelisted(Context c, InetAddress ip) {
        if (ip == null) return false;
        for (String entry : p(c).getStringSet(KEY, new HashSet<>())) {
            if (!looksLikeIpOrCidr(entry)) continue;
            try {
                int slash = entry.indexOf('/');
                if (slash < 0) {
                    if (InetAddress.getByName(entry).equals(ip)) return true;
                } else if (cidrContains(entry, slash, ip)) {
                    return true;
                }
            } catch (Exception ignore) { /* malformed entry — skip */ }
        }
        return false;
    }

    private static boolean looksLikeIpOrCidr(String entry) {
        // A domain label can't start with a digit-only octet pattern reliably,
        // but the simple/robust check here is: does it parse as an IP
        // (with an optional /prefix stripped first)?
        String addrPart = entry.contains("/") ? entry.substring(0, entry.indexOf('/')) : entry;
        return addrPart.matches("^[0-9.]+$") || addrPart.contains(":");
    }

    private static boolean cidrContains(String entry, int slash, InetAddress ip) throws Exception {
        String addrPart = entry.substring(0, slash);
        int prefix = Integer.parseInt(entry.substring(slash + 1));
        InetAddress net = InetAddress.getByName(addrPart);
        byte[] netBytes = net.getAddress();
        byte[] ipBytes = ip.getAddress();
        if (netBytes.length != ipBytes.length) return false; // v4 vs v6 mismatch
        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (netBytes[i] != ipBytes[i]) return false;
        }
        if (remBits > 0 && fullBytes < netBytes.length) {
            int mask = 0xFF << (8 - remBits) & 0xFF;
            if ((netBytes[fullBytes] & mask) != (ipBytes[fullBytes] & mask)) return false;
        }
        return true;
    }
}
