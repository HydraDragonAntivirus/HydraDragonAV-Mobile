package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import com.google.common.base.Charsets;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * URL/domain threat lookup against the bundled Guava bloom filters.
 *
 * <p>Only {@code http://} and {@code https://} strings are considered, and every
 * URL is normalised to the {@code http://} form before lookup because the bloom
 * filters were built from {@code http://} strings. Used both for static APK
 * scanning (URLs embedded in DEX/resources) and live website scanning
 * (browser-bar text read passively via accessibility — no MITM/TLS interception).
 */
public final class UrlThreatScanner {

    private static final String TAG = "UrlThreatScanner";

    /** Bloom asset -> category label. */
    private static final String[][] BLOOMS = {
            {"malwareurl.bloom",     "MALWARE_URL"},
            {"phishingurl.bloom",    "PHISHING_URL"},
            {"phishing.bloom",       "PHISHING"},
            {"malicious.bloom",      "MALICIOUS"},
            {"malicious_mail.bloom", "MAIL"},
            {"abuse.bloom",          "ABUSE"},
            {"spam.bloom",           "SPAM"},
            {"mining.bloom",         "MINING"},
    };

    /** Matches http:// and https:// URLs in arbitrary text. */
    private static final Pattern URL_RE =
            Pattern.compile("https?://[^\\s\"'<>\\\\)\\]}]+", Pattern.CASE_INSENSITIVE);

    /**
     * steamcommunity.com phishing typosquats — plain https form only. The REAL
     * steamcommunity.com (and its subdomains) is whitelisted before this runs.
     */
    private static final Pattern STEAM_FAKE = Pattern.compile(
            "^https://s[cftz]y?[ace][aemnu][a-z]{1,4}o[mn][a-z]{4,8}[iy][a-z]?\\.com/$");

    /** Per-entry scan cap when reading APK entries (DEX can be large). */
    private static final int MAX_ENTRY_BYTES = 16 * 1024 * 1024;

    private static volatile UrlThreatScanner instance;

    private final Map<String, BloomFilter<CharSequence>> filters = new LinkedHashMap<>();
    private final java.util.Set<String> publicSuffixes = new java.util.HashSet<>();

    private UrlThreatScanner(Context context) {
        for (String[] b : BLOOMS) {
            BloomFilter<CharSequence> f = load(context, b[0]);
            if (f != null) {
                filters.put(b[1], f);
                Log.i(TAG, "loaded " + b[0] + " (" + b[1] + ")");
            }
        }
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                context.getAssets().open("public_suffixes.txt"), java.nio.charset.StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim().toLowerCase(Locale.US);
                if (!line.isEmpty() && !line.startsWith("//")) publicSuffixes.add(line);
            }
        } catch (Exception e) { Log.w(TAG, "public_suffixes.txt missing"); }
    }

    /** Registrable (main) domain via the public suffix list. If a suffix isn't
     *  found, falls back to the last two labels — a 3-label host whose last two
     *  labels aren't a listed suffix is NOT treated as a deeper sub-domain.
     *  mc.yandex.ru -> yandex.ru; google.com.tk (com.tk not a suffix) -> com.tk. */
    String getMainDomain(String host) {
        if (host == null || host.isEmpty()) return host == null ? "" : host;
        String[] p = host.split("\\.");
        for (int i = 0; i < p.length; i++) {
            StringBuilder suf = new StringBuilder();
            for (int j = i; j < p.length; j++) { if (j > i) suf.append('.'); suf.append(p[j]); }
            if (publicSuffixes.contains(suf.toString())) {
                if (i == 0) return host;
                StringBuilder m = new StringBuilder();
                for (int j = i - 1; j < p.length; j++) { if (j > i - 1) m.append('.'); m.append(p[j]); }
                return m.toString();
            }
        }
        return p.length >= 2 ? p[p.length - 2] + "." + p[p.length - 1] : host;
    }

    public static UrlThreatScanner get(Context context) {
        UrlThreatScanner local = instance;
        if (local == null) {
            synchronized (UrlThreatScanner.class) {
                local = instance;
                if (local == null) {
                    local = new UrlThreatScanner(context.getApplicationContext());
                    instance = local;
                }
            }
        }
        return local;
    }

    private static BloomFilter<CharSequence> load(Context context, String asset) {
        try (InputStream is = context.getAssets().open(asset)) {
            return BloomFilter.readFrom(is, Funnels.stringFunnel(Charsets.UTF_8));
        } catch (Exception e) {
            Log.w(TAG, "missing/invalid bloom: " + asset);
            return null;
        }
    }

    /**
     * Normalise a URL for bloom lookup: trim, lowercase, and strip ONLY the
     * leading scheme ({@code http://} / {@code https://}). The blooms store
     * scheme-less {@code host[:port]/path} entries, so we keep the rest as-is.
     * Returns null if the string isn't an http(s):// URL.
     */
    public static String normalize(String url) {
        if (url == null) return null;
        String u = url.trim().toLowerCase(Locale.US);
        if (u.startsWith("https://")) {
            u = u.substring("https://".length());
        } else if (u.startsWith("http://")) {
            u = u.substring("http://".length());
        } else {
            return null;
        }
        return u.isEmpty() ? null : u;
    }

    /** Extract every http(s):// URL from arbitrary text. */
    public static List<String> extractUrls(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.isEmpty()) return out;
        Matcher m = URL_RE.matcher(text);
        while (m.find()) {
            out.add(m.group());
        }
        return out;
    }

    /**
     * Look a single URL up across all bloom filters.
     *
     * <p>Checks two kinds of candidate against every bloom:
     * <ul>
     *   <li>the full {@code http://} URL (with/without trailing slash) — matches
     *       the URL blooms (malwareurl/phishingurl), built from http:// strings;
     *   <li>the host as plain text, reduced from the full subdomain down to the
     *       registrable domain (e.g. {@code a.b.example.com} -> {@code b.example.com}
     *       -> {@code example.com}) — matches the domain blooms (plain text).
     * </ul>
     *
     * @return the matching category (e.g. "PHISHING_URL"), or null if clean.
     */
    public String scanUrl(String url) {
        if (isSteamFake(url)) return "STEAM_PHISHING";
        if (url == null) return null;
        String lower = url.trim().toLowerCase(Locale.US);
        boolean http = lower.startsWith("http://");
        boolean https = lower.startsWith("https://");
        if (!http && !https) return null;

        String norm = normalize(url);   // scheme-less host[/path]
        if (norm == null) return null;
        int slash = norm.indexOf('/');
        boolean hasPath = slash >= 0 && slash < norm.length() - 1;
        String host = (slash >= 0) ? norm.substring(0, slash) : norm;
        int colon = host.indexOf(':');
        if (colon >= 0) host = host.substring(0, colon);

        // http + path => URL scan (URL blooms, full URL). Else => domain scan:
        // reduce the host to its main (registrable) domain via the public suffix
        // list and check ONLY that against the domain blooms. One check per bloom
        // (not host+main) and sub-domains fold to their base (mc.yandex.ru ->
        // yandex.ru), avoiding the false positives that flooded every domain.
        boolean urlScan = http && hasPath;
        String main = urlScan ? null : getMainDomain(host);
        for (Map.Entry<String, BloomFilter<CharSequence>> e : filters.entrySet()) {
            boolean urlBloom = e.getKey().endsWith("_URL");
            BloomFilter<CharSequence> f = e.getValue();
            if (urlScan) {
                if (urlBloom && f.mightContain(norm)) return e.getKey();
            } else if (!urlBloom && f.mightContain(main)) {
                return e.getKey();
            }
        }
        return null;
    }

    /**
     * True if {@code url} is a steamcommunity.com phishing typosquat (plain,
     * base64 or reversed form). The genuine steamcommunity.com and its subdomains
     * are whitelisted first, so the real site is never flagged.
     */
    public static boolean isSteamFake(String url) {
        if (url == null) return false;
        String u = url.trim();
        String host = rawHost(u);
        if (host != null
                && (host.equals("steamcommunity.com") || host.endsWith(".steamcommunity.com"))) {
            return false;   // genuine site — whitelisted
        }
        return STEAM_FAKE.matcher(u).find();
    }

    /** Lowercased host of an http(s):// URL (no scheme/port/path/userinfo), or null. */
    private static String rawHost(String url) {
        String u = url.toLowerCase(Locale.US);
        int i = u.indexOf("://");
        if (i < 0) return null;
        String rest = u.substring(i + 3);
        int slash = rest.indexOf('/');
        String host = slash >= 0 ? rest.substring(0, slash) : rest;
        int at = host.indexOf('@');
        if (at >= 0) host = host.substring(at + 1);
        int colon = host.indexOf(':');
        if (colon >= 0) host = host.substring(0, colon);
        return host.isEmpty() ? null : host;
    }

    /**
     * Derive the plain-text domain candidates from a scheme-less
     * {@code host[:port]/path} string for domain-bloom matching:
     * <ol>
     *   <li>the exact host (catches sub-domain blacklist entries), and</li>
     *   <li>its registrable domain — the last two labels (catches the case
     *       where the URL lives on a sub-domain but the base domain itself is
     *       blacklisted).</li>
     * </ol>
     * No intermediate cascade levels are emitted, so unrelated middle
     * sub-domains can never spuriously match.
     */
    static List<String> hostCandidates(String schemeless) {
        List<String> out = new ArrayList<>();
        String host = schemeless;
        int slash = host.indexOf('/');
        if (slash >= 0) host = host.substring(0, slash);
        int at = host.indexOf('@');                 // strip userinfo
        if (at >= 0) host = host.substring(at + 1);
        int colon = host.indexOf(':');              // strip port
        if (colon >= 0) host = host.substring(0, colon);
        if (host.isEmpty()) return out;

        // EXACT host only. The earlier registrable-domain reduction
        // (host + base domain) doubled the per-host bloom lookups, and with 8
        // filters each at ~1% fpp the independent false-positive probabilities
        // STACK (1 - 0.99^N), pushing the real per-host FP to ~10-15%. Checking
        // only the exact host roughly halves that.
        out.add(host);
        return out;
    }

    /**
     * Extract URLs embedded in an APK (DEX, resources, manifest, native libs)
     * and look them up. APK entries are zlib-compressed, so we must decompress
     * each entry before scanning — a raw byte grep of the .apk would miss them.
     *
     * @return map of malicious URL -> category (empty if none).
     */
    public Map<String, String> scanApk(String apkPath) {
        Map<String, String> hits = new LinkedHashMap<>();
        if (filters.isEmpty()) return hits;
        try (ZipFile zip = new ZipFile(apkPath)) {
            java.util.Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry entry = en.nextElement();
                if (entry.isDirectory() || entry.getSize() == 0) continue;
                if (entry.getSize() > MAX_ENTRY_BYTES) continue;
                try (InputStream is = zip.getInputStream(entry)) {
                    String text = readAsLatin1(is);
                    for (String url : extractUrls(text)) {
                        if (hits.containsKey(url)) continue;
                        String cat = scanUrl(url);
                        if (cat != null) hits.put(url, cat);
                    }
                } catch (Exception ignore) {
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "scanApk failed: " + e.getMessage());
        }
        return hits;
    }

    /** Read a stream as Latin-1 so every byte maps 1:1 to a char (URLs are ASCII). */
    private static String readAsLatin1(InputStream is) throws Exception {
        byte[] buf = new byte[64 * 1024];
        StringBuilder sb = new StringBuilder();
        int n;
        int total = 0;
        while ((n = is.read(buf)) != -1) {
            sb.append(new String(buf, 0, n, Charsets.ISO_8859_1));
            total += n;
            if (total > MAX_ENTRY_BYTES) break;
        }
        return sb.toString();
    }
}
