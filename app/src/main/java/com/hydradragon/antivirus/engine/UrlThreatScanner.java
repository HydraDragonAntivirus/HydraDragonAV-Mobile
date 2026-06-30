package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import com.google.common.base.Charsets;

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
 * URL/domain threat lookup. The bloom membership now lives entirely on the
 * native (Rust/fastbloom) side — {@link NativeScanner#scanUrl} — so the domain
 * blooms and the public-suffix list are loaded into NATIVE memory, not the Java
 * heap. This class is a thin wrapper that keeps the Java-side helpers (URL
 * extraction from APK entries, the steamcommunity typosquat guard).
 */
public final class UrlThreatScanner {

    private static final String TAG = "UrlThreatScanner";

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

    private UrlThreatScanner() {}

    public static UrlThreatScanner get(Context context) {
        UrlThreatScanner local = instance;
        if (local == null) {
            synchronized (UrlThreatScanner.class) {
                local = instance;
                if (local == null) {
                    local = new UrlThreatScanner();
                    instance = local;
                }
            }
        }
        return local;
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
     * Look a single URL up. Returns the matching category (e.g. "PHISHING_URL")
     * or null if clean. The steamcommunity typosquat guard runs first (Java); the
     * actual bloom membership is the native fastbloom URL/domain scanner.
     */
    public String scanUrl(String url) {
        if (isSteamFake(url)) return "STEAM_PHISHING";
        return NativeScanner.scanUrl(url);
    }

    /**
     * True if {@code url} is a steamcommunity.com phishing typosquat. The genuine
     * steamcommunity.com and its subdomains are whitelisted first.
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
     * Extract URLs embedded in an APK (DEX, resources, manifest, native libs)
     * and look them up. APK entries are zlib-compressed, so we must decompress
     * each entry before scanning.
     *
     * @return map of malicious URL -> category (empty if none).
     */
    public Map<String, String> scanApk(String apkPath) {
        Map<String, String> hits = new LinkedHashMap<>();
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
