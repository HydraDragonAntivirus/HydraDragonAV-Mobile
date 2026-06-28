package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.util.Log;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * MITM / TLS-interception detector.
 *
 * <p>Bundles the legitimate Android system root CAs (pulled from
 * {@code platform/system/ca-certificates}) as a known-good baseline, then
 * compares them against the CAs the device currently trusts
 * ({@code AndroidCAStore}). A TLS man-in-the-middle proxy works by installing
 * its own root CA so it can re-sign traffic; therefore:
 * <ul>
 *   <li>any <b>user-installed</b> CA, or
 *   <li>any trusted root whose fingerprint is <b>not in the baseline</b>
 * </ul>
 * is a strong indicator that traffic can be intercepted/decrypted on this
 * device (corporate proxy, debugging proxy, or malware).
 *
 * <p>This does NOT decrypt anything — it inspects the trust store only.
 */
public final class MitmDetector {

    private static final String TAG = "MitmDetector";
    private static final String BASELINE_DIR = "cacerts";

    private static volatile MitmDetector instance;

    /** SHA-256 fingerprints of the legitimate Android system roots. */
    private final Set<String> baseline = new HashSet<>();

    public static final class Result {
        public final boolean mitmSuspected;
        /** Human-readable subject names of the suspicious CAs. */
        public final List<String> userInstalledCas = new ArrayList<>();
        public final List<String> unknownTrustedCas = new ArrayList<>();

        Result(boolean mitm) { this.mitmSuspected = mitm; }
    }

    private MitmDetector(Context context) {
        loadBaseline(context);
    }

    public static MitmDetector get(Context context) {
        MitmDetector local = instance;
        if (local == null) {
            synchronized (MitmDetector.class) {
                local = instance;
                if (local == null) {
                    local = new MitmDetector(context.getApplicationContext());
                    instance = local;
                }
            }
        }
        return local;
    }

    private void loadBaseline(Context context) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            String[] files = context.getAssets().list(BASELINE_DIR);
            if (files == null) return;
            for (String f : files) {
                try (InputStream is = context.getAssets().open(BASELINE_DIR + "/" + f)) {
                    X509Certificate c = (X509Certificate) cf.generateCertificate(is);
                    baseline.add(fingerprint(c));
                } catch (Exception ignore) {
                }
            }
            Log.i(TAG, "baseline roots loaded: " + baseline.size());
        } catch (Exception e) {
            Log.w(TAG, "baseline load failed", e);
        }
    }

    /**
     * Inspect the device trust store for MITM indicators.
     */
    public Result scan() {
        Result r = new Result(false);
        boolean mitm = false;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                if (!(cert instanceof X509Certificate)) continue;
                X509Certificate x = (X509Certificate) cert;
                String subject = x.getSubjectDN().getName();

                // AndroidCAStore aliases are "system:<hash>" / "user:<hash>".
                boolean userInstalled = alias.startsWith("user:");
                boolean inBaseline = baseline.contains(fingerprint(x));

                if (userInstalled) {
                    // The real MITM signal: TLS-intercepting proxies (Burp,
                    // mitmproxy, corporate MDM, malware) install their CA into
                    // the USER store — the system store needs root.
                    r.userInstalledCas.add(subject);
                    mitm = true;
                } else if (!inBaseline && !baseline.isEmpty()) {
                    // A "system" root not in our stock snapshot — almost always a
                    // benign OEM/updated Google root, so report it as info only
                    // (does NOT raise the MITM verdict, to avoid false positives).
                    r.unknownTrustedCas.add(subject);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "trust store scan failed", e);
        }
        Result out = new Result(mitm);
        out.userInstalledCas.addAll(r.userInstalledCas);
        out.unknownTrustedCas.addAll(r.unknownTrustedCas);
        return out;
    }

    private static String fingerprint(X509Certificate c) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(c.getEncoded());
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
