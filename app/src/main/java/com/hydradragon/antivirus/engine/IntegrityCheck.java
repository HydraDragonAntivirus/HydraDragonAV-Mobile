package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.security.MessageDigest;

/** Detects a repackaged/re-signed copy of this APK. `BuildConfig.EXPECTED_SIGNATURE_SHA256`
 *  is baked in by app/build.gradle from the SAME keystore that signs the build
 *  (see signingCertSha256 there), so it always matches an untouched build —
 *  it only diverges if someone decompiled/modified the code and re-signed the
 *  APK with a different key (unavoidable: Android refuses to install an
 *  unsigned APK, so a tampered copy is necessarily signed by someone else). */
public final class IntegrityCheck {

    private IntegrityCheck() {}

    /** @return true iff the running APK's actual signing certificate does NOT
     *  match the one this build was compiled/signed with — i.e. tampered.
     *  Fails CLOSED to "not tampered" on any read error or when the build-time
     *  hash itself was unavailable, so this only ever flags a KNOWN mismatch,
     *  never a build-pipeline hiccup. */
    public static boolean isTampered(Context context) {
        String expected = com.hydradragon.antivirus.BuildConfig.EXPECTED_SIGNATURE_SHA256;
        if (expected == null || expected.isEmpty() || "UNAVAILABLE".equals(expected)) return false;
        try {
            PackageManager pm = context.getPackageManager();
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(context.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = info.signingInfo.hasMultipleSigners()
                    ? info.signingInfo.getApkContentsSigners()
                    : info.signingInfo.getSigningCertificateHistory();
            } else {
                PackageInfo info = pm.getPackageInfo(context.getPackageName(),
                    PackageManager.GET_SIGNATURES);
                sigs = info.signatures;
            }
            if (sigs == null || sigs.length == 0) return true;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) sb.append('0');
                sb.append(h);
            }
            return !expected.equalsIgnoreCase(sb.toString());
        } catch (Exception e) {
            return false;
        }
    }
}
