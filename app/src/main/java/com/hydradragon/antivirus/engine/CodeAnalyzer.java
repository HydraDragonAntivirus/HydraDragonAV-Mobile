package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class CodeAnalyzer {
    private static final String TAG = "HydraDragon-CodeAnalyzer";

    private static final List<String> MALICIOUS_SIGNATURES = Arrays.asList(
        "Runtime.exec", "ProcessBuilder", "getRuntime().exec",
        "CryptoMiner", "XMRig",
        "SmsManager.sendTextMessage", "TelephonyManager.getDeviceId", "getSubscriberId",
        "su\n", "su -c", "/system/bin/su",
        "com.startapp", "com.airpush", "com.leadbolt",
        "Ljava/net/Socket", "HttpURLConnection",
        "java.lang.reflect", "DexClassLoader", "PathClassLoader", "dalvik.system.DexFile"
    );

    private static final int HIGH_RISK_SCORE = 35;
    private static final int CRITICAL_SCORE = 100;

    private final Context context;

    public CodeAnalyzer(Context context) {
        this.context = context;
    }

    public static class AnalysisResult {
        public final int riskScore;
        public final List<String> findings;
        public final boolean isMalicious;
        public final com.hydradragon.antivirus.model.ThreatResult.ThreatType threatType;

        public AnalysisResult(int riskScore, List<String> findings, com.hydradragon.antivirus.model.ThreatResult.ThreatType type) {
            this.riskScore = Math.min(riskScore, 100);
            this.findings = findings;
            this.isMalicious = riskScore >= 60;
            this.threatType = type;
        }
    }

    public AnalysisResult analyzeApk(String apkPath) {
        List<String> findings = new ArrayList<>();
        int totalRisk = 0;

        try {
            File apkFile = new File(apkPath);
            if (!apkFile.exists()) {
                findings.add("APK file not found!");
                return new AnalysisResult(0, findings, com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN);
            }

            ZipFile zipFile = new ZipFile(apkFile);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();

            StringBuilder bytecodeContent = new StringBuilder();
            int dexCount = 0;

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().startsWith("classes") && entry.getName().endsWith(".dex")) {
                    dexCount++;
                    java.io.InputStream is = zipFile.getInputStream(entry);
                    byte[] buffer = new byte[Math.min((int) entry.getSize(), 204800)];
                    int read = is.read(buffer);
                    is.close();
                    bytecodeContent.append(new String(buffer, 0, read, "ISO-8859-1"));
                }
            }
            zipFile.close();

            if (dexCount > 2) {
                findings.add("⚠ Multiple DEX (" + dexCount + " count) - Code obfuscation suspected!");
                totalRisk += 20;
            }

            String content = bytecodeContent.toString();
            for (String sig : MALICIOUS_SIGNATURES) {
                if (content.contains(sig)) {
                    if (sig.equals("DexClassLoader") || sig.equals("dalvik.system.DexFile")) {
                        findings.add("🔴 CRITICAL: Dynamic Code Loading detected! (" + sig + ")");
                        totalRisk += CRITICAL_SCORE;
                    } else {
                        findings.add("🟡 Suspicious API: " + sig);
                        totalRisk += HIGH_RISK_SCORE;
                    }
                }
            }

            Map<String, Boolean> features = new HashMap<>();
            features.put("has_obfuscation", dexCount > 2);
            features.put("has_dynamic_loading", content.contains("DexClassLoader") || content.contains("dalvik.system.DexFile"));
            features.put("has_crypto", content.contains(".enc") || content.contains(".crypt"));
            features.put("targets_files", content.contains("renameTo") || content.contains("Environment.getExternalStorageDirectory"));
            features.put("has_socket", content.contains("Ljava/net/Socket") || content.contains("HttpURLConnection"));
            features.put("has_shell_exec", content.contains("Runtime.exec") || content.contains("ProcessBuilder"));
            features.put("has_system_alert", content.contains("SYSTEM_ALERT_WINDOW") || content.contains("TYPE_SYSTEM_ERROR"));
            features.put("has_boot_receiver", content.contains("BOOT_COMPLETED"));
            features.put("has_adware_sdk", content.contains("com.airpush") || content.contains("com.leadbolt"));

            AIEngine.AIResult aiResult = AIEngine.predictMalwareProbability(features);
            com.hydradragon.antivirus.model.ThreatResult.ThreatType detectedType = aiResult.threatType;
            if (aiResult.isAnomalyDetected) {
                findings.add(aiResult.description);
                totalRisk += aiResult.riskScore;
                totalRisk = Math.min(totalRisk, 100);
            }

            if (findings.isEmpty() && totalRisk == 0) {
                findings.add("✅ Code analysis clean - No malicious signature found.");
            }

        } catch (java.util.zip.ZipException e) {
            // Encrypted / malformed zip entry — Java's strict ZipFile (Android 14+)
            // refuses to read it ("invalid CEN header (encrypted entry)"). That's
            // not a threat by itself and the native (Rust) engine still scans the
            // raw bytes, so just skip the Java code-analysis quietly.
            Log.w(TAG, "skip code analysis (unreadable zip): " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Code analysis error: " + e.getMessage());
        }

        com.hydradragon.antivirus.model.ThreatResult.ThreatType finalType = com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN;
        if (totalRisk >= 30) finalType = com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE;
        
        // AIResult'tan gelen türü kullan, ama genel bir risk varsa MALWARE'e düşür.
        try {
            // detectedType tanımlıysa
            if (totalRisk >= 30) finalType = com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE;
            // ama metod dışına scope olmaması için catch'te değişken yok, bu yüzden doğrudan atıyoruz
        } catch(Exception ignored) {}

        // Güvenli dönüş:
        return new AnalysisResult(totalRisk, findings, finalType);
    }

    public AnalysisResult analyzeInstalledApp(String packageName) {
        try {
            PackageInfo pkgInfo = context.getPackageManager().getPackageInfo(packageName, 0);
            return analyzeApk(pkgInfo.applicationInfo.sourceDir);
        } catch (PackageManager.NameNotFoundException e) {
            List<String> err = new ArrayList<>();
            err.add("App not found: " + packageName);
            return new AnalysisResult(0, err, com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN);
        }
    }
}
