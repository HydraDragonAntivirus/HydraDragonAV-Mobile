// FILE: app/src/main/java/com/hydradragon/antivirus/model/ThreatResult.java
package com.hydradragon.antivirus.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Threat detection result model
 */
public class ThreatResult {

    public enum ThreatType {
        CLEAN,          // Clean
        UNKNOWN,        // Zero Trust: no detector matched — NOT verified clean
        SUSPICIOUS,     // Suspicious (low risk)
        MALWARE,        // Known malware
        SPYWARE,        // Spyware
        RANSOMWARE,     // Ransomware
        ADWARE,         // Adware
        TROJAN,         // Trojan
        BACKDOOR,       // Backdoor
        PHISHING,       // Phishing (embedded phishing/typosquat URL)
        PUA,            // Potansiyel istenmeyen uygulama (PUA.* / PUA_*)
        TEST_MALWARE    // EICAR standard AV test signature — a deliberate test
                         // file, not a real threat; kept distinct so the UI can
                         // label it clearly instead of alarming the user.
    }

    private final String packageName;
    private final String appName;
    private final String apkPath;
    private final int riskScore;          // 0-100
    private final ThreatType threatType;
    private final List<String> reasons;
    private final List<String> dangerousPermissions;
    private final long timestamp;

    private ThreatResult(Builder builder) {
        this.packageName = builder.packageName;
        this.appName = builder.appName;
        this.apkPath = builder.apkPath;
        this.riskScore = builder.riskScore;
        this.threatType = builder.threatType;
        this.reasons = builder.reasons;
        this.dangerousPermissions = builder.dangerousPermissions;
        this.timestamp = System.currentTimeMillis();
    }

    public boolean isThreat() { return riskScore >= 30; }
    public boolean isCritical() { return riskScore >= 70; }

    
    public int getThreatLevelResId() {
        if (riskScore >= 70) return com.hydradragon.antivirus.R.string.level_critical;
        if (riskScore >= 50) return com.hydradragon.antivirus.R.string.level_high;
        if (riskScore >= 30) return com.hydradragon.antivirus.R.string.level_medium;
        return com.hydradragon.antivirus.R.string.level_clean;
    }
    public String getThreatLevel() {
        if (riskScore >= 70) return "CRITICAL";
        if (riskScore >= 50) return "HIGH";
        if (riskScore >= 30) return "MEDIUM";
        return "SAFE";
    }

    public String getThreatLevelColor() {
        if (riskScore >= 70) return "#FF0040";
        if (riskScore >= 50) return "#FF6600";
        if (riskScore >= 30) return "#FFD700";
        return "#00FF88";
    }

    // Getters
    public String getPackageName() { return packageName; }
    public String getAppName() { return appName != null ? appName : packageName; }
    public String getApkPath() { return apkPath; }
    public int getRiskScore() { return riskScore; }
    public ThreatType getThreatType() { return threatType; }
    public List<String> getReasons() { return reasons; }
    public List<String> getDangerousPermissions() { return dangerousPermissions; }
    public long getTimestamp() { return timestamp; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ThreatResult)) return false;
        ThreatResult other = (ThreatResult) o;
        return packageName != null ? packageName.equals(other.packageName) : other.packageName == null;
    }

    @Override
    public int hashCode() {
        return packageName != null ? packageName.hashCode() : 0;
    }

    public static class Builder {
        private final String packageName;
        private String appName;
        private String apkPath;
        private int riskScore = 0;
        private ThreatType threatType = ThreatType.CLEAN;
        private List<String> reasons = new ArrayList<>();
        private List<String> dangerousPermissions = new ArrayList<>();

        public Builder(String packageName) { this.packageName = packageName; }
        public Builder setAppName(String n) { appName = n; return this; }
        public Builder setApkPath(String p) { apkPath = p; return this; }
        public Builder setRiskScore(int s) { riskScore = Math.min(s, 100); return this; }
        public Builder setThreatType(ThreatType t) { threatType = t; return this; }
        public Builder setReasons(List<String> r) { reasons = r; return this; }
        public Builder setDangerousPermissions(List<String> p) { dangerousPermissions = p; return this; }
        public ThreatResult build() { return new ThreatResult(this); }
    }
}
