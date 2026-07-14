package com.hydradragon.antivirus.model;

public class ScannedFileInfo {
    private final String filePath;
    private final String packageName;
    private final String appName;
    private final int riskScore;
    private final String md5;
    private final long timestamp;
    private final boolean threat;
    private final String verdictReason;

    public ScannedFileInfo(String filePath, String packageName, String appName,
                          int riskScore, String md5, long timestamp,
                          boolean threat, String verdictReason) {
        this.filePath = filePath;
        this.packageName = packageName;
        this.appName = appName;
        this.riskScore = riskScore;
        this.md5 = md5;
        this.timestamp = timestamp;
        this.threat = threat;
        this.verdictReason = verdictReason;
    }

    public String getFilePath() { return filePath; }
    public String getPackageName() { return packageName; }
    public String getAppName() { return appName; }
    public int getRiskScore() { return riskScore; }
    public String getMd5() { return md5; }
    public long getTimestamp() { return timestamp; }
    public boolean isThreat() { return threat; }
    public String getVerdictReason() { return verdictReason; }
}
