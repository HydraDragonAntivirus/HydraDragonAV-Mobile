// DOSYA: app/src/main/java/com/hydradragon/antivirus/model/ProcessInfo.java
package com.hydradragon.antivirus.model;

import java.util.ArrayList;
import java.util.List;

public class ProcessInfo {
    private final int pid;
    private final String processName;
    private final String appName;
    private final long memoryMb;
    private final int riskScore;
    private final List<String> flags;
    private final boolean isSystemProcess;
    private final int importance;

    private ProcessInfo(Builder builder) {
        this.pid = builder.pid;
        this.processName = builder.processName;
        this.appName = builder.appName;
        this.memoryMb = builder.memoryMb;
        this.riskScore = builder.riskScore;
        this.flags = builder.flags;
        this.isSystemProcess = builder.isSystemProcess;
        this.importance = builder.importance;
    }

    public boolean isSuspicious() { return riskScore >= 30; }
    public boolean isCritical() { return riskScore >= 70; }

    public int getPid() { return pid; }
    public String getProcessName() { return processName; }
    public String getAppName() { return appName != null ? appName : processName; }
    public long getMemoryMb() { return memoryMb; }
    public int getRiskScore() { return riskScore; }
    public List<String> getFlags() { return flags; }
    public boolean isSystemProcess() { return isSystemProcess; }
    public int getImportance() { return importance; }

    public static class Builder {
        private int pid;
        private String processName = "";
        private String appName;
        private long memoryMb;
        private int riskScore;
        private List<String> flags = new ArrayList<>();
        private boolean isSystemProcess;
        private int importance;

        public Builder setPid(int p) { pid = p; return this; }
        public Builder setProcessName(String n) { processName = n; return this; }
        public Builder setAppName(String n) { appName = n; return this; }
        public Builder setMemoryMb(long m) { memoryMb = m; return this; }
        public Builder setRiskScore(int s) { riskScore = s; return this; }
        public Builder setFlags(List<String> f) { flags = f; return this; }
        public Builder setSystemProcess(boolean s) { isSystemProcess = s; return this; }
        public Builder setImportance(int i) { importance = i; return this; }
        public ProcessInfo build() { return new ProcessInfo(this); }
    }
}
