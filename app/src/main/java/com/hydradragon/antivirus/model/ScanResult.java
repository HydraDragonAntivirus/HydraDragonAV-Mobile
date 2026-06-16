// DOSYA: app/src/main/java/com/hydradragon/antivirus/model/ScanResult.java
package com.hydradragon.antivirus.model;

import java.util.List;

public class ScanResult {
    private final int totalScanned;
    private final int threatsFound;
    private final List<ThreatResult> threats;
    private final long scanDurationMs;

    public ScanResult(int totalScanned, int threatsFound, List<ThreatResult> threats) {
        this.totalScanned = totalScanned;
        this.threatsFound = threatsFound;
        this.threats = threats;
        this.scanDurationMs = 0;
    }

    public int getTotalScanned() { return totalScanned; }
    public int getThreatsFound() { return threatsFound; }
    public List<ThreatResult> getThreats() { return threats; }
    public boolean isClean() { return threatsFound == 0; }
}

