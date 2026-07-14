package com.hydradragon.antivirus.model;

import java.util.Collections;
import java.util.List;

public class ScanResult {
    private final int totalScanned;
    private final int threatsFound;
    private final List<ThreatResult> threats;
    private final List<ScannedFileInfo> scannedFiles;
    private final long scanDurationMs;

    public ScanResult(int totalScanned, int threatsFound, List<ThreatResult> threats,
                     List<ScannedFileInfo> scannedFiles, long scanDurationMs) {
        this.totalScanned = totalScanned;
        this.threatsFound = threatsFound;
        this.threats = threats;
        this.scannedFiles = scannedFiles != null ? scannedFiles : Collections.emptyList();
        this.scanDurationMs = scanDurationMs;
    }

    public int getTotalScanned() { return totalScanned; }
    public int getThreatsFound() { return threatsFound; }
    public List<ThreatResult> getThreats() { return threats; }
    public List<ScannedFileInfo> getScannedFiles() { return scannedFiles; }
    public long getScanDurationMs() { return scanDurationMs; }
    public boolean isClean() { return threatsFound == 0; }
}

