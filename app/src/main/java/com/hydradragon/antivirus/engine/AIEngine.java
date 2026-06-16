package com.hydradragon.antivirus.engine;

import android.util.Log;
import java.util.HashMap;
import java.util.Map;

public class AIEngine {
    private static final String TAG = "HydraDragon-AI";

    private static final Map<String, Double> WEIGHTS = new HashMap<>();
    static {
        WEIGHTS.put("has_obfuscation", 2.5);
        WEIGHTS.put("has_dynamic_loading", 4.0);
        WEIGHTS.put("has_crypto", 3.0);
        WEIGHTS.put("targets_files", 2.5);
        WEIGHTS.put("has_socket", 2.0);
        WEIGHTS.put("has_shell_exec", 3.5);
        WEIGHTS.put("has_system_alert", 2.8);
        WEIGHTS.put("has_boot_receiver", 1.5);
        WEIGHTS.put("has_adware_sdk", 1.8);
    }

    private static final double BIAS = -2.0;

    // GuardService ile geriye dönük uyumluluk için (Hata Çözümü)
    public AIEngine() {}
    public AIEngine(android.content.Context context) {}
    public void close() {}


    public static class AIResult {
        public final int riskScore;
        public final String description;
        public final boolean isAnomalyDetected;
        public final com.hydradragon.antivirus.model.ThreatResult.ThreatType threatType;

        public AIResult(int score, String desc, boolean isAnomaly, com.hydradragon.antivirus.model.ThreatResult.ThreatType type) {
            this.riskScore = score;
            this.description = desc;
            this.isAnomalyDetected = isAnomaly;
            this.threatType = type;
        }
    }

    public static AIResult predictMalwareProbability(Map<String, Boolean> features) {
        double sum = BIAS;
        int activeFeatures = 0;

        for (Map.Entry<String, Boolean> feature : features.entrySet()) {
            if (feature.getValue() && WEIGHTS.containsKey(feature.getKey())) {
                sum += WEIGHTS.get(feature.getKey());
                activeFeatures++;
            }
        }

        double probability = 1.0 / (1.0 + Math.exp(-sum));
        int aiScore = (int) (probability * 100);

        Log.d(TAG, "AI Probability: " + probability + " (Features: " + activeFeatures + ")");

        com.hydradragon.antivirus.model.ThreatResult.ThreatType type = com.hydradragon.antivirus.model.ThreatResult.ThreatType.MALWARE;
        if (Boolean.TRUE.equals(features.get("has_crypto")) || Boolean.TRUE.equals(features.get("has_system_alert"))) {
            type = com.hydradragon.antivirus.model.ThreatResult.ThreatType.RANSOMWARE;
        } else if (Boolean.TRUE.equals(features.get("has_shell_exec")) || Boolean.TRUE.equals(features.get("has_socket"))) {
            type = com.hydradragon.antivirus.model.ThreatResult.ThreatType.SPYWARE;
        } else if (Boolean.TRUE.equals(features.get("has_adware_sdk"))) {
            type = com.hydradragon.antivirus.model.ThreatResult.ThreatType.ADWARE;
        } else if (Boolean.TRUE.equals(features.get("has_dynamic_loading"))) {
            type = com.hydradragon.antivirus.model.ThreatResult.ThreatType.TROJAN;
        }

        if (aiScore > 75) {
            return new AIResult(aiScore, "AI Detection: Advanced Suspicious Behavior", true, type);
        } else if (aiScore > 50 && activeFeatures >= 3) {
            return new AIResult(aiScore / 2, "AI WARNING: Suspicious Behavior Combination Detected.", true, type);
        }
        
        return new AIResult(0, "", false, com.hydradragon.antivirus.model.ThreatResult.ThreatType.CLEAN);
    }
}
