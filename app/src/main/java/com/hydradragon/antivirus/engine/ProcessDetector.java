// FILE: app/src/main/java/com/hydradragon/antivirus/engine/ProcessDetector.java
package com.hydradragon.antivirus.engine;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import com.hydradragon.antivirus.model.ProcessInfo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * HydraDragon Process Detector
 * Hidden and suspicious process detection.
 *
 * Detection methods:
 * - /proc/ filesystem analysis (may require root)
 * - ActivityManager process list
 * - Hidden process name detection
 * - Suspicious processes with high CPU/RAM usage
 * - Root/su process detection
 */
public class ProcessDetector {

    private static final String TAG = "HydraDragon-ProcDet";

    // Known dangerous process names
    private static final Set<String> DANGEROUS_PROCESS_NAMES = new HashSet<>(Arrays.asList(
        "su", "supersu", "magisk", "daemonsu",
        "netcat", "nc", "ncat",
        "tcpdump", "wireshark", "frida",
        "xposed", "substrate",
        "metasploit", "msfconsole", "meterpreter",
        "cryptominer", "xmrig",
        "keylogger", "spyware"
    ));

    // Abnormal high memory usage threshold (MB)
    private static final long HIGH_MEMORY_THRESHOLD_MB = 500;
    // Abnormal high CPU usage threshold (%)
    private static final float HIGH_CPU_THRESHOLD = 80.0f;

    private final Context context;
    private final ActivityManager activityManager;
    private final PackageManager packageManager;
    private ProcessCallback callback;

    public interface ProcessCallback {
        void onSuspiciousProcess(ProcessInfo processInfo);
        void onProcessListUpdated(List<ProcessInfo> processes);
    }

    public ProcessDetector(Context context) {
        this.context = context;
        this.activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        this.packageManager = context.getPackageManager();
    }

    public void setCallback(ProcessCallback callback) {
        this.callback = callback;
    }

    /**
     * Scan all running processes
     */
    public List<ProcessInfo> scanRunningProcesses() {
        List<ProcessInfo> processList = new ArrayList<>();

        // Get process list via ActivityManager
        List<ActivityManager.RunningAppProcessInfo> runningApps =
            activityManager.getRunningAppProcesses();

        if (runningApps == null) {
            Log.w(TAG, "Could not get process list");
            return processList;
        }

        for (ActivityManager.RunningAppProcessInfo processInfo : runningApps) {
            ProcessInfo info = analyzeProcess(processInfo);
            processList.add(info);

            if (callback != null && info.getPackageName() != null) {
                callback.onSuspiciousProcess(info);
            }
        }

        // /proc/ analysis (limited on non-root devices)
        List<ProcessInfo> procFsProcesses = scanProcFilesystem();
        for (ProcessInfo p : procFsProcesses) {
            if (!containsProcess(processList, p.getPid())) {
                processList.add(p);
                if (callback != null && p.getPackageName() != null) {
                    callback.onSuspiciousProcess(p);
                }
            }
        }

        if (callback != null) callback.onProcessListUpdated(processList);
        return processList;
    }

    /**
     * Single process analysis
     */
    private ProcessInfo analyzeProcess(ActivityManager.RunningAppProcessInfo rawInfo) {
        ProcessInfo.Builder builder = new ProcessInfo.Builder();
        builder.setPid(rawInfo.pid);
        builder.setProcessName(rawInfo.processName);
        builder.setImportance(rawInfo.importance);

        int riskScore = 0;
        List<String> flags = new ArrayList<>();

        // 1. Dangerous name check
        String name = rawInfo.processName.toLowerCase();
        for (String dangerous : DANGEROUS_PROCESS_NAMES) {
            if (name.contains(dangerous)) {
                riskScore += 80;
                flags.add("TEHLİKELİ PROCESS: " + dangerous);
                break;
            }
        }

        // 2. Anonymous/hidden process check
        if (name.startsWith(":") || name.matches(".*\\d{4,}.*")) {
            riskScore += 20;
            flags.add("Gizlenmiş process adı");
        }

        // 3. Memory usage
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        activityManager.getMemoryInfo(memInfo);
        int[] pids = {rawInfo.pid};
        android.os.Debug.MemoryInfo[] memInfoArray = activityManager.getProcessMemoryInfo(pids);
        if (memInfoArray.length > 0) {
            long memMB = memInfoArray[0].getTotalPss() / 1024;
            builder.setMemoryMb(memMB);
            if (memMB > HIGH_MEMORY_THRESHOLD_MB) {
                riskScore += 15;
                flags.add("Yüksek bellek kullanımı: " + memMB + "MB");
            }
        }

        // 4. Application info
        String[] packages = rawInfo.pkgList;
        if (packages != null && packages.length > 0) {
            try {
                ApplicationInfo appInfo = packageManager.getApplicationInfo(packages[0], 0);
                boolean isSystem = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                builder.setSystemProcess(isSystem);
                builder.setPackageName(packages[0]);
                builder.setAppName((String) packageManager.getApplicationLabel(appInfo));
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found - suspicious!
                riskScore += 30;
                flags.add("Bilinmeyen uygulama paketi");
            }
        }

        // 5. Background service check
        if (rawInfo.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE) {
            // Background service - may be normal but check
        }

        builder.setRiskScore(riskScore);
        builder.setFlags(flags);
        return builder.build();
    }

    private List<ProcessInfo> cachedProcScan = null;
    private long lastProcScanMs = 0;
    private static final long PROC_SCAN_TTL_MS = 300_000;

    /**
     * Scan /proc/ filesystem (for hidden processes)
     */
    private List<ProcessInfo> scanProcFilesystem() {
        long now = System.currentTimeMillis();
        if (cachedProcScan != null && (now - lastProcScanMs) < PROC_SCAN_TTL_MS) {
            return cachedProcScan;
        }

        List<ProcessInfo> processes = new ArrayList<>();
        File procDir = new File("/proc");

        if (!procDir.exists() || !procDir.canRead()) {
            Log.d(TAG, "/proc not readable (root may be required)");
            cachedProcScan = processes;
            lastProcScanMs = now;
            return processes;
        }

        File[] procEntries;
        try {
            procEntries = procDir.listFiles();
        } catch (SecurityException e) {
            Log.w(TAG, "/proc listing denied: " + e.getMessage());
            cachedProcScan = processes;
            lastProcScanMs = now;
            return processes;
        }
        if (procEntries == null) {
            cachedProcScan = processes;
            lastProcScanMs = now;
            return processes;
        }

        for (File entry : procEntries) {
            String name = entry.getName();
            if (!name.matches("\\d+")) continue;

            int pid;
            try {
                pid = Integer.parseInt(name);
            } catch (NumberFormatException e) {
                continue;
            }
            String processName = readProcessName(pid);
            long memoryKb = readProcessMemory(pid);

            ProcessInfo.Builder builder = new ProcessInfo.Builder();
            builder.setPid(pid);
            builder.setProcessName(processName != null ? processName : "unknown:" + pid);
            builder.setMemoryMb(memoryKb / 1024);

            int riskScore = 0;
            List<String> flags = new ArrayList<>();

            if (processName != null) {
                for (String dangerous : DANGEROUS_PROCESS_NAMES) {
                    if (processName.toLowerCase().contains(dangerous)) {
                        riskScore += 90;
                        flags.add("/proc tespit - TEHLİKELİ: " + dangerous);
                        break;
                    }
                }
            } else {
                riskScore += 25;
                flags.add("Process adı gizlenmiş");
            }

            builder.setRiskScore(riskScore);
            builder.setFlags(flags);
            processes.add(builder.build());
        }

        cachedProcScan = processes;
        lastProcScanMs = now;
        return processes;
    }

    private String readProcessName(int pid) {
        try {
            BufferedReader reader = new BufferedReader(
                new FileReader("/proc/" + pid + "/comm"));
            String name = reader.readLine();
            reader.close();
            return name != null ? name.trim() : null;
        } catch (IOException e) {
            return null;
        }
    }

    private long readProcessMemory(int pid) {
        try {
            BufferedReader reader = new BufferedReader(
                new FileReader("/proc/" + pid + "/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("VmRSS:")) {
                    reader.close();
                    return Long.parseLong(line.replaceAll("[^0-9]", ""));
                }
            }
            reader.close();
        } catch (IOException e) { /* ignore */ }
        return 0;
    }

    private boolean containsProcess(List<ProcessInfo> list, int pid) {
        for (ProcessInfo p : list) if (p.getPid() == pid) return true;
        return false;
    }
}

