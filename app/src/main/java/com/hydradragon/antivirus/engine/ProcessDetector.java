// DOSYA: app/src/main/java/com/hydradragon/antivirus/engine/ProcessDetector.java
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
 * Gizli ve şüpheli process tespiti.
 *
 * Tespit yöntemleri:
 * - /proc/ filesystem analizi (root gerekebilir)
 * - ActivityManager process listesi
 * - Gizlenmiş process adı tespiti
 * - Yüksek CPU/RAM kullanan şüpheli processler
 * - Root/su process tespiti
 */
public class ProcessDetector {

    private static final String TAG = "HydraDragon-ProcDet";

    // Bilinen tehlikeli process adları
    private static final Set<String> DANGEROUS_PROCESS_NAMES = new HashSet<>(Arrays.asList(
        "su", "supersu", "magisk", "daemonsu",
        "netcat", "nc", "ncat",
        "tcpdump", "wireshark", "frida",
        "xposed", "substrate",
        "metasploit", "msfconsole", "meterpreter",
        "cryptominer", "xmrig",
        "keylogger", "spyware"
    ));

    // Normal olmayan yüksek memory kullanım eşiği (MB)
    private static final long HIGH_MEMORY_THRESHOLD_MB = 500;
    // Normal olmayan yüksek CPU kullanım eşiği (%)
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
     * Tüm çalışan processleri tara
     */
    public List<ProcessInfo> scanRunningProcesses() {
        List<ProcessInfo> processList = new ArrayList<>();

        // ActivityManager ile process listesi al
        List<ActivityManager.RunningAppProcessInfo> runningApps =
            activityManager.getRunningAppProcesses();

        if (runningApps == null) {
            Log.w(TAG, "Process listesi alınamadı");
            return processList;
        }

        for (ActivityManager.RunningAppProcessInfo processInfo : runningApps) {
            ProcessInfo info = analyzeProcess(processInfo);
            processList.add(info);

            if (info.isSuspicious() && callback != null) {
                callback.onSuspiciousProcess(info);
            }
        }

        // /proc/ analizi (root olmayan cihazlarda sınırlı)
        List<ProcessInfo> procFsProcesses = scanProcFilesystem();
        for (ProcessInfo p : procFsProcesses) {
            if (!containsProcess(processList, p.getPid())) {
                processList.add(p);
                if (p.isSuspicious() && callback != null) {
                    callback.onSuspiciousProcess(p);
                }
            }
        }

        if (callback != null) callback.onProcessListUpdated(processList);
        return processList;
    }

    /**
     * Tek process analizi
     */
    private ProcessInfo analyzeProcess(ActivityManager.RunningAppProcessInfo rawInfo) {
        ProcessInfo.Builder builder = new ProcessInfo.Builder();
        builder.setPid(rawInfo.pid);
        builder.setProcessName(rawInfo.processName);
        builder.setImportance(rawInfo.importance);

        int riskScore = 0;
        List<String> flags = new ArrayList<>();

        // 1. Tehlikeli isim kontrolü
        String name = rawInfo.processName.toLowerCase();
        for (String dangerous : DANGEROUS_PROCESS_NAMES) {
            if (name.contains(dangerous)) {
                riskScore += 80;
                flags.add("TEHLİKELİ PROCESS: " + dangerous);
                break;
            }
        }

        // 2. Anonim/gizlenmiş process kontrolü
        if (name.startsWith(":") || name.matches(".*\\d{4,}.*")) {
            riskScore += 20;
            flags.add("Gizlenmiş process adı");
        }

        // 3. Memory kullanımı
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

        // 4. Uygulama bilgisi
        String[] packages = rawInfo.pkgList;
        if (packages != null && packages.length > 0) {
            try {
                ApplicationInfo appInfo = packageManager.getApplicationInfo(packages[0], 0);
                boolean isSystem = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                builder.setSystemProcess(isSystem);
                builder.setAppName((String) packageManager.getApplicationLabel(appInfo));
            } catch (PackageManager.NameNotFoundException e) {
                // Package bulunamadı - şüpheli!
                riskScore += 30;
                flags.add("Bilinmeyen uygulama paketi");
            }
        }

        // 5. Arka plan servis kontrolü
        if (rawInfo.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE) {
            // Arka plan servisi - normal olabilir ama kontrol et
        }

        builder.setRiskScore(riskScore);
        builder.setFlags(flags);
        return builder.build();
    }

    /**
     * /proc/ filesystem'i tara (gizli processler için)
     */
    private List<ProcessInfo> scanProcFilesystem() {
        List<ProcessInfo> processes = new ArrayList<>();
        File procDir = new File("/proc");

        if (!procDir.exists() || !procDir.canRead()) {
            Log.d(TAG, "/proc okunamadı (root gerekebilir)");
            return processes;
        }

        File[] procEntries = procDir.listFiles();
        if (procEntries == null) return processes;

        for (File entry : procEntries) {
            if (!entry.isDirectory()) continue;
            String name = entry.getName();

            // Sayısal klasörler PID'leri temsil eder
            if (!name.matches("\\d+")) continue;

            int pid = Integer.parseInt(name);
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

