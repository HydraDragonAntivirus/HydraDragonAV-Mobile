package com.hydradragon.antivirus.engine;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CleanupEngine {

    private static final Set<String> SAFE = new HashSet<>(Arrays.asList(
        "com.android.", "android", "com.google.android.", "com.miui.",
        "com.samsung.", "com.sec.", "com.oppo.", "com.vivo.", "com.motorola.",
        "com.huawei.", "com.oneplus.", "com.realme.", "com.coloros.", "com.heytap.",
        "com.qualcomm.", "com.mediatek.", "com.hydradragon."
    ));

    public static class BloatwareApp {
        public final String pkg, name, reason;
        public final long memKb;
        public android.graphics.drawable.Drawable icon;

        public BloatwareApp(String pkg, String name, String reason, long memKb,
                            android.graphics.drawable.Drawable icon) {
            this.pkg = pkg; this.name = name; this.reason = reason;
            this.memKb = memKb; this.icon = icon;
        }
    }

    public interface Callback {
        void onFound(BloatwareApp app);
        void onDone(int total);
    }

    private final Context ctx;
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    public CleanupEngine(Context ctx) { this.ctx = ctx; }

    public void scan(Callback cb) {
        exec.execute(() -> {
            PackageManager pm = ctx.getPackageManager();
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) { cb.onDone(0); return; }

            List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();
            if (procs == null) procs = new ArrayList<>();

            Set<String> seen = new HashSet<>();
            int found = 0;

            for (ActivityManager.RunningAppProcessInfo proc : procs) {
                // Sadece arka plan / servis / önbellektekiler
                if (proc.importance < ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE)
                    continue;
                if (proc.processName.equals(ctx.getPackageName())) continue;
                if (proc.processName.startsWith("android")
                    || proc.processName.startsWith("system")) continue;

                String pkg = proc.processName.contains(":")
                    ? proc.processName.split(":")[0] : proc.processName;

                if (seen.contains(pkg)) continue;
                seen.add(pkg);

                // Güvenli önekler
                boolean safe = false;
                for (String s : SAFE) { if (pkg.startsWith(s)) { safe = true; break; } }
                if (safe) continue;

                // RAM ölçüm
                long memKb = 0;
                try {
                    android.os.Debug.MemoryInfo[] mi =
                        am.getProcessMemoryInfo(new int[]{proc.pid});
                    if (mi != null && mi.length > 0) memKb = mi[0].getTotalPss();
                } catch (Exception ignored) {}

                // Uygulama bilgisi
                String appName = pkg;
                android.graphics.drawable.Drawable icon = null;
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                    appName = pm.getApplicationLabel(ai).toString();
                    icon = pm.getApplicationIcon(ai);
                    boolean isSys = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                    if (ai.sourceDir != null && (ai.sourceDir.startsWith("/system/")
                        || ai.sourceDir.startsWith("/vendor/"))) isSys = true;
                    if (isSys) continue;
                } catch (PackageManager.NameNotFoundException e) { continue; }

                // switch yerine if-else (duplicate case hatası önlenir)
                String reason;
                int imp = proc.importance;
                if (imp == ActivityManager.RunningAppProcessInfo.IMPORTANCE_BACKGROUND) {
                    reason = "📦 Arka Planda Çalışıyor";
                } else if (imp == ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE) {
                    reason = "⚙ Gizli Servis Olarak Çalışıyor";
                } else if (imp >= ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED) {
                    reason = "💾 RAM'de Boşuna Bekliyor";
                } else {
                    reason = "🔄 Aktif Arka Plan Süreci";
                }
                reason += "  (" + (memKb / 1024) + " MB)";

                found++;
                cb.onFound(new BloatwareApp(pkg, appName, reason, memKb, icon));
            }
            cb.onDone(found);
        });
    }

    /** Root ile devre dışı bırak. Başarısızsa false döner. */
    public static boolean disableWithRoot(String pkg) {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"su", "-c", "pm disable-user --user 0 " + pkg});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String out = r.readLine(); p.waitFor();
            return out != null && out.contains("disabled");
        } catch (Exception e) { return false; }
    }
}
