package com.hydradragon.antivirus.security;

import android.app.Activity;
import android.app.ActivityManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import com.hydradragon.antivirus.engine.AppLifecycleTracker;

import java.util.List;

/**
 * Guardsquare "Activities count check" — detects task hijacking (StrandHogg):
 * a malicious app inserting one of ITS OWN activities into OUR task's back
 * stack so it renders on top of (or instead of) a genuine HydraDragon screen,
 * e.g. to overlay a fake login/permission prompt on top of the real app UI.
 *
 * <p>{@link ActivityManager.TaskInfo#numActivities} counts every activity in
 * a task's back stack, regardless of which app put it there.
 * {@link AppLifecycleTracker#getExpectedActivityCount()} counts only what
 * HydraDragon itself created. If the task's real count is ever higher than
 * what we created, something else is in our task — fail closed.
 *
 * <p>Limitation (inherent to the API, not this implementation):
 * {@code TaskInfo.numActivities} was only added in API 29 (Android 10); below
 * that this check is a no-op. {@code ActivityManager.getRunningTasks()} (the
 * older, deprecated API) can see other apps' tasks pre-Android 10 but is
 * restricted to the caller's own tasks from Android 5.0 onward for non-system
 * apps anyway, so {@code getAppTasks()} (never deprecated, always
 * self-scoped) is used instead — there is no gap this trades away.
 */
public final class StrandHoggGuard {

    public interface OnHijackDetected {
        void onHijackDetected(int expected, int actual);
    }

    private final Activity activity;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable tick;

    public StrandHoggGuard(Activity activity) {
        this.activity = activity;
    }

    public void startWatching(OnHijackDetected callback, long intervalMs) {
        stopWatching();
        tick = new Runnable() {
            @Override
            public void run() {
                checkOnce(callback);
                handler.postDelayed(this, intervalMs);
            }
        };
        handler.postDelayed(tick, intervalMs);
    }

    public void stopWatching() {
        if (tick != null) handler.removeCallbacks(tick);
        tick = null;
    }

    private void checkOnce(OnHijackDetected callback) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return; // numActivities needs API 29
        // Screen pinning (App Pinning / lock task mode) legitimately changes
        // how the system reports this task — not a hijack, the user pinned
        // it themselves. Skip the check entirely while pinned.
        if (activity.isInLockTaskMode()) return;
        try {
            ActivityManager am = activity.getSystemService(ActivityManager.class);
            if (am == null) return;
            int taskId = activity.getTaskId();
            List<ActivityManager.AppTask> tasks = am.getAppTasks();
            for (ActivityManager.AppTask t : tasks) {
                ActivityManager.RecentTaskInfo info = t.getTaskInfo();
                if (info == null || info.taskId != taskId) continue;
                int actual = info.numActivities;
                int expected = AppLifecycleTracker.getExpectedActivityCount();
                if (actual > expected && isSuspectForeignForeground()) {
                    callback.onHijackDetected(expected, actual);
                }
                return;
            }
        } catch (Throwable ignore) {
            // Resource-intensive-but-best-effort by design (Guardsquare's own
            // caveat) — never crash the host activity over this check.
        }
    }

    /** A numActivities mismatch only means anything if it was actually caused
     *  by an untrusted THIRD-PARTY app landing on top of us — our own
     *  legitimate same-task navigation (Play Protect, Accessibility/Security
     *  Settings, VPN/screen-capture consent...) also bumps the task's real
     *  activity count without a hijacker involved, and none of those should
     *  ever trip this. {@link com.hydradragon.antivirus.service.DynamicAnalysisService}
     *  already tracks whichever package the accessibility service last saw in
     *  the foreground — if that's still us, or a known/trusted (system/OEM)
     *  package, this isn't a hijack. */
    private boolean isSuspectForeignForeground() {
        String fg = com.hydradragon.antivirus.service.DynamicAnalysisService.getForegroundPackage();
        if (fg == null || fg.isEmpty()) return false; // unknown — not enough evidence either way
        if (fg.equals(activity.getPackageName())) return false; // still our own app
        return !com.hydradragon.antivirus.engine.TrustedPackages.isTrusted(activity, fg);
    }
}
