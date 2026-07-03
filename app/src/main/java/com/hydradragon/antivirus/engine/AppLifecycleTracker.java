package com.hydradragon.antivirus.engine;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

/** Tracks how many of HydraDragon's own activities are currently alive
 *  (created, not yet destroyed) — i.e. what THIS app itself put in its
 *  task's back stack. Used by {@link com.hydradragon.antivirus.security.StrandHoggGuard}
 *  to detect task hijacking (StrandHogg): a malicious app inserting one of
 *  ITS OWN activities into our task would make the task's real activity
 *  count (from ActivityManager) higher than what we ourselves created —
 *  since ActivityLifecycleCallbacks only ever fires for THIS app's own
 *  Activity instances, never another app's, that mismatch is exactly the
 *  detection signal. */
public final class AppLifecycleTracker implements Application.ActivityLifecycleCallbacks {

    private static volatile boolean registered = false;
    private static volatile int createdCount = 0;

    public static int getExpectedActivityCount() { return createdCount; }

    private AppLifecycleTracker() {}

    public static void register(Application app) {
        if (registered) return;
        registered = true;
        app.registerActivityLifecycleCallbacks(new AppLifecycleTracker());
    }

    @Override
    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        createdCount++;
    }

    @Override
    public void onActivityDestroyed(Activity activity) {
        createdCount--;
    }

    @Override public void onActivityStarted(Activity activity) {}
    @Override public void onActivityResumed(Activity activity) {}
    @Override public void onActivityPaused(Activity activity) {}
    @Override public void onActivityStopped(Activity activity) {}
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
}
