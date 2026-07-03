package com.hydradragon.antivirus.engine;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.SystemClock;

/** Counts how many of HydraDragon's own activities are currently
 *  started/visible. When the count drops to zero the app has genuinely gone
 *  to the background (home press, task switch, screen off) rather than just
 *  handing off to one of our own activities (e.g. MainActivity opening
 *  AppLockActivity or BlockActivity), since those handoffs never let the
 *  count reach zero for more than an instant. Feeds AppLockManager so App
 *  Lock only re-prompts after a real background stay, not every internal
 *  transition. */
public final class AppLifecycleTracker implements Application.ActivityLifecycleCallbacks {

    private static volatile boolean registered = false;

    private int startedCount = 0;

    private AppLifecycleTracker() {}

    public static void register(Application app) {
        if (registered) return;
        registered = true;
        app.registerActivityLifecycleCallbacks(new AppLifecycleTracker());
    }

    @Override
    public void onActivityStarted(Activity activity) {
        startedCount++;
        if (startedCount == 1) {
            AppLockManager.onAppForegrounded(SystemClock.elapsedRealtime());
        }
    }

    @Override
    public void onActivityStopped(Activity activity) {
        startedCount--;
        if (startedCount == 0) {
            AppLockManager.onAppBackgrounded(SystemClock.elapsedRealtime());
        }
    }

    @Override public void onActivityCreated(Activity activity, Bundle savedInstanceState) {}
    @Override public void onActivityResumed(Activity activity) {}
    @Override public void onActivityPaused(Activity activity) {}
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
    @Override public void onActivityDestroyed(Activity activity) {}
}
