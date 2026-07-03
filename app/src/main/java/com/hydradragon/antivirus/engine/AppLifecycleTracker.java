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

    /** How many of OUR OWN activities are currently alive (created, not yet
     *  destroyed) — i.e. what this app itself put in its task's back stack.
     *  Compared by StrandHoggGuard against the task's actual activity count
     *  (which also includes any foreign activity injected into our task by a
     *  StrandHogg-style task-hijacking attack) — a mismatch means something
     *  is in our task that we didn't create. */
    private static volatile int createdCount = 0;

    public static int getExpectedActivityCount() { return createdCount; }

    private int startedCount = 0;

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

    @Override public void onActivityResumed(Activity activity) {}
    @Override public void onActivityPaused(Activity activity) {}
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
}
