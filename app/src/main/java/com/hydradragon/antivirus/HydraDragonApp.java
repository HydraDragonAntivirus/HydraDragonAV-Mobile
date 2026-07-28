package com.hydradragon.antivirus;

import android.app.Application;
import android.content.SharedPreferences;

import androidx.appcompat.app.AppCompatDelegate;

import com.hydradragon.antivirus.engine.NativeScanner;

public final class HydraDragonApp extends Application {
    @Override
    public void onCreate() {
        // Apply the persisted theme preference before any Activity is created
        // or any view is inflated. AppCompatDelegate.setDefaultNightMode() must
        // be called before the first Activity's super.onCreate() — doing it here
        // in Application.onCreate() guarantees that even if the launcher or a
        // notification opens a different Activity first, the correct theme mode
        // (dark / light / system) is already active.
        SharedPreferences prefs = getSharedPreferences("hydra_prefs", MODE_PRIVATE);
        String theme = prefs.getString("theme_mode", null);
        if (theme == null) {
            boolean dark = prefs.getBoolean("dark_mode", true);
            theme = dark ? "dark" : "light";
            prefs.edit().putString("theme_mode", theme).apply();
        }
        switch (theme) {
            case "light":  AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);  break;
            case "system": AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM); break;
            default:       AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES); break;
        }

        super.onCreate();
        // Register the activity-lifecycle tracker at the Application level, BEFORE
        // any Activity is created. Registering it inside MainActivity.onCreate()
        // (as it used to be) misses MainActivity's own onActivityCreated — it
        // fires only for activities created AFTER registration — so createdCount
        // stayed 0 while MainActivity was on screen. StrandHoggGuard then read
        // numActivities=1 vs expected=0 and false-tripped "task hijack".
        com.hydradragon.antivirus.engine.AppLifecycleTracker.register(this);
        NativeScanner.init(this);
    }
}
