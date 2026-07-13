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
        NativeScanner.init(this);
    }
}
