package com.hydradragon.antivirus;

import android.app.Application;

import com.hydradragon.antivirus.engine.NativeScanner;

public final class HydraDragonApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        // Fire the native engine init at process start — before any Activity,
        // before any UI inflation. The ~70s ClamAV/YARA/ML load runs on a Rust
        // background thread so it overlaps with the splash screen / permission
        // dialogs instead of blocking the first scan.
        NativeScanner.init(this);
    }
}
