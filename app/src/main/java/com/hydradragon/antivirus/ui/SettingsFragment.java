package com.hydradragon.antivirus.ui;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.CleanupEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SettingsFragment extends Fragment {

    private LinearLayout container;
    private final List<CleanupEngine.BloatwareApp> foundBloatware = new ArrayList<>();
    private static final String PREFS = "hydra_prefs";
    private static final String KEY_DARK = "dark_mode";
    private static final String KEY_SHIELD = "web_shield_enabled";
    private static final String KEY_SCREEN_OCR = "screen_ocr_enabled";
    private static final int REQ_VPN = 1201;
    private static final int REQ_SCREEN_CAPTURE = 1202;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inf, @Nullable ViewGroup p, @Nullable Bundle s) {
        ScrollView scroll = new ScrollView(getContext());
        scroll.setBackgroundColor(color(R.color.bg_primary));
        container = new LinearLayout(getContext());
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(40, 56, 40, 56);
        scroll.addView(container);
        buildUI();
        return scroll;
    }

    private void buildUI() {
        container.removeAllViews();
        addTitle(getString(R.string.settings_title));
        addBtn("🌍 " + getString(R.string.language_settings), color(R.color.bg_secondary), v -> selectLanguage());

        addHeader(getString(R.string.appearance));
        boolean dark = prefs().getBoolean(KEY_DARK, true);
        addToggle(getString(R.string.dark_light_mode), dark, (btn, on) -> {
            prefs().edit().putBoolean(KEY_DARK, on).apply();
            // Tüm uygulamaya temayı anında uygula ve yeniden çiz
            AppCompatDelegate.setDefaultNightMode(on
                ? AppCompatDelegate.MODE_NIGHT_YES
                : AppCompatDelegate.MODE_NIGHT_NO);
            if (getActivity() != null) getActivity().recreate();
        });

        addHeader(getString(R.string.protection_header));
        boolean prot = com.hydradragon.antivirus.engine.ProtectionState.isEnabled(requireContext());
        addToggle(getString(R.string.realtime_protection), prot, (btn, on) -> {
            com.hydradragon.antivirus.engine.ProtectionState.setEnabled(requireContext(), on);
            Intent svc = new Intent(requireContext(),
                com.hydradragon.antivirus.service.GuardService.class);
            if (on) {
                ContextCompat.startForegroundService(requireContext(), svc);
                Toast.makeText(getContext(), getString(R.string.protection_enabled), Toast.LENGTH_SHORT).show();
            } else {
                requireContext().stopService(svc);
                Toast.makeText(getContext(), "Protection paused — no alerts", Toast.LENGTH_SHORT).show();
            }
        });

        boolean shield = prefs().getBoolean(KEY_SHIELD, false);
        addToggle("Web Shield (DNS VPN)", shield, (btn, on) -> {
            prefs().edit().putBoolean("web_shield_decided", true)
                          .putBoolean(KEY_SHIELD, on).apply();
            if (on) enableWebShield(btn);
            else disableWebShield();
        });

        addHeader("Zero Trust (experimental)");
        boolean zeroTrust = com.hydradragon.antivirus.engine.ZeroTrustMode.isEnabled(requireContext());
        addToggle("Zero Trust Mode — NOT RECOMMENDED", zeroTrust, (btn, on) -> {
            com.hydradragon.antivirus.engine.ZeroTrustMode.setEnabled(requireContext(), on);
            Toast.makeText(getContext(), on
                ? "Zero Trust ON: unmatched apps now show as unverified, not clean — expect false positives"
                : "Zero Trust OFF", Toast.LENGTH_LONG).show();
        });

        boolean screenOcr = prefs().getBoolean(KEY_SCREEN_OCR, false);
        addToggle("Screen OCR scanning — NOT RECOMMENDED (battery)", screenOcr, (btn, on) -> {
            if (on) requestScreenCapture(btn);
            else stopScreenCapture();
        });

        addHeader(getString(R.string.system));
        // app lock removed });
        addBtn(getString(R.string.bloatware_cleaner), color(R.color.neon_cyan), v -> runCleanup());

        addHeader(getString(R.string.about));
        addAbout();
    }

    // ─── BLOATWARE ─────────────────────────────────────────────────
    private void runCleanup() {
        foundBloatware.clear();
        AlertDialog dlg = new AlertDialog.Builder(requireContext(),
            android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.scanning_bloatware))
            .setMessage(getString(R.string.scanning_bloatware_msg))
            .setCancelable(false).create();
        dlg.show();

        new CleanupEngine(requireContext()).scan(new CleanupEngine.Callback() {
            @Override public void onFound(CleanupEngine.BloatwareApp a) { foundBloatware.add(a); }
            @Override public void onDone(int n) {
                if (getActivity() == null) return;
                getActivity().runOnUiThread(() -> {
                    dlg.dismiss();
                    if (n == 0) Toast.makeText(getContext(), getString(R.string.clean_no_bloatware), Toast.LENGTH_LONG).show();
                    else showNext();
                });
            }
        });
    }

    private void showNext() {
        if (foundBloatware.isEmpty()) {
            Toast.makeText(getContext(), getString(R.string.all_apps_processed), Toast.LENGTH_SHORT).show();
            return;
        }
        CleanupEngine.BloatwareApp a = foundBloatware.get(0);
        LinearLayout lay = new LinearLayout(getContext());
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setPadding(32, 24, 32, 24);

        if (a.icon != null) {
            ImageView iv = new ImageView(getContext());
            iv.setImageDrawable(a.icon);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(96, 96);
            lp.gravity = Gravity.CENTER_HORIZONTAL; lp.bottomMargin = 16;
            lay.addView(iv, lp);
        }
        TextView tv = new TextView(getContext());
        tv.setText(a.reason + "\n\n📱 " + a.name + "\n📦 " + a.pkg
            + "\n💾 " + (a.memKb / 1024) + " MB RAM\n\n⏳ Kalan: " + foundBloatware.size());
        tv.setTextColor(color(R.color.text_primary));
        tv.setTypeface(Typeface.MONOSPACE);
        lay.addView(tv);

        new AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.bg_app_found))
            .setView(lay)
            .setPositiveButton(getString(R.string.btn_uninstall_disable), (d, w) -> {
                if (!CleanupEngine.disableWithRoot(a.pkg)) {
                    startActivity(new Intent(Intent.ACTION_DELETE)
                        .setData(Uri.parse("package:" + a.pkg)));
                } else {
                    Toast.makeText(getContext(), getString(R.string.disabled_success), Toast.LENGTH_SHORT).show();
                }
                foundBloatware.remove(0); showNext();
            })
            .setNegativeButton(getString(R.string.btn_skip), (d, w) -> { foundBloatware.remove(0); showNext(); })
            .setNeutralButton(getString(R.string.btn_close), null).show();
    }

    // ─── WEB SHIELD (DNS VPN) ─────────────────────────────────────
    private void enableWebShield(CompoundButton btn) {
        Intent prep;
        try {
            prep = VpnService.prepare(requireContext());
        } catch (Throwable t) {
            Toast.makeText(getContext(), "VPN unavailable on this device", Toast.LENGTH_LONG).show();
            prefs().edit().putBoolean(KEY_SHIELD, false).apply();
            if (btn != null) btn.setChecked(false);
            return;
        }
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);   // system consent dialog
        } else {
            startShieldService();                    // already authorised
        }
    }

    private void startShieldService() {
        ContextCompat.startForegroundService(requireContext(),
            new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class));
        Toast.makeText(getContext(), "Web Shield enabled", Toast.LENGTH_SHORT).show();
    }

    private void disableWebShield() {
        // Deliver an explicit STOP action so the running service tears the tunnel
        // down deterministically, then also stopService as a belt-and-braces.
        Intent svc = new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class);
        svc.setAction(com.hydradragon.antivirus.service.DnsVpnService.ACTION_STOP);
        try { requireContext().startService(svc); } catch (Throwable ignore) {}
        requireContext().stopService(
            new Intent(requireContext(), com.hydradragon.antivirus.service.DnsVpnService.class));
        Toast.makeText(getContext(), "Web Shield disabled", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == android.app.Activity.RESULT_OK) {
                startShieldService();
            } else {
                // Consent denied — revert the toggle.
                prefs().edit().putBoolean(KEY_SHIELD, false).apply();
                Toast.makeText(getContext(), "VPN consent denied", Toast.LENGTH_LONG).show();
                buildUI();
            }
        } else if (requestCode == REQ_SCREEN_CAPTURE) {
            if (resultCode == android.app.Activity.RESULT_OK && data != null) {
                prefs().edit().putBoolean(KEY_SCREEN_OCR, true).apply();
                Intent svc = new Intent(requireContext(),
                    com.hydradragon.antivirus.service.ScreenCaptureService.class);
                svc.putExtra(com.hydradragon.antivirus.service.ScreenCaptureService.EXTRA_RESULT_CODE, resultCode);
                svc.putExtra(com.hydradragon.antivirus.service.ScreenCaptureService.EXTRA_RESULT_DATA, data);
                ContextCompat.startForegroundService(requireContext(), svc);
                Toast.makeText(getContext(), "Screen OCR scanning ON", Toast.LENGTH_SHORT).show();
            } else {
                prefs().edit().putBoolean(KEY_SCREEN_OCR, false).apply();
                Toast.makeText(getContext(), "Screen capture consent denied", Toast.LENGTH_LONG).show();
                buildUI();
            }
        }
    }

    // ─── SCREEN OCR (Zero Trust) ───────────────────────────────────
    private void requestScreenCapture(CompoundButton btn) {
        android.media.projection.MediaProjectionManager mgr =
            (android.media.projection.MediaProjectionManager)
                requireContext().getSystemService(Context.MEDIA_PROJECTION_SERVICE);
        if (mgr == null) {
            Toast.makeText(getContext(), "Screen capture unavailable on this device", Toast.LENGTH_LONG).show();
            if (btn != null) btn.setChecked(false);
            return;
        }
        startActivityForResult(mgr.createScreenCaptureIntent(), REQ_SCREEN_CAPTURE);
    }

    private void stopScreenCapture() {
        prefs().edit().putBoolean(KEY_SCREEN_OCR, false).apply();
        requireContext().stopService(new Intent(requireContext(),
            com.hydradragon.antivirus.service.ScreenCaptureService.class));
        Toast.makeText(getContext(), "Screen OCR scanning OFF", Toast.LENGTH_SHORT).show();
    }

    // ─── UI YARDIMCILARI ──────────────────────────────────────────
    private int color(int rid) { return ContextCompat.getColor(requireContext(), rid); }
    private SharedPreferences prefs() { return requireContext().getSharedPreferences(PREFS, 0); }

    private void addTitle(String t) {
        TextView v = new TextView(getContext());
        v.setText(t); v.setTextColor(color(R.color.neon_green));
        v.setTextSize(22); v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        v.setPadding(0,0,0,32); container.addView(v);
    }
    private void addHeader(String t) {
        TextView v = new TextView(getContext());
        v.setText("── " + t + " ──"); v.setTextColor(color(R.color.text_secondary));
        v.setTextSize(11); v.setTypeface(Typeface.MONOSPACE);
        v.setPadding(0,32,0,12); container.addView(v);
    }
    private LinearLayout row() {
        LinearLayout r = new LinearLayout(getContext());
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setBackgroundColor(color(R.color.bg_secondary));
        r.setPadding(24,20,24,20); r.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = 8; r.setLayoutParams(lp); return r;
    }
    private void addInfo(String em, String label, String val) {
        LinearLayout r = row();
        TextView l = new TextView(getContext()); l.setText(em + "  " + label);
        l.setTextColor(color(R.color.text_primary)); l.setTypeface(Typeface.MONOSPACE);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(l);
        TextView v = new TextView(getContext()); v.setText(val);
        v.setTextColor(color(R.color.neon_green)); v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        r.addView(v); container.addView(r);
    }
    private void addToggle(String label, boolean state, CompoundButton.OnCheckedChangeListener cb) {
        LinearLayout r = row();
        TextView l = new TextView(getContext()); l.setText(label);
        l.setTextColor(color(R.color.text_primary)); l.setTypeface(Typeface.MONOSPACE);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(l);
        Switch sw = new Switch(getContext()); sw.setChecked(state); sw.setOnCheckedChangeListener(cb);
        r.addView(sw); container.addView(r);
    }
    private void addBtn(String label, int bgColor, View.OnClickListener cl) {
        TextView b = new TextView(getContext()); b.setText(label);
        b.setTextColor(0xFF000000); b.setBackgroundColor(bgColor);
        b.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        b.setPadding(32,28,32,28); b.setTextSize(14); b.setGravity(Gravity.CENTER);
        b.setOnClickListener(cl);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = 12; b.setLayoutParams(lp); container.addView(b);
    }
    private void addAbout() {
        TextView v = new TextView(getContext());
        v.setText("HydraDragon Antivirus v1.0\n━━━━━━━━━━━━━━━━━━━━━━\n\n" +
            "[ GELİŞTİRİCİLER ]\n\n  ◈  Musayev Yusif\n  ◈  Emirhan Uçan\n\n" +
            "━━━━━━━━━━━━━━━━━━━━━━\n" +
            "Engine : XOR Filter (Binary-Fuse) + X.509\nAI : Native Rust (MinHash/LSH + Isolation Forest)");
        v.setTextColor(color(R.color.text_secondary));
        v.setTypeface(Typeface.MONOSPACE); v.setLineSpacing(6,1); v.setPadding(16,24,16,0);
        container.addView(v);
    }

    // Display name (native script) <-> BCP-47 tag, in the same order/set as the
    // 20 localized app/src/main/res/values-XX resource folders.
    private static final String[] LANGUAGE_NAMES = {
        "English", "Türkçe", "Español", "Deutsch", "Français", "Русский",
        "Português", "العربية", "Italiano", "Nederlands", "Polski", "Українська",
        "中文", "日本語", "한국어", "हिन्दी", "Bahasa Indonesia", "Tiếng Việt",
        "فارسی", "ไทย",
    };
    private static final String[] LANGUAGE_CODES = {
        "en", "tr", "es", "de", "fr", "ru",
        "pt", "ar", "it", "nl", "pl", "uk",
        "zh", "ja", "ko", "hi", "in", "vi",
        "fa", "th",
    };

    private void selectLanguage() {
        new android.app.AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(getString(R.string.language_settings))
            .setItems(LANGUAGE_NAMES, (dialog, which) -> {
                String code = LANGUAGE_CODES[which];
                prefs().edit().putString("language", code).apply();
                // Per-app language override (AndroidX AppCompat) — this is what
                // actually switches the UI's resource-qualifier locale; the
                // previous version only saved the preference and restarted the
                // activity, which did nothing because no locale was ever applied.
                // AppCompat persists this across process restarts on its own.
                AppCompatDelegate.setApplicationLocales(
                    androidx.core.os.LocaleListCompat.forLanguageTags(code));
            }).show();
    }

}
