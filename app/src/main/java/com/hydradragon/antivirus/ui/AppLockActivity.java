package com.hydradragon.antivirus.ui;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.AppLockManager;
import com.hydradragon.antivirus.security.SecurePinPad;
import com.hydradragon.antivirus.security.SecureWindowGuard;
import com.hydradragon.antivirus.security.StrandHoggGuard;

/**
 * Full-screen PIN lock, in two modes (see {@link #EXTRA_MODE}):
 * <ul>
 *   <li>{@link #MODE_VERIFY} — shown at app launch/resume when App Lock is on
 *       (see MainActivity). Finishes with RESULT_OK once the correct PIN is
 *       entered; the caller (MainActivity) finishes itself on anything else,
 *       never falling through to the real app UI on a wrong/missing PIN.</li>
 *   <li>{@link #MODE_SET} — from Settings' "Set/Change PIN" button. Asks for
 *       a new 4-digit PIN, then asks again to confirm it matches, before
 *       saving.</li>
 * </ul>
 * Applies every defense from the Guardsquare secure-keyboard write-up: this
 * whole window is FLAG_SECURE (see SecureWindowGuard), the digit pad never
 * shows visual press feedback and reshuffles after every tap (see
 * SecurePinPad), "Show taps" is checked and blocks PIN entry while active,
 * and FLAG_SECURE's own presence is periodically re-verified against the
 * live window (catches a runtime hook silently stripping it, which static
 * tamper checks like IntegrityCheck can't).
 */
public class AppLockActivity extends AppCompatActivity {

    public static final String EXTRA_MODE = "mode";
    public static final String MODE_VERIFY = "verify";
    public static final String MODE_SET = "set";
    private static final int PIN_LENGTH = 4;

    private SecureWindowGuard windowGuard;
    private StrandHoggGuard strandHoggGuard;
    private TextView tvMessage;
    private TextView tvDots;
    private StringBuilder entered = new StringBuilder();
    private String firstEntryForConfirm; // MODE_SET only: PIN entered the first time, awaiting confirmation
    private String mode;
    private boolean showTapsDialogShowing = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        windowGuard = new SecureWindowGuard(this);
        windowGuard.applyFlagSecure(); // MUST be before super.onCreate/setContentView
        super.onCreate(savedInstanceState);

        strandHoggGuard = new StrandHoggGuard(this);

        mode = getIntent().getStringExtra(EXTRA_MODE);
        if (mode == null) mode = MODE_VERIFY;

        buildUI();
        refreshLockoutOrPrompt();
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkShowTaps();
        windowGuard.startWatching(this::onSecureFlagLost, 2000);
        strandHoggGuard.startWatching(this::onTaskHijackDetected, 1500);
    }

    @Override
    protected void onPause() {
        super.onPause();
        windowGuard.stopWatching();
        strandHoggGuard.stopWatching();
    }

    /** See StrandHoggGuard's javadoc — something other than HydraDragon itself
     *  is present in this activity's task. Fail closed exactly like a lost
     *  FLAG_SECURE: never keep showing the PIN pad once this is possible. */
    private void onTaskHijackDetected(int expected, int actual) {
        Log.e("HydraDragon-AppLock", "Task hijack suspected: expected " + expected
            + " activities in our task, found " + actual);
        Toast.makeText(this, getString(R.string.task_hijack_detected), Toast.LENGTH_LONG).show();
        setResult(RESULT_CANCELED);
        finish();
    }

    /** See SecureWindowGuard's javadoc: this fires only if something (e.g. a
     *  runtime instrumentation hook) stripped FLAG_SECURE from OUR OWN
     *  window after we set it — fail closed rather than silently continue
     *  showing the PIN pad unprotected. */
    private void onSecureFlagLost() {
        Toast.makeText(this, getString(R.string.security_flag_lost), Toast.LENGTH_LONG).show();
        setResult(RESULT_CANCELED);
        finish();
    }

    private void checkShowTaps() {
        if (SecureWindowGuard.isShowTapsEnabled(this)) {
            if (showTapsDialogShowing) return;
            showTapsDialogShowing = true;
            new AlertDialog.Builder(this)
                .setTitle(getString(R.string.show_taps_warning_title))
                .setMessage(getString(R.string.show_taps_warning_msg))
                .setCancelable(false)
                .setPositiveButton(getString(R.string.show_taps_open_settings), (d, w) -> {
                    showTapsDialogShowing = false;
                    startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
                })
                .setNegativeButton(getString(R.string.btn_exit_app), (d, w) -> finish())
                .show();
        }
    }

    private void buildUI() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0A0F1A);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(48, 120, 48, 48);

        TextView title = new TextView(this);
        title.setText(getString(R.string.app_lock));
        title.setTextColor(Color.WHITE);
        title.setTextSize(22);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        tvMessage = new TextView(this);
        tvMessage.setTextColor(0xFFA0A0A0);
        tvMessage.setTextSize(14);
        tvMessage.setGravity(Gravity.CENTER);
        tvMessage.setPadding(0, 24, 0, 24);
        root.addView(tvMessage);

        tvDots = new TextView(this);
        tvDots.setTextColor(Color.WHITE);
        tvDots.setTextSize(28);
        tvDots.setGravity(Gravity.CENTER);
        tvDots.setPadding(0, 0, 0, 32);
        root.addView(tvDots);
        updateDots();

        SecurePinPad pad = new SecurePinPad(this);
        LinearLayout.LayoutParams padParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        pad.setLayoutParams(padParams);
        pad.setListener(new SecurePinPad.Listener() {
            @Override
            public void onDigit(char digit) {
                if (AppLockManager.lockoutSecondsRemaining(AppLockActivity.this) > 0) return;
                if (entered.length() < PIN_LENGTH) entered.append(digit);
                updateDots();
                if (entered.length() == PIN_LENGTH) onPinComplete();
            }

            @Override
            public void onBackspace() {
                if (entered.length() > 0) entered.deleteCharAt(entered.length() - 1);
                updateDots();
            }

            @Override
            public void onObscuredTouch() {
                Toast.makeText(AppLockActivity.this, getString(R.string.obscured_touch_warning), Toast.LENGTH_SHORT).show();
            }
        });
        root.addView(pad);

        setContentView(root);
    }

    private void updateDots() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < PIN_LENGTH; i++) sb.append(i < entered.length() ? "● " : "○ ");
        tvDots.setText(sb.toString());
    }

    private void refreshLockoutOrPrompt() {
        long wait = AppLockManager.lockoutSecondsRemaining(this);
        if (wait > 0) {
            tvMessage.setText(wait >= 60
                ? getString(R.string.lock_wait_min, String.valueOf(wait / 60))
                : getString(R.string.lock_wait_sec, String.valueOf(wait)));
            return;
        }
        tvMessage.setText(MODE_SET.equals(mode)
            ? (firstEntryForConfirm == null ? getString(R.string.lock_enter_pin) : getString(R.string.lock_confirm_pin))
            : getString(R.string.lock_sub));
    }

    private void onPinComplete() {
        String pin = entered.toString();
        entered.setLength(0);

        if (MODE_SET.equals(mode)) {
            if (firstEntryForConfirm == null) {
                firstEntryForConfirm = pin;
                updateDots();
                refreshLockoutOrPrompt();
                return;
            }
            if (firstEntryForConfirm.equals(pin)) {
                AppLockManager.setPin(this, pin);
                Toast.makeText(this, getString(R.string.lock_saved), Toast.LENGTH_SHORT).show();
                setResult(RESULT_OK);
                finish();
            } else {
                firstEntryForConfirm = null;
                Toast.makeText(this, getString(R.string.lock_wrong), Toast.LENGTH_SHORT).show();
                updateDots();
                refreshLockoutOrPrompt();
            }
            return;
        }

        // MODE_VERIFY
        if (AppLockManager.verifyPin(this, pin)) {
            setResult(RESULT_OK);
            finish();
        } else {
            long wait = AppLockManager.lockoutSecondsRemaining(this);
            Toast.makeText(this, getString(R.string.lock_wrong), Toast.LENGTH_SHORT).show();
            updateDots();
            refreshLockoutOrPrompt();
        }
    }

    @Override
    public void onBackPressed() {
        // No back-out of the lock screen in verify mode — that would defeat
        // its whole purpose. In set mode, cancel back to Settings normally.
        if (MODE_SET.equals(mode)) {
            setResult(RESULT_CANCELED);
            super.onBackPressed();
        }
    }
}
