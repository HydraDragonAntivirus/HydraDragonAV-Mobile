package com.hydradragon.antivirus.security;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.GridLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * In-app secure PIN pad (a {@link GridLayout} of digit buttons), built
 * following the Guardsquare "secure keyboard" guidance:
 *
 * <ul>
 *   <li>Embedded as a plain View in our own window (not a system IME) — an
 *       IME can't protect against the user being tricked into a different,
 *       malicious keyboard; this pad only ever exists inside our own
 *       FLAG_SECURE'd Activity.</li>
 *   <li>No visual press feedback on the digit buttons (transparent
 *       background always, no ripple/highlight state) — a screen recording
 *       that somehow captures the layout still can't tell which key was
 *       pressed from a highlight effect.</li>
 *   <li>Digits are RESHUFFLED into new positions after every single tap —
 *       defeats an attacker who knows this pad's fixed layout and is
 *       inferring keystrokes purely from tap COORDINATES (e.g. via
 *       show-taps + a screen recording, or a UI-injection overlay), since the
 *       digit-to-position mapping never repeats.</li>
 *   <li>Obscured-touch detection (Guardsquare "obscure touch detection")  —
 *       taps are dropped, not delivered, whenever the system reports the
 *       window as obscured or partially obscured (FLAG_WINDOW_IS_OBSCURED /
 *       FLAG_WINDOW_IS_PARTIALLY_OBSCURED), which is what a transparent
 *       tap-jacking overlay sitting on top of this pad would trigger. This
 *       only catches invisible/transparent view injections on top of the pad
 *       itself — it does nothing against an opaque overlay impersonating the
 *       whole pad, or against a hostile Activity on top of ours; those are
 *       out of scope for a touch filter and are why FLAG_SECURE + shuffled
 *       digits (above) exist independently.</li>
 * </ul>
 */
public class SecurePinPad extends GridLayout {

    public interface Listener {
        void onDigit(char digit);
        void onBackspace();
        /** A tap landed on the pad while the window was reported obscured or
         *  partially obscured — the tap was dropped, not delivered. */
        default void onObscuredTouch() {}
    }

    private final List<TextView> cells = new ArrayList<>();
    private Listener listener;

    public SecurePinPad(Context context) {
        super(context);
        setColumnCount(3);
        setRowCount(4);
        setFilterTouchesWhenObscured(true);
        build();
        shuffle();
    }

    public void setListener(Listener l) {
        this.listener = l;
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        return onFilterTouchEventForSecurity(event) && super.dispatchTouchEvent(event);
    }

    @Override
    public boolean onFilterTouchEventForSecurity(MotionEvent event) {
        int flags = event.getFlags();
        boolean badTouch = (flags & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
            || (flags & MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0;
        if (badTouch) {
            if (listener != null) listener.onObscuredTouch();
            return false; // drop the event, never reaches a digit cell
        }
        return super.onFilterTouchEventForSecurity(event);
    }

    private void build() {
        // 9 digit cells + 1 blank + backspace + (last digit) — laid out as a
        // standard 3x4 phone keypad; positions 0-8 hold shuffled digits 1-9,
        // position 9 is blank, 10 holds "0", 11 is backspace.
        for (int i = 0; i < 12; i++) {
            TextView cell = new TextView(getContext());
            cell.setGravity(Gravity.CENTER);
            cell.setTextSize(24);
            cell.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            cell.setTextColor(Color.WHITE);
            // Deliberately no pressed/ripple state — see class javadoc.
            cell.setBackgroundColor(Color.TRANSPARENT);
            cell.setFilterTouchesWhenObscured(true);
            GridLayout.LayoutParams lp = new GridLayout.LayoutParams(
                GridLayout.spec(i / 3, 1f), GridLayout.spec(i % 3, 1f));
            lp.width = 0;
            lp.height = 0;
            lp.setMargins(8, 8, 8, 8);
            cell.setLayoutParams(lp);
            final int index = i;
            cell.setOnClickListener(v -> onCellTapped(index));
            cells.add(cell);
            addView(cell);
        }
    }

    private void onCellTapped(int index) {
        TextView cell = cells.get(index);
        Object tag = cell.getTag();
        if ("BKSP".equals(tag)) {
            if (listener != null) listener.onBackspace();
        } else if (tag instanceof Character) {
            if (listener != null) listener.onDigit((Character) tag);
        }
        // Reshuffle after EVERY tap — see class javadoc.
        shuffle();
    }

    /** Randomize which digit sits in which cell. Called on construction and
     *  after every tap. */
    public void shuffle() {
        List<Character> digits = new ArrayList<>();
        for (char c = '1'; c <= '9'; c++) digits.add(c);
        Collections.shuffle(digits);
        for (int i = 0; i < 9; i++) {
            cells.get(i).setText(String.valueOf(digits.get(i)));
            cells.get(i).setTag(digits.get(i));
        }
        cells.get(9).setText("");
        cells.get(9).setTag(null);
        cells.get(9).setEnabled(false);
        cells.get(10).setText("0");
        cells.get(10).setTag('0');
        cells.get(11).setText("⌫");
        cells.get(11).setTag("BKSP");
    }
}
