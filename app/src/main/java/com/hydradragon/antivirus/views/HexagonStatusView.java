// DOSYA: app/src/main/java/com/hydradragon/antivirus/views/HexagonStatusView.java
package com.hydradragon.antivirus.views;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;

/**
 * Özel hexagon güvenlik durumu göstergesi.
 * Windows versiyonundaki hexagon animasyonunu birebir taklit eder.
 */
public class HexagonStatusView extends View {

    private Paint hexPaint;
    private Paint glowPaint;
    private Paint checkPaint;
    private Paint borderPaint;

    private boolean isSecure = true;
    private float pulseRadius = 0f;
    private float pulseAlpha = 1f;
    private ValueAnimator pulseAnimator;

    // Renk paletleri
    private static final int COLOR_SECURE = 0xFF00FF88;
    private static final int COLOR_ALERT  = 0xFFFF0040;
    private static final int COLOR_WARN   = 0xFFFFD700;

    public HexagonStatusView(Context context) { super(context); init(); }
    public HexagonStatusView(Context context, AttributeSet attrs) { super(context, attrs); init(); }
    public HexagonStatusView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr); init();
    }

    private void init() {
        hexPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        hexPaint.setStyle(Paint.Style.FILL);
        hexPaint.setColor(0xFF0D2B1E);

        borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(4f);
        borderPaint.setColor(COLOR_SECURE);

        glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        glowPaint.setStyle(Paint.Style.STROKE);
        glowPaint.setStrokeWidth(2f);
        glowPaint.setColor(COLOR_SECURE);

        checkPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        checkPaint.setStyle(Paint.Style.STROKE);
        checkPaint.setStrokeWidth(6f);
        checkPaint.setStrokeCap(Paint.Cap.ROUND);
        checkPaint.setStrokeJoin(Paint.Join.ROUND);
        checkPaint.setColor(COLOR_SECURE);
    }

    public void setSecureState(boolean secure) {
        isSecure = secure;
        int color = secure ? COLOR_SECURE : COLOR_ALERT;
        borderPaint.setColor(color);
        glowPaint.setColor(color);
        checkPaint.setColor(color);
        hexPaint.setColor(secure ? 0xFF0D2B1E : 0xFF2B0D0D);
        invalidate();
    }

    public void startPulseAnimation() {
        pulseAnimator = ValueAnimator.ofFloat(0f, 1f);
        pulseAnimator.setDuration(2000);
        pulseAnimator.setRepeatCount(ValueAnimator.INFINITE);
        pulseAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        pulseAnimator.addUpdateListener(anim -> {
            float progress = (float) anim.getAnimatedValue();
            pulseRadius = progress;
            pulseAlpha = 1f - progress;
            invalidate();
        });
        pulseAnimator.start();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float cx = getWidth() / 2f;
        float cy = getHeight() / 2f;
        float radius = Math.min(cx, cy) * 0.75f;

        // Pulse dalgası (arka plan)
        if (pulseRadius > 0) {
            Paint pulsePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            pulsePaint.setStyle(Paint.Style.STROKE);
            pulsePaint.setStrokeWidth(3f);
            int color = isSecure ? COLOR_SECURE : COLOR_ALERT;
            pulsePaint.setColor(adjustAlpha(color, (int)(pulseAlpha * 80)));
            canvas.drawCircle(cx, cy, radius + pulseRadius * 40, pulsePaint);
        }

        // Hexagon çiz
        Path hexPath = createHexagonPath(cx, cy, radius);
        canvas.drawPath(hexPath, hexPaint);
        canvas.drawPath(hexPath, borderPaint);

        // İç hexagon (ikinci katman)
        Path innerHex = createHexagonPath(cx, cy, radius * 0.88f);
        Paint innerPaint = new Paint(hexPaint);
        innerPaint.setAlpha(60);
        canvas.drawPath(innerHex, borderPaint);

        // Check veya X işareti
        if (isSecure) {
            drawCheckmark(canvas, cx, cy, radius * 0.45f);
        } else {
            drawX(canvas, cx, cy, radius * 0.35f);
        }

        // Köşe parıltıları
        drawCornerGlints(canvas, cx, cy, radius);
    }

    private Path createHexagonPath(float cx, float cy, float radius) {
        Path path = new Path();
        for (int i = 0; i < 6; i++) {
            double angle = Math.PI / 180 * (60 * i - 30);
            float x = cx + (float)(radius * Math.cos(angle));
            float y = cy + (float)(radius * Math.sin(angle));
            if (i == 0) path.moveTo(x, y);
            else path.lineTo(x, y);
        }
        path.close();
        return path;
    }

    private void drawCheckmark(Canvas canvas, float cx, float cy, float size) {
        canvas.drawLine(cx - size, cy, cx - size * 0.2f, cy + size * 0.8f, checkPaint);
        canvas.drawLine(cx - size * 0.2f, cy + size * 0.8f, cx + size, cy - size * 0.6f, checkPaint);
    }

    private void drawX(Canvas canvas, float cx, float cy, float size) {
        canvas.drawLine(cx - size, cy - size, cx + size, cy + size, checkPaint);
        canvas.drawLine(cx + size, cy - size, cx - size, cy + size, checkPaint);
    }

    private void drawCornerGlints(Canvas canvas, float cx, float cy, float radius) {
        Paint glintPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        glintPaint.setStyle(Paint.Style.FILL);
        glintPaint.setColor(isSecure ? adjustAlpha(COLOR_SECURE, 180) : adjustAlpha(COLOR_ALERT, 180));

        for (int i = 0; i < 6; i++) {
            double angle = Math.PI / 180 * (60 * i - 30);
            float x = cx + (float)(radius * Math.cos(angle));
            float y = cy + (float)(radius * Math.sin(angle));
            canvas.drawCircle(x, y, 4f, glintPaint);
        }
    }

    private int adjustAlpha(int color, int alpha) {
        return (color & 0x00FFFFFF) | (alpha << 24);
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (pulseAnimator != null) pulseAnimator.cancel();
    }
}
