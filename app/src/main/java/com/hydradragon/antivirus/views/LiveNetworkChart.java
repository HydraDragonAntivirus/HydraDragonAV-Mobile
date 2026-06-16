// DOSYA: app/src/main/java/com/hydradragon/antivirus/views/LiveNetworkChart.java
package com.hydradragon.antivirus.views;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;

/**
 * Canlı ağ aktivitesi grafiği
 * Windows versiyonundaki mavi dalga grafiğini taklit eder.
 */
public class LiveNetworkChart extends View {

    private static final int MAX_POINTS = 60;
    private final Deque<Float> dataPoints = new ArrayDeque<>();

    private Paint linePaint;
    private Paint fillPaint;
    private Paint gridPaint;
    private Paint glowPaint;
    private Path linePath;
    private Path fillPath;

    private float maxValue = 1000f;

    public LiveNetworkChart(Context context) { super(context); init(); }
    public LiveNetworkChart(Context context, AttributeSet attrs) { super(context, attrs); init(); }
    public LiveNetworkChart(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle); init();
    }

    private void init() {
        linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        linePaint.setStyle(Paint.Style.STROKE);
        linePaint.setStrokeWidth(3f);
        linePaint.setColor(0xFF00D4FF); // Cyan - Windows versiyonuyla aynı

        glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        glowPaint.setStyle(Paint.Style.STROKE);
        glowPaint.setStrokeWidth(6f);
        glowPaint.setColor(0x4000D4FF);

        fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        fillPaint.setStyle(Paint.Style.FILL);

        gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setStyle(Paint.Style.STROKE);
        gridPaint.setStrokeWidth(1f);
        gridPaint.setColor(0x20FFFFFF);

        linePath = new Path();
        fillPath = new Path();

        // Başlangıç veri noktaları
        for (int i = 0; i < MAX_POINTS; i++) dataPoints.addLast(0f);
    }

    public void addDataPoint(float value) {
        if (dataPoints.size() >= MAX_POINTS) dataPoints.pollFirst();
        dataPoints.addLast(value);
        if (value > maxValue) maxValue = value * 1.2f;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();

        if (w == 0 || h == 0) return;

        // Arka plan grid çizgileri
        drawGrid(canvas, w, h);

        // Gradient dolgu
        fillPaint.setShader(new LinearGradient(
            0, 0, 0, h,
            new int[]{0x6000D4FF, 0x0000D4FF},
            null, Shader.TileMode.CLAMP));

        float[] points = new float[dataPoints.size()];
        int idx = 0;
        for (float p : dataPoints) points[idx++] = p;

        if (points.length < 2) return;

        float stepX = (float) w / (MAX_POINTS - 1);

        linePath.reset();
        fillPath.reset();

        for (int i = 0; i < points.length; i++) {
            float x = i * stepX;
            float y = h - (points[i] / maxValue * h * 0.85f) - (h * 0.05f);

            if (i == 0) {
                linePath.moveTo(x, y);
                fillPath.moveTo(x, h);
                fillPath.lineTo(x, y);
            } else {
                // Smooth bezier curve
                float prevX = (i - 1) * stepX;
                float prevY = h - (points[i-1] / maxValue * h * 0.85f) - (h * 0.05f);
                float cpX = prevX + stepX / 2;
                linePath.cubicTo(cpX, prevY, cpX, y, x, y);
                fillPath.cubicTo(cpX, prevY, cpX, y, x, y);
            }
        }

        // Fill path kapat
        fillPath.lineTo((points.length - 1) * stepX, h);
        fillPath.close();

        // Glow efekti (önce)
        canvas.drawPath(linePath, glowPaint);
        // Dolgu
        canvas.drawPath(fillPath, fillPaint);
        // Ana çizgi
        canvas.drawPath(linePath, linePaint);

        // Peak noktası
        float maxPoint = 0;
        int maxIdx = 0;
        for (int i = 0; i < points.length; i++) {
            if (points[i] > maxPoint) { maxPoint = points[i]; maxIdx = i; }
        }
        if (maxPoint > 0) {
            Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            dotPaint.setStyle(Paint.Style.FILL);
            dotPaint.setColor(0xFFFFFFFF);
            float px = maxIdx * stepX;
            float py = h - (maxPoint / maxValue * h * 0.85f) - (h * 0.05f);
            canvas.drawCircle(px, py, 5f, dotPaint);
        }
    }

    private void drawGrid(Canvas canvas, int w, int h) {
        // Yatay çizgiler
        int lines = 4;
        for (int i = 1; i < lines; i++) {
            float y = h * i / lines;
            canvas.drawLine(0, y, w, y, gridPaint);
        }
        // Dikey çizgiler
        for (int i = 1; i < 6; i++) {
            float x = w * i / 6f;
            canvas.drawLine(x, 0, x, h, gridPaint);
        }
    }
}
