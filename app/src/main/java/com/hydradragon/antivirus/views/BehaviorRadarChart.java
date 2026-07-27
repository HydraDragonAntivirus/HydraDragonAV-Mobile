package com.hydradragon.antivirus.views;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;

import androidx.core.content.ContextCompat;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.BehaviorGraphData;

import java.util.List;
import java.util.Locale;

public class BehaviorRadarChart extends View {

    private List<BehaviorGraphData.AxisValue> axes;
    private Paint gridPaint, fillPaint, strokePaint, textPaint, labelPaint;

    public BehaviorRadarChart(Context context) { super(context); init(); }
    public BehaviorRadarChart(Context context, AttributeSet attrs) { super(context, attrs); init(); }
    public BehaviorRadarChart(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle); init();
    }

    private void init() {
        Context ctx = getContext();

        int textPrimary = 0xFFE0E0E0;
        int textSecondary = 0xFFA0A0A0;
        if (ctx != null) {
            textPrimary = ContextCompat.getColor(ctx, R.color.text_primary);
            textSecondary = ContextCompat.getColor(ctx, R.color.text_secondary);
        }

        gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setStyle(Paint.Style.STROKE);
        gridPaint.setStrokeWidth(1f);
        gridPaint.setColor((textSecondary & 0x00FFFFFF) | 0x40000000);

        fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        fillPaint.setStyle(Paint.Style.FILL);
        fillPaint.setColor(0x4000D4FF);

        strokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        strokePaint.setStyle(Paint.Style.STROKE);
        strokePaint.setStrokeWidth(2f);
        strokePaint.setColor(0xFF00D4FF);

        textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setColor(textSecondary);
        textPaint.setTextSize(28f);
        textPaint.setTextAlign(Paint.Align.CENTER);

        labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        labelPaint.setColor(textPrimary);
        labelPaint.setTextSize(32f);
        labelPaint.setTextAlign(Paint.Align.CENTER);
    }

    public void setData(List<BehaviorGraphData.AxisValue> axes) {
        this.axes = axes;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (axes == null || axes.isEmpty()) return;

        int w = getWidth();
        int h = getHeight();
        float cx = w / 2f;
        float cy = h / 2f;
        float radius = Math.min(w, h) * 0.35f;
        int n = axes.size();
        if (n < 3) return;

        float labelR = Math.min(radius * 1.6f, cy * 0.8f);
        float startAngle = -90f;

        // Grid rings (20%, 40%, 60%, 80%, 100%)
        for (int ring = 1; ring <= 5; ring++) {
            float r = radius * ring / 5f;
            Path ringPath = new Path();
            for (int i = 0; i < n; i++) {
                double angle = Math.toRadians(startAngle + 360.0 * i / n);
                float x = cx + r * (float) Math.cos(angle);
                float y = cy + r * (float) Math.sin(angle);
                if (i == 0) ringPath.moveTo(x, y);
                else ringPath.lineTo(x, y);
            }
            ringPath.close();
            canvas.drawPath(ringPath, gridPaint);
        }

        // Spokes
        for (int i = 0; i < n; i++) {
            double angle = Math.toRadians(startAngle + 360.0 * i / n);
            float x = cx + radius * (float) Math.cos(angle);
            float y = cy + radius * (float) Math.sin(angle);
            canvas.drawLine(cx, cy, x, y, gridPaint);
        }

        // Data polygon
        Path dataPath = new Path();
        for (int i = 0; i < n; i++) {
            double angle = Math.toRadians(startAngle + 360.0 * i / n);
            float r = radius * Math.max(0.02f, Math.min(1f, axes.get(i).level / 100f));
            float x = cx + r * (float) Math.cos(angle);
            float y = cy + r * (float) Math.sin(angle);
            if (i == 0) dataPath.moveTo(x, y);
            else dataPath.lineTo(x, y);
        }
        dataPath.close();
        canvas.drawPath(dataPath, fillPaint);
        canvas.drawPath(dataPath, strokePaint);

        // Data point dots
        for (int i = 0; i < n; i++) {
            double angle = Math.toRadians(startAngle + 360.0 * i / n);
            float r = radius * Math.max(0.02f, Math.min(1f, axes.get(i).level / 100f));
            float x = cx + r * (float) Math.cos(angle);
            float y = cy + r * (float) Math.sin(angle);
            canvas.drawCircle(x, y, 6f, strokePaint);
        }

        // Labels
        for (int i = 0; i < n; i++) {
            double angle = Math.toRadians(startAngle + 360.0 * i / n);
            float lx = cx + labelR * (float) Math.cos(angle);
            float ly = cy + labelR * (float) Math.sin(angle);

            String label = axes.get(i).label;
            String val = String.format(Locale.US, "%d%%", axes.get(i).level);

            float textY = ly + (angle > 0 && angle < Math.PI ? 10f : -10f);
            canvas.drawText(label, lx, textY, labelPaint);
            canvas.drawText(val, lx, textY + (angle > 0 && angle < Math.PI ? 32f : -20f), textPaint);
        }
    }
}
