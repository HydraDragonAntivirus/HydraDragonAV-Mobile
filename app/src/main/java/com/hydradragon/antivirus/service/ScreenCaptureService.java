package com.hydradragon.antivirus.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.DisplayMetrics;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.google.android.gms.tasks.Tasks;
import com.google.mlkit.vision.common.InputImage;
import com.google.mlkit.vision.text.Text;
import com.google.mlkit.vision.text.TextRecognition;
import com.google.mlkit.vision.text.TextRecognizer;
import com.google.mlkit.vision.text.latin.TextRecognizerOptions;

import com.hydradragon.antivirus.MainActivity;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.NativeScanner;
import com.hydradragon.antivirus.engine.NetworkObservations;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Zero Trust screen-text scanning: periodically captures the screen via
 * {@link MediaProjection}, OCRs each frame on-device (ML Kit, Latin script),
 * then:
 *  1. feeds the recognized text into {@link NetworkObservations} attributed to
 *     the current foreground app (see DynamicAnalysisService.getForegroundPackage),
 *     so the NEXT native APK scan of that app carries it as
 *     {@code hydradragon.screen_text} for YARA-X rules to match, and
 *  2. immediately runs {@link NativeScanner#scanText} against it so a
 *     scam/ransomware/phishing message rendered on screen RIGHT NOW is caught
 *     without waiting for a scan.
 *
 * Heavier than the AccessibilityService text-node approach (real pixel OCR
 * catches custom-drawn/canvas UI the accessibility tree can't see) — capture
 * is throttled to reduce battery/CPU cost. Requires per-session user consent
 * via {@link MediaProjectionManager#createScreenCaptureIntent()}; Android does
 * not let this be granted silently or persist across process death.
 */
public class ScreenCaptureService extends Service {
    private static final String TAG = "HydraDragon-ScreenOCR";
    private static final String CHANNEL_ID = "hydradragon_screen_ocr";
    private static final int NOTIF_ID = 0x5C4E;
    /** Frame capture interval — OCR is comparatively expensive, no need for
     *  video-rate capture to catch a static scam/ransomware screen. */
    private static final long CAPTURE_INTERVAL_MS = 4000;

    public static final String EXTRA_RESULT_CODE = "result_code";
    public static final String EXTRA_RESULT_DATA = "result_data";

    private MediaProjection projection;
    private VirtualDisplay virtualDisplay;
    private ImageReader imageReader;
    private HandlerThread bgThread;
    private Handler bgHandler;
    private TextRecognizer recognizer;
    private volatile boolean running = false;

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Android 14+ (targetSdk 35) requires a mediaProjection-type foreground
        // service to have valid, JUST-GRANTED consent extras at the moment
        // startForeground() is called, or the OS kills the process with a
        // SecurityException before this method even returns. That happens on
        // every redelivery: START_STICKY makes the system relaunch this service
        // with intent=null after ANY process death (including a normal user
        // "swipe away recents"), and the one-time MediaProjection token from the
        // original consent can never be reconstructed from a null Intent. So we
        // must validate BEFORE claiming foreground status, and never ask for a
        // sticky restart in the first place.
        if (intent == null || !intent.hasExtra(EXTRA_RESULT_CODE)) {
            Log.w(TAG, "missing MediaProjection consent result — not starting foreground");
            stopSelf();
            return START_NOT_STICKY;
        }
        int resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, 0);
        Intent resultData = intent.getParcelableExtra(EXTRA_RESULT_DATA);
        if (resultData == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        MediaProjectionManager mgr =
            (MediaProjectionManager) getSystemService(Context.MEDIA_PROJECTION_SERVICE);
        if (mgr == null) { stopSelf(); return START_NOT_STICKY; }

        // Android requires startForeground() with the mediaProjection service
        // type to happen BEFORE getMediaProjection() is called — calling it the
        // other way around throws "Media projections require a foreground
        // service of type FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION" even though
        // the manifest declares that type, because the OS checks the service's
        // ACTUAL running foreground state at the moment of the call, not just
        // its manifest declaration. We only reach this point once real, fresh
        // consent extras were already validated above, so it's safe to claim
        // foreground status here (unlike the original bug: claiming it
        // unconditionally at the top of onStartCommand for every redelivery).
        createNotificationChannel();
        startForeground(NOTIF_ID, buildNotification());

        projection = mgr.getMediaProjection(resultCode, resultData);
        if (projection == null) { stopSelf(); return START_NOT_STICKY; }

        recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS);
        bgThread = new HandlerThread("ScreenOCR");
        bgThread.start();
        bgHandler = new Handler(bgThread.getLooper());

        // Android 14+ (targetSdk 35) THROWS IllegalStateException from
        // createVirtualDisplay() below unless a Callback is registered on the
        // projection first — even an empty one satisfies the requirement. Also
        // handles the projection being revoked externally (user taps "Stop
        // sharing" in the system status bar) so we tear ourselves down instead
        // of the next captureLoop tick hitting a dead projection.
        projection.registerCallback(new MediaProjection.Callback() {
            @Override
            public void onStop() {
                running = false;
                stopSelf();
            }
        }, bgHandler);

        try {
            startCapture();
        } catch (Throwable t) {
            // createVirtualDisplay/ImageReader.newInstance can throw on edge-case
            // display states (e.g. mid-rotation, 0-sized window during multi-window
            // transition) — this runs on the main thread inside onStartCommand, so
            // an uncaught exception here crashes the whole app process.
            Log.e(TAG, "startCapture failed — stopping", t);
            stopSelf();
            return START_NOT_STICKY;
        }
        // Never sticky: a killed process invalidates the MediaProjection token,
        // so an OS-initiated restart could only crash again (no consent data to
        // redeliver). The user re-enabling Zero Trust screen scanning is what
        // starts this service again, with a fresh consent grant.
        return START_NOT_STICKY;
    }

    private void startCapture() {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        int width = dm.widthPixels;
        int height = dm.heightPixels;
        int density = dm.densityDpi;

        imageReader = ImageReader.newInstance(width, height, android.graphics.PixelFormat.RGBA_8888, 2);
        virtualDisplay = projection.createVirtualDisplay(
            "hydradragon-ocr", width, height, density,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader.getSurface(), null, bgHandler);

        running = true;
        bgHandler.post(this::captureLoop);
    }

    /** Pull the latest frame, OCR it, then reschedule — rather than a tight
     *  ImageReader listener, so OCR latency naturally paces capture and two
     *  frames are never processed concurrently. */
    private void captureLoop() {
        if (!running) return;
        try {
            processLatestFrame();
        } catch (Throwable t) {
            Log.w(TAG, "capture/OCR failed", t);
        }
        if (running) bgHandler.postDelayed(this::captureLoop, CAPTURE_INTERVAL_MS);
    }

    private void processLatestFrame() {
        Image image = imageReader.acquireLatestImage();
        if (image == null) return;
        Bitmap bitmap;
        try {
            bitmap = imageToBitmap(image);
        } finally {
            image.close();
        }
        if (bitmap == null) return;

        InputImage input = InputImage.fromBitmap(bitmap, 0);
        try {
            Text result = Tasks.await(recognizer.process(input), 10, java.util.concurrent.TimeUnit.SECONDS);
            String text = result.getText();
            if (text == null || text.trim().isEmpty()) return;
            onRecognizedText(text.trim());
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            Log.w(TAG, "OCR failed", e);
        } finally {
            bitmap.recycle();
        }
    }

    private void onRecognizedText(String text) {
        String pkg = DynamicAnalysisService.getForegroundPackage();
        if (pkg != null && !pkg.isEmpty() && !pkg.equals(getPackageName())) {
            NetworkObservations.addScreenText(pkg, text);
        }
        // Immediate match: don't wait for the app's next full scan.
        List<String> hits = NativeScanner.scanText(text);
        if (!hits.isEmpty()) {
            Log.w(TAG, "screen-text match: " + hits + " (fg=" + pkg + ")");
            sendAlert(pkg, hits);
        }
    }

    private void sendAlert(String pkg, List<String> hits) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_alert)
            .setContentTitle("Malicious on-screen text detected")
            .setContentText((pkg != null ? pkg + ": " : "") + String.join(", ", hits))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true);
        nm.notify(0xA1EA, b.build());
    }

    /** RGBA_8888 ImageReader plane -> Bitmap, cropping the row-stride padding
     *  Android adds to each captured row. */
    private static Bitmap imageToBitmap(Image image) {
        Image.Plane plane = image.getPlanes()[0];
        int pixelStride = plane.getPixelStride();
        int rowStride = plane.getRowStride();
        int rowPadding = rowStride - pixelStride * image.getWidth();
        Bitmap bitmap = Bitmap.createBitmap(
            image.getWidth() + rowPadding / pixelStride, image.getHeight(), Bitmap.Config.ARGB_8888);
        bitmap.copyPixelsFromBuffer(plane.getBuffer());
        if (rowPadding == 0) return bitmap;
        return Bitmap.createBitmap(bitmap, 0, 0, image.getWidth(), image.getHeight());
    }

    private Notification buildNotification() {
        Intent tap = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, tap,
            PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_secure)
            .setContentTitle("Zero Trust screen scanning active")
            .setContentText("Scanning on-screen text for threats (OCR)")
            .setContentIntent(pi)
            .setOngoing(true)
            .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationChannel ch = new NotificationChannel(
            CHANNEL_ID, "Screen OCR scanning", NotificationManager.IMPORTANCE_LOW);
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.createNotificationChannel(ch);
    }

    @Override
    public void onDestroy() {
        running = false;
        if (virtualDisplay != null) virtualDisplay.release();
        if (imageReader != null) imageReader.close();
        if (projection != null) projection.stop();
        if (bgThread != null) bgThread.quitSafely();
        super.onDestroy();
    }
}
