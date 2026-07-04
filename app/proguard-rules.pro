# Project ProGuard/R8 rules (release build).

# Keep the JNI bridge entry points — names must match the native symbols in
# libhydradragonandroid.so, so R8 must not rename/strip them.
-keep class com.hydradragon.antivirus.engine.NativeScanner {
    native <methods>;
    public static *** init(...);
    public static *** scanApk(...);
    public static *** isReady();
}

# TensorFlow Lite.
-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**

# OkHttp.
-dontwarn okhttp3.**
-dontwarn okio.**

# Guava.
-dontwarn com.google.common.**
-dontwarn java.lang.SafeVarargs
-dontwarn javax.annotation.**

# MPAndroidChart.
-keep class com.github.mikephil.charting.** { *; }

# Room database _Impl classes (loaded by reflection — name-pattern matching is brittle,
# so we keep the exact known classes by fully-qualified name).
-keep class androidx.work.impl.WorkDatabase_Impl { *; }

# ML Kit / Firebase component registrars (loaded via ComponentDiscovery reflection).
-keep class com.google.mlkit.common.internal.CommonComponentRegistrar { *; }
-keep class com.google.mlkit.vision.text.internal.TextRegistrar { *; }
-keep class com.google.mlkit.vision.common.internal.VisionCommonRegistrar { *; }
