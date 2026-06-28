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
