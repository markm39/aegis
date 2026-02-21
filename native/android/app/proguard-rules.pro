# Aegis Android ProGuard / R8 rules
# ===================================

# Keep kotlinx.serialization annotated classes
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers @kotlinx.serialization.Serializable class com.aegis.android.** {
    *** Companion;
    *** INSTANCE;
    kotlinx.serialization.KSerializer serializer(...);
}

-keepclasseswithmembers class com.aegis.android.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep all model classes used for JSON deserialization
-keep class com.aegis.android.api.** { *; }

# OkHttp -- keep platform-specific implementations
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Keep OkHttp certificate pinner
-keepclassmembers class okhttp3.CertificatePinner {
    *;
}

# AndroidX Security-Crypto
-keep class androidx.security.crypto.** { *; }

# Biometric
-keep class androidx.biometric.** { *; }

# Prevent stripping of Compose runtime
-keep class androidx.compose.** { *; }
