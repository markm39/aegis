// Root build file for Aegis Android.
// Applies Kotlin and AGP plugins at the project level without activating them,
// so the :app module can apply them independently.

plugins {
    id("com.android.application") version "8.2.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.22" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.22" apply false
}
