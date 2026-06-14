// CryptoLib Flutter plugin — Android module (Kotlin DSL).
//
// FFI plugin: the prebuilt libcryptolib_c.so ships per-ABI under
// src/main/jniLibs/<abi>/ and the Android Gradle Plugin packages it into the
// host app's APK. The only Kotlin code is CryptolibStartup, a manifest-
// registered ContentProvider that warms the native library off the main thread
// at launch.
//
// Built-in Kotlin (Flutter 3.44+ / AGP 9+): the Kotlin Gradle Plugin is NOT
// applied here — Flutter's Android tooling provides Kotlin compilation. We only
// configure the Kotlin compiler options.
// See https://docs.flutter.dev/release/breaking-changes/migrate-to-built-in-kotlin

group = "com.cryptolib.cryptolib_flutter"
version = "3.0.0"

plugins {
    id("com.android.library")
}

android {
    namespace = "com.cryptolib.cryptolib_flutter"
    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        minSdk = 24
    }

    // Prebuilt .so files live in src/main/jniLibs/<abi>/.
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}
