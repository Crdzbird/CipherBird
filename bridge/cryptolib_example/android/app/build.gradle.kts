plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.cryptolib.cryptolib_example"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "com.cryptolib.cryptolib_example"
        // libcryptolib_c was cross-compiled at Android API 24 (see
        // scripts/android/lib/common.sh). Anything lower would fail to
        // dlopen() the .so at runtime.
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // We currently ship only arm64-v8a in jniLibs. Tell Gradle not to
        // package any other ABI — avoids "duplicate package" warnings and
        // shrinks the APK. To add armeabi-v7a / x86_64 / x86, rebuild with
        //   ./scripts/android/build_all.sh all
        // and extend this filter list accordingly.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}
