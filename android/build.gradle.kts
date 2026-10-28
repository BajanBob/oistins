plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.oistins.monitor"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.oistins.monitor"
        minSdk = 29          // Android 10+
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    // A fixed signing key kept in the repo, so each new APK installs over the old one.
    // For a Play Store release, replace this with your own private key (see README).
    signingConfigs {
        create("oistins") {
            storeFile = file("../oistins-sideload.keystore")
            storePassword = "oistins"
            keyAlias = "oistins"
            keyPassword = "oistins"
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("oistins")
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("oistins")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}
