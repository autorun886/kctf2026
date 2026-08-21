plugins {
    alias(libs.plugins.android.application)
}

val releaseKeystorePath = providers.environmentVariable("KCTF_KEYSTORE").orNull
val releaseStorePassword = providers.environmentVariable("KCTF_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("KCTF_KEY_ALIAS").orNull ?: "kctf"
val releaseKeyPassword = providers.environmentVariable("KCTF_KEY_PASSWORD").orNull
    ?: releaseStorePassword
val releaseSigningConfigured =
    !releaseKeystorePath.isNullOrBlank() && !releaseStorePassword.isNullOrBlank()

android {
    namespace = "com.autorun.kctf"
    buildToolsVersion = "36.0.0"
    ndkVersion = "27.0.12077973"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.autorun.kctf"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = file(releaseKeystorePath!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }
    buildTypes {
        debug {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        viewBinding = true
    }
    packaging {
        resources {
            excludes += "DebugProbesKt.bin"
        }
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.constraintlayout)
}
